use axum::{
    body::Bytes,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
    routing::any,
    Extension, Router,
};
use config::Config;
use core::fmt;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use matchit::Router as MatchRouter;
use reqwest;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Type;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Deserialize)]
struct PermissionEntry {
    path: String,
    method: String,
    #[serde(rename = "allowed_roles", default)]
    allowed_roles_permission_entry: Vec<String>,
    #[serde(default)]
    param: Option<String>,
}

struct PathPermissions {
    methods: HashMap<Method, (Vec<String>, Option<String>)>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    id: String,
    exp: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize)]
#[sqlx(type_name = "role", rename_all = "PascalCase")] // Matches DB type name
enum Role {
    ProjectOwner,
    Member,
}

struct AppState {
    db_pool: PgPool,
    jwt_secret: String,
    backend_url: String,
}

#[derive(sqlx::FromRow)]
struct UserRole {
    admin: bool,
}

#[derive(sqlx::FromRow)]
struct ProjectRole {
    #[sqlx(rename = "role")]
    role: Role,
}

// Implement Display to allow Role to be printed as a string
impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::ProjectOwner => write!(f, "ProjectOwner"),
            Role::Member => write!(f, "Member"),
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok(); // Load environment variables
    let config = Config::builder()
        .add_source(config::File::with_name("gateway-config"))
        .build()
        .unwrap();

    let permissions: Vec<PermissionEntry> = config.get("permissions").unwrap();
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env");
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let backend_url = config.get_string("backend_url").unwrap();

    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create database pool");

    let mut router = MatchRouter::new();
    let mut permissions_map = HashMap::new();

    // Register permissions and log them
    for entry in permissions {
        let method = entry.method.parse::<Method>().unwrap();
        let path = entry.path.clone();

        let path_perms = permissions_map
            .entry(path.clone())
            .or_insert_with(|| PathPermissions {
                methods: HashMap::new(),
            });

        path_perms.methods.insert(
            method,
            (entry.allowed_roles_permission_entry, entry.param),
        );
    }

    // Log all registered routes
    println!("🛣️ Registered Routes:");
    for (path, perms) in &permissions_map {
        println!("- Path: {}", path);
        for (method, (roles, param)) in &perms.methods {
            println!(
                "  ▸ Method: {} | Roles: {:?} | Param: {:?}",
                method, roles, param
            );
        }
    }

    // Insert paths into router
    for (path, perms) in permissions_map {
        router.insert(&path, perms).unwrap();
    }

    let shared_router = Arc::new(Mutex::new(router));
    let app_state = Arc::new(AppState {
        db_pool,
        jwt_secret,
        backend_url,
    });

    let app = Router::new()
        .route("/*path", any(proxy_handler))
        .layer(Extension(shared_router))
        .layer(Extension(app_state));

    println!("🚀 Gateway started on http://localhost:5000");
    axum::Server::bind(&"0.0.0.0:5000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[axum::debug_handler]
async fn proxy_handler(
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    Extension(router): Extension<Arc<Mutex<MatchRouter<PathPermissions>>>>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    // Auth handling
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let user_id = decode_jwt(token, &app_state.jwt_secret).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Path matching
    let path = uri.path();
    let router = router.lock().await;

    println!("\n🔍 Incoming Request: {} {}", method, path);

    let matched = router.at(path).map_err(|_| {
        println!("❌ No route matched for path: {}", path);
        StatusCode::NOT_FOUND
    })?;

    println!("✅ Matched Route: {:?}", matched.value.methods);
    println!("📦 Route Params: {:?}", matched.params);

    // Method validation
    let (allowed_roles, param) =
        matched.value.methods.get(&method).ok_or_else(|| {
            println!("⚠️ Method not allowed: {}", method);
            StatusCode::METHOD_NOT_ALLOWED
        })?;

    // Project ID extraction
    let project_id = param
        .as_ref()
        .and_then(|param| matched.params.get(param));

    // Role checking
    let user_roles = fetch_user_roles(&app_state.db_pool, &user_id, project_id)
        .await
        .map_err(|e| {
            println!("💥 Database error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    println!("👤 User Roles: {:?}", user_roles);

    let is_admin = user_roles.contains(&"admin".to_string());

    if !is_admin {
        // If not admin, enforce normal role checks
        if !allowed_roles.iter().any(|role| user_roles.contains(role)) {
            println!("⛔ Access denied. Required roles: {:?}", allowed_roles);
            return Err(StatusCode::FORBIDDEN);
        }
    } else {
        println!("👑 Admin override - granting access to all routes");
    }
    

    // Proxy request
    let client = reqwest::Client::new();
    let backend_url = format!("{}{}", app_state.backend_url, uri);

    let response = client
        .request(method.as_str().parse().unwrap(), &backend_url)
        .headers(headers.clone())
        .body(body)
        .send()
        .await
        .map_err(|e| {
            println!("🔌 Backend connection error: {:?}", e);
            StatusCode::BAD_GATEWAY
        })?;

    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    let headers = response.headers().clone();
    let bytes = response.bytes().await.unwrap();

    Ok((status, headers, bytes))
}

fn decode_jwt(token: &str, secret: &str) -> Result<String, ()> {
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::new(Algorithm::HS256);

    decode::<Claims>(token, &decoding_key, &validation)
        .map(|token_data| {
            println!(
                "🔑 Successfully decoded JWT for user: {}",
                token_data.claims.id
            );
            token_data.claims.id
        })
        .map_err(|e| {
            println!("🔒 JWT decode error: {:?}", e);
            ()
        })
}

async fn fetch_user_roles(
    pool: &PgPool,
    user_id: &str,
    project_id: Option<&str>,
) -> Result<Vec<String>, sqlx::Error> {
    let mut roles = Vec::new();

    // Check admin status
    let user: Option<UserRole> = sqlx::query_as("SELECT admin FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

    if let Some(user) = user {
        if user.admin {
            println!("🌟 User is admin");
            roles.push("admin".to_string());
        }
    }

    // Check project roles
    if let Some(project_id) = project_id {
        let project_roles: Vec<ProjectRole> = sqlx::query_as(
            r#"SELECT role, "userId" FROM project_roles WHERE "userId" = $1 AND "projectId" = $2"#,
        )
        .bind(user_id)
        .bind(project_id)
        .fetch_all(pool)
        .await?;

        for role in project_roles {
            println!("🏗️ Found project role: {}", role.role);
            roles.push(role.role.to_string());
        }
    }

    Ok(roles)
}
