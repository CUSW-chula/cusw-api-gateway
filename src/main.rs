use axum::{routing::any, Extension, Router};
use configs::{load_config, load_permissions};
use http::Method;
use matchit::Router as MatchRouter;
use sqlx::postgres::PgPoolOptions;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use tracing::{debug, info};

mod auth;
mod configs;
mod database;
mod handlers;
mod logging;
mod models;

use crate::{
    handlers::proxy_handler,
    logging::init_tracing,
    models::{AppState, PathPermissions},
};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    init_tracing().await;

    info!("🚀 Starting gateway initialization...");

    // Load configuration files
    let config_files = std::env::var("CONFIG_FILES")
        .unwrap_or_else(|_| "gateway-config.toml".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .collect::<Vec<_>>();

    info!("🔧 Loading configuration files: {:?}", config_files);

    let config = load_config(&config_files).expect("Failed to build configuration");
    let permissions = load_permissions(&config_files).expect("Failed to load permissions");

    info!("🔐 Total merged permissions: {}", permissions.len());

    // Load environment variables
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let backend_url = config.get_string("backend_url").unwrap();

    // Database setup
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create database pool");

    // Build routing
    let mut router = MatchRouter::new();
    let mut permissions_map = HashMap::new();

    for entry in &permissions {
        let method = entry.method.parse::<Method>().unwrap();
        let path = entry.path.clone();

        let path_perms = permissions_map
            .entry(path.clone())
            .or_insert_with(|| PathPermissions {
                methods: HashMap::new(),
            });

        path_perms
            .methods
            .insert(method, (entry.allowed_roles.clone(), entry.param.clone()));
    }

    // Register routes
    for (path, perms) in &permissions_map {
        info!(route.path = %path, "Route registered");
        for (method, (roles, param)) in &perms.methods {
            debug!(
                method = %method,
                allowed_roles = ?roles,
                param = ?param,
                "Route details"
            );
        }
    }

    for (path, perms) in permissions_map {
        router
            .insert(&path, perms)
            .unwrap_or_else(|_| panic!("Failed to register route: {}", path));
    }

    let shared_router = Arc::new(Mutex::new(router));
    let app_state = Arc::new(AppState {
        db_pool,
        jwt_secret,
        backend_url,
    });

    // Create Axum app
    let app = Router::new()
        .route("/*path", any(proxy_handler))
        .layer(Extension(shared_router))
        .layer(Extension(app_state));

    let bind_address = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8000".into());

    info!("\n🚀 Gateway initialized successfully");
    info!("🌐 Listening on: http://{}", bind_address);

    // Start server with ConnectInfo for IP tracking
    axum::Server::bind(&bind_address.parse().unwrap())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
