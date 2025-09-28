use axum::http::Method;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::database::RoleCache;

#[derive(Debug, Deserialize)]
pub struct PermissionEntry {
    pub path: String,
    pub method: String,
    #[serde(rename = "allowed_roles", default)]
    pub allowed_roles: Vec<String>,
    #[serde(default)]
    pub param: Option<String>,
}

pub struct PathPermissions {
    pub methods: HashMap<Method, (Vec<String>, Option<String>)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub id: String,
    pub exp: usize,
}

// Removed unused Role enum - now using String directly for flexibility

pub struct AppState {
    pub db_pool: sqlx::PgPool,
    pub jwt_secret: String,
    pub backend_url: String,
    pub role_cache: RoleCache,
}

#[derive(sqlx::FromRow)]
pub struct UserRole {
    pub admin: bool,
    pub head: bool,
}

#[derive(sqlx::FromRow)]
pub struct ProjectRole {
    #[sqlx(rename = "role")]
    pub role: String,
}
