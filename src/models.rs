use axum::http::Method;
use serde::{Deserialize, Serialize};
use sqlx::Type;
use std::collections::HashMap;
use std::fmt;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Type, Serialize, Deserialize)]
#[sqlx(type_name = "Role", rename_all = "PascalCase")]
pub enum Role {
    ProjectOwner,
    Member,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::ProjectOwner => write!(f, "ProjectOwner"),
            Role::Member => write!(f, "Member"),
        }
    }
}

pub struct AppState {
    pub db_pool: sqlx::PgPool,
    pub jwt_secret: String,
    pub backend_url: String,
}

#[derive(sqlx::FromRow)]
pub struct UserRole {
    pub admin: bool,
}

#[derive(sqlx::FromRow)]
pub struct ProjectRole {
    #[sqlx(rename = "role")]
    pub role: Role,
}
