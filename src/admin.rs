use axum::{
    extract::Query,
    http::StatusCode,
    response::Json,
    Extension,
};
use serde::{Deserialize, Serialize};

use std::sync::Arc;
use tracing::info;

use crate::{
    database::{clear_user_cache, get_cache_stats},
    models::AppState,
};

#[derive(Deserialize)]
pub struct ClearCacheQuery {
    user_id: Option<String>,
}

#[derive(Serialize)]
pub struct CacheStatsResponse {
    total_entries: usize,
    expired_entries: usize,
    cache_hit_ratio: Option<f64>, // Could be tracked separately
}

#[derive(Serialize)]
pub struct ClearCacheResponse {
    success: bool,
    message: String,
}

// GET /admin/cache/stats
pub async fn get_cache_stats_handler(
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<Json<CacheStatsResponse>, StatusCode> {
    let (total, expired) = get_cache_stats(&app_state.role_cache);
    
    info!(total_entries = total, expired_entries = expired, "Cache stats requested");
    
    Ok(Json(CacheStatsResponse {
        total_entries: total,
        expired_entries: expired,
        cache_hit_ratio: None, // Could implement hit ratio tracking
    }))
}

// DELETE /admin/cache
pub async fn clear_cache_handler(
    Query(params): Query<ClearCacheQuery>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<Json<ClearCacheResponse>, StatusCode> {
    
    match &params.user_id {
        Some(user_id) => {
            clear_user_cache(&app_state.role_cache, Some(user_id));
            info!(user_id = user_id, "Cleared cache for specific user");
            Ok(Json(ClearCacheResponse {
                success: true,
                message: format!("Cache cleared for user: {}", user_id),
            }))
        }
        None => {
            clear_user_cache(&app_state.role_cache, None);
            info!("Cleared all cache");
            Ok(Json(ClearCacheResponse {
                success: true,
                message: "All cache cleared".to_string(),
            }))
        }
    }
}