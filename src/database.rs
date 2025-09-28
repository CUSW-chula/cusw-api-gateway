use crate::models::{ProjectRole, UserRole};
use sqlx::{Error, PgPool};
use tracing::{info, instrument};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// Simple in-memory cache with TTL
#[derive(Clone)]
pub struct CacheEntry {
    pub roles: Vec<String>,
    pub expires_at: Instant,
}

pub type RoleCache = Arc<RwLock<HashMap<String, CacheEntry>>>;

// Cache TTL - 5 minutes
const CACHE_TTL: Duration = Duration::from_secs(300);

pub fn create_role_cache() -> RoleCache {
    Arc::new(RwLock::new(HashMap::new()))
}

// Helper function to clean expired cache entries
fn clean_expired_cache(cache: &RoleCache) {
    let now = Instant::now();
    if let Ok(mut cache_map) = cache.write() {
        cache_map.retain(|_, entry| entry.expires_at > now);
    }
}

// Get roles from cache if available and not expired
fn get_cached_roles(cache: &RoleCache, cache_key: &str) -> Option<Vec<String>> {
    if let Ok(cache_map) = cache.read() {
        if let Some(entry) = cache_map.get(cache_key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.roles.clone());
            }
        }
    }
    None
}

// Store roles in cache
fn cache_roles(cache: &RoleCache, cache_key: String, roles: Vec<String>) {
    if let Ok(mut cache_map) = cache.write() {
        cache_map.insert(cache_key, CacheEntry {
            roles,
            expires_at: Instant::now() + CACHE_TTL,
        });
    }
}

#[instrument(
    skip_all,
    fields(
        user_id = %user_id,
        resource_id = ?id,
        found_roles,
        cache_hit
    )
)]
pub async fn fetch_user_roles(
    pool: &PgPool,
    cache: &RoleCache,
    user_id: &str,
    id: Option<&str>,
) -> Result<Vec<String>, Error> {
    // Create cache key
    let cache_key = match id {
        Some(resource_id) => format!("{}:{}", user_id, resource_id),
        None => user_id.to_string(),
    };

    // Check cache first
    if let Some(cached_roles) = get_cached_roles(cache, &cache_key) {
        tracing::Span::current().record("cache_hit", true);
        tracing::Span::current().record("found_roles", &format!("{:?}", cached_roles));
        info!(total_roles = cached_roles.len(), "Returned cached roles");
        return Ok(cached_roles);
    }

    tracing::Span::current().record("cache_hit", false);
    
    // Clean expired entries periodically
    clean_expired_cache(cache);

    let mut roles = Vec::new();

    // Get user basic roles (admin, head) - single query
    info!("Fetching user basic roles");
    let user: Option<UserRole> = sqlx::query_as("SELECT admin, head FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

    if let Some(user) = user {
        if user.admin {
            info!("Admin role found");
            roles.push("admin".to_string());
        }
        if user.head {
            info!("Head role found");
            roles.push("head".to_string());
        }
    }

    // Handle resource-specific roles
    if let Some(resource_id) = id {
        // Try to determine if this is a task ID or project ID by checking tasks table first
        let task_info: Option<(String, String)> = sqlx::query_as(
            r#"SELECT "id", "projectId" FROM tasks WHERE "id" = $1"#
        )
        .bind(resource_id)
        .fetch_optional(pool)
        .await?;

        if let Some((task_id, project_id)) = task_info {
            // This is a task - get task-specific roles and project roles
            info!(%task_id, %project_id, "Processing task-related roles");
            
            // Get task creator and assignee info in one query
            let task_relations: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
                r#"
                SELECT 
                    t."createdById" as creator_id,
                    ta."userId" as assignee_id
                FROM tasks t
                LEFT JOIN task_assignments ta ON t."id" = ta."taskId" AND ta."userId" = $2
                WHERE t."id" = $1
                "#
            )
            .bind(&task_id)
            .bind(user_id)
            .fetch_all(pool)
            .await?;

            for (creator_id, assignee_id) in task_relations {
                if let Some(creator) = creator_id {
                    if creator == user_id {
                        info!("Task creator role found");
                        roles.push("TaskCreator".to_string());
                    }
                }
                if assignee_id.is_some() {
                    info!("Task assignee role found");
                    roles.push("TaskAssignee".to_string());
                }
            }

            // Get project roles for the task's project
            let project_roles: Vec<ProjectRole> = sqlx::query_as(
                r#"SELECT role FROM project_roles WHERE "userId" = $1 AND "projectId" = $2"#,
            )
            .bind(user_id)
            .bind(&project_id)
            .fetch_all(pool)
            .await?;

            for role in project_roles {
                info!(role = %role.role, "Found project role via task");
                roles.push(role.role);
            }
        } else {
            // This might be a direct project ID
            info!(%resource_id, "Processing direct project roles");
            let project_roles: Vec<ProjectRole> = sqlx::query_as(
                r#"SELECT role FROM project_roles WHERE "userId" = $1 AND "projectId" = $2"#,
            )
            .bind(user_id)
            .bind(resource_id)
            .fetch_all(pool)
            .await?;

            for role in project_roles {
                info!(role = %role.role, "Found direct project role");
                roles.push(role.role);
            }
        }
    }

    // Remove duplicates
    roles.sort();
    roles.dedup();

    // Cache the result
    cache_roles(cache, cache_key, roles.clone());

    tracing::Span::current().record("found_roles", &format!("{:?}", roles));
    info!(total_roles = roles.len(), "Completed role collection and cached");
    Ok(roles)
}

// Clear cache for specific user or all cache
pub fn clear_user_cache(cache: &RoleCache, user_id: Option<&str>) {
    if let Ok(mut cache_map) = cache.write() {
        match user_id {
            Some(uid) => {
                // Clear all entries for specific user
                cache_map.retain(|key, _| !key.starts_with(&format!("{}:", uid)) && key != uid);
                info!(user_id = uid, "Cleared cache for specific user");
            }
            None => {
                // Clear all cache
                cache_map.clear();
                info!("Cleared all role cache");
            }
        }
    }
}

// Get cache statistics
pub fn get_cache_stats(cache: &RoleCache) -> (usize, usize) {
    if let Ok(cache_map) = cache.read() {
        let total = cache_map.len();
        let expired = cache_map.values()
            .filter(|entry| entry.expires_at <= Instant::now())
            .count();
        (total, expired)
    } else {
        (0, 0)
    }
}#[cfg(test)]

mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_cache_functionality() {
        let cache = create_role_cache();
        
        // Test cache miss
        let result = get_cached_roles(&cache, "user1");
        assert!(result.is_none());
        
        // Test cache set and hit
        let roles = vec!["admin".to_string(), "user".to_string()];
        cache_roles(&cache, "user1".to_string(), roles.clone());
        
        let cached_result = get_cached_roles(&cache, "user1");
        assert_eq!(cached_result, Some(roles));
        
        // Test cache stats
        let (total, expired) = get_cache_stats(&cache);
        assert_eq!(total, 1);
        assert_eq!(expired, 0);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = create_role_cache();
        
        let roles = vec!["admin".to_string()];
        
        // Manually insert expired entry
        if let Ok(mut cache_map) = cache.write() {
            cache_map.insert("user1".to_string(), CacheEntry {
                roles: roles.clone(),
                expires_at: Instant::now() - Duration::from_secs(1), // Already expired
            });
        }
        
        // Should return None for expired entry
        let result = get_cached_roles(&cache, "user1");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_clear_user_cache() {
        let cache = create_role_cache();
        
        // Add multiple entries
        cache_roles(&cache, "user1".to_string(), vec!["admin".to_string()]);
        cache_roles(&cache, "user1:project1".to_string(), vec!["member".to_string()]);
        cache_roles(&cache, "user2".to_string(), vec!["user".to_string()]);
        
        // Clear specific user
        clear_user_cache(&cache, Some("user1"));
        
        // user1 entries should be gone, user2 should remain
        assert!(get_cached_roles(&cache, "user1").is_none());
        assert!(get_cached_roles(&cache, "user1:project1").is_none());
        assert!(get_cached_roles(&cache, "user2").is_some());
        
        // Clear all
        clear_user_cache(&cache, None);
        assert!(get_cached_roles(&cache, "user2").is_none());
    }
}