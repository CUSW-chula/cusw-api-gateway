use crate::models::{ProjectRole, UserRole};
use sqlx::{Error, PgPool};
use tracing::{info, instrument};

#[instrument(
    skip_all,
    fields(
        user_id = %user_id,
        resource_id = ?id,
        found_roles
    )
)]
pub async fn fetch_user_roles(
    pool: &PgPool,
    user_id: &str,
    id: Option<&str>,
) -> Result<Vec<String>, Error> {
    let mut roles = Vec::new();

    info!("Checking user admin status");
    let user: Option<UserRole> = sqlx::query_as("SELECT admin FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

    if let Some(user) = user {
        if user.admin {
            info!("Admin role found");
            roles.push("admin".to_string());
        }
    }

    info!("Checking user head roles");
    let head_roles: Vec<UserRole> = sqlx::query_as("SELECT head FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_all(pool)
        .await?;

    if let Some(head_role) = head_roles.into_iter().next() {
        if head_role.head {
            info!("Head role found");
            roles.push("head".to_string());
        }
    }

    if let Some(task_id) = id {
        info!(%task_id, "Checking task-related roles");
        let project_ids: Vec<(String, String)> =
            sqlx::query_as(r#"SELECT "id", "projectId" FROM tasks WHERE "id" = $1"#)
                .bind(task_id)
                .fetch_all(pool)
                .await?;

        for project_id in project_ids {
            info!(project_id = %project_id.1, "Checking project roles");
            let project_roles: Vec<ProjectRole> = sqlx::query_as(
                r#"SELECT role FROM project_roles WHERE "userId" = $1 AND "projectId" = $2"#,
            )
            .bind(user_id)
            .bind(project_id.1)
            .fetch_all(pool)
            .await?;

            for role in project_roles {
                info!(role = %role.role, "Found project role");
                roles.push(role.role.to_string());
            }
        }
    }

    if let Some(project_id) = id {
        info!(%project_id, "Checking direct project roles");
        let project_roles: Vec<ProjectRole> = sqlx::query_as(
            r#"SELECT role FROM project_roles WHERE "userId" = $1 AND "projectId" = $2"#,
        )
        .bind(user_id)
        .bind(project_id)
        .fetch_all(pool)
        .await?;

        for role in project_roles {
            info!(role = %role.role, "Found direct project role");
            roles.push(role.role.to_string());
        }
    }

    if let Some(task_id) = id {
        info!(%task_id, "Checking task creator role");
        let creators: Vec<(String, String)> =
            sqlx::query_as(r#"SELECT "id", "createdById" FROM tasks WHERE "id" = $1"#)
                .bind(task_id)
                .fetch_all(pool)
                .await?;

        for creator in creators {
            if creator.1 == user_id {
                info!("Task creator role found");
                roles.push("TaskCreator".to_string());
            }
        }
    }

    if let Some(task_id) = id {
        info!(%task_id, "Checking task assignee role");
        let assigners: Vec<(String, String)> = sqlx::query_as(
            r#"SELECT "taskId","userId" FROM task_assignments WHERE "taskId" = $1 AND "userId" = $2"#,
        )
        .bind(task_id)
        .bind(user_id)
        .fetch_all(pool)
        .await?;

        for assignee in assigners {
            if assignee.1 == user_id {
                info!("Task assignee role found");
                roles.push("TaskAssignee".to_string());
            }
        }
    }

    tracing::Span::current().record("found_roles", &format!("{:?}", roles));
    info!(total_roles = roles.len(), "Completed role collection");
    Ok(roles)
}
