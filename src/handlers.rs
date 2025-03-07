use axum::{
    body::Bytes,
    extract::ConnectInfo,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
    Extension,
};
use matchit::Router as MatchRouter;
use reqwest;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument};

use crate::{
    auth::decode_jwt,
    database::fetch_user_roles,
    models::{AppState, PathPermissions},
};

#[instrument(
    skip_all,
    fields(
        method = %method,
        uri = %uri,
        user_id,
        status,
        params,
        query,
        matched_route,
        required_roles,
        user_roles,
        is_admin,
        client_ip
    )
)]
pub async fn proxy_handler(
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    Extension(router): Extension<Arc<Mutex<MatchRouter<PathPermissions>>>>,
    Extension(app_state): Extension<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, StatusCode> {
    tracing::Span::current().record("client_ip", &addr.ip().to_string());

    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            error!("Missing or invalid Authorization header");
            StatusCode::UNAUTHORIZED
        })?;

    let user_id = decode_jwt(token, &app_state.jwt_secret).map_err(|e| {
        error!(error = %e, "JWT validation failed");
        StatusCode::UNAUTHORIZED
    })?;

    tracing::Span::current().record("user_id", &user_id);

    let path = uri.path();
    let router = router.lock().await;

    debug!("Incoming request: {} {}", method, path);
    let matched = router.at(path).map_err(|_| {
        error!("No route matched for path: {}", path);
        StatusCode::NOT_FOUND
    })?;

    let (allowed_roles, param) = matched.value.methods.get(&method).ok_or_else(|| {
        error!("Method not allowed: {}", method);
        StatusCode::METHOD_NOT_ALLOWED
    })?;

    tracing::Span::current()
        .record("matched_route", &format!("{:?}", matched.value.methods))
        .record("required_roles", &format!("{:?}", allowed_roles));

    let param_name = param.as_ref().map(|p| p.as_str()).unwrap_or_default();
    let id = matched.params.get(param_name);

    let user_roles = fetch_user_roles(&app_state.db_pool, &user_id, id)
        .await
        .map_err(|e| {
            error!(error = %e, "Database error");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let is_admin = user_roles.contains(&"admin".to_string());
    tracing::Span::current()
        .record("user_roles", &format!("{:?}", user_roles))
        .record("is_admin", &is_admin);

    info!(
        user_roles = ?user_roles,
        required_roles = ?allowed_roles,
        "Checking authorization"
    );

    if !is_admin {
        if allowed_roles.contains(&"*".to_string()) {
            info!("Wildcard access granted for route");
        } else {
            let has_required_role = allowed_roles.iter().any(|role| user_roles.contains(role));
            if !has_required_role {
                error!(
                    "Access denied. User roles: {:?}, Required roles: {:?}",
                    user_roles, allowed_roles
                );
                return Err(StatusCode::FORBIDDEN);
            }
            info!(
                "Access granted with roles: {:?}",
                user_roles
                    .iter()
                    .filter(|r| allowed_roles.contains(r))
                    .collect::<Vec<_>>()
            );
        }
    } else {
        info!("Admin access granted");
    }

    let client = reqwest::Client::new();
    let backend_url = format!("{}{}", app_state.backend_url, uri);
    info!(backend_url = %backend_url, "Forwarding request");

    let response = client
        .request(method.as_str().parse().unwrap(), &backend_url)
        .headers(headers.clone())
        .body(body)
        .send()
        .await
        .map_err(|e| {
            error!(error = %e, "Backend connection error");
            StatusCode::BAD_GATEWAY
        })?;

    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    let headers = response.headers().clone();
    let bytes = response.bytes().await.unwrap();

    tracing::Span::current().record("status", &status.as_u16());

    info!(
        status = %status,
        content_length = bytes.len(),
        "Response received"
    );

    Ok((status, headers, bytes))
}
