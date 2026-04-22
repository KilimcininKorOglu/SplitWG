use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::config::CamouflageConfig;

pub fn fallback_service(config: &Option<CamouflageConfig>) -> Router {
    let config = match config {
        Some(c) if c.enabled => c,
        _ => return Router::new().fallback(default_fallback),
    };

    if config.mode != "static" {
        log::warn!(
            "camouflage mode '{}' not supported, falling back to 404",
            config.mode
        );
        return Router::new().fallback(default_fallback);
    }

    let site_dir = match &config.site_dir {
        Some(dir) if dir.is_dir() => dir,
        Some(dir) => {
            log::warn!(
                "camouflage site_dir '{}' not found, falling back to 404",
                dir.display()
            );
            return Router::new().fallback(default_fallback);
        }
        None => {
            log::warn!("camouflage enabled but no site_dir configured, falling back to 404");
            return Router::new().fallback(default_fallback);
        }
    };

    log::info!(
        "camouflage: serving static files from {}",
        site_dir.display()
    );

    Router::new().fallback_service(
        ServeDir::new(site_dir).not_found_service(axum::routing::get(|| async {
            (StatusCode::NOT_FOUND, "404 Not Found")
        })),
    )
}

pub fn apply_headers<S>(router: Router<S>, config: &Option<CamouflageConfig>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let headers = match config {
        Some(c) if c.enabled && !c.headers.is_empty() => &c.headers,
        _ => return router,
    };

    let mut app = router;
    for (name, value) in headers {
        let Ok(header_name) = name.parse::<HeaderName>() else {
            log::warn!("camouflage: invalid header name '{name}', skipping");
            continue;
        };
        let Ok(header_value) = HeaderValue::from_str(value) else {
            log::warn!("camouflage: invalid header value for '{name}', skipping");
            continue;
        };
        app = app.layer(SetResponseHeaderLayer::overriding(
            header_name,
            header_value,
        ));
    }

    app
}

async fn default_fallback() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "404 Not Found")
}
