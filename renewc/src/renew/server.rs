#![allow(clippy::missing_errors_doc)]

use axum::extract::Path;
use axum::routing::get;
use axum::{Extension, Router};

use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use color_eyre::eyre;
use tracing::{debug, error};

use std::collections::HashMap;
use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Config;
use crate::diagnostics;

#[derive(Debug, Clone)]
pub struct Http01Challenge {
    pub url: String,
    pub token: String,
    pub key_auth: String,
    pub id: String,
}

type Token = String;
type KeyAuth = String;

#[tracing::instrument(skip_all, fields(token))]
async fn challenge(
    Extension(key_auth): Extension<Arc<HashMap<Token, KeyAuth>>>,
    Path(token): Path<String>,
) -> String {
    let Some(key_auth) = key_auth.get(&token) else {
        error!("do not have a auth key for token");
        return "Error no auth key for token".to_owned();
    };
    debug!("got request for aut key");
    key_auth.clone()
}

pub async fn run(
    config: &Config,
    challenges: &[Http01Challenge],
) -> eyre::Result<impl Future<Output = Result<(), std::io::Error>>> {
    let key_auth: HashMap<_, _> = challenges
        .iter()
        .map(|c| (c.token.clone(), c.key_auth.clone()))
        .collect();
    let shared_state = Arc::new(key_auth);

    let app = Router::new()
        .route("/.well-known/acme-challenge/:token", get(challenge))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(Extension(shared_state)),
        );

    let addr: SocketAddr = ([0, 0, 0, 0], config.port).into();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| diagnostics::cant_bind_port(config, e))?;
    let server = axum::serve(listener, app).into_future();

    // this needs to shutdown when done not keep going cause then next call to run will have port in use, maybe even graceful shutdown? see: https://github.com/tokio-rs/axum/blob/main/examples/graceful-shutdown/src/main.rs
    Ok(server)
}
