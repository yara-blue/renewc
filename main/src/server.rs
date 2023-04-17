#![allow(clippy::missing_errors_doc)]

use axum::extract::Path;
use axum::routing::get;
use axum::{Extension, Router};

use tokio::task::JoinHandle;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use color_eyre::eyre;
use tracing::error;

use std::collections::HashMap;
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

#[tracing::instrument]
async fn challenge(
    Extension(key_auth): Extension<Arc<HashMap<Token, KeyAuth>>>,
    Path(token): Path<String>,
) -> String {
    let Some(key_auth) = key_auth.get(&token) else {
        error!("we do not have a auth key for token: {token}");
        return "Error no auth key for token".to_owned();
    };
    key_auth.clone()
}

pub fn run(
    config: &Config,
    challenges: &[Http01Challenge],
) -> eyre::Result<JoinHandle<Result<(), hyper::Error>>> {
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

    let addr = ([0, 0, 0, 0], config.port).into();
    let server = axum::Server::try_bind(&addr)
        .map_err(|e| diagnostics::cant_bind_port(&config, e))?
        .serve(app.into_make_service());

    Ok(tokio::spawn(server))
}
