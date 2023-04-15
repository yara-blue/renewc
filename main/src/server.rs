use axum::extract::Path;
use axum::routing::get;
use axum::{Extension, Router};

use tower_http::trace::TraceLayer;
use tower::ServiceBuilder;

use color_eyre::eyre;
use tracing::error;

use std::collections::HashMap;
use std::sync::Arc;

use crate::diagnostics;

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
    let key_auth = match key_auth.get(&token) {
        None => {
            error!("we do not have a auth key for token: {token}");
            return "Error no auth key for token".to_owned();
        }
        Some(key_auth) => key_auth,
    };
    key_auth.clone()
}

pub async fn run(port: u16, challenges: &[Http01Challenge]) -> eyre::Result<()> {
    let key_auth: HashMap<_, _> = challenges
        .iter()
        .map(|c| (c.token.clone(), c.key_auth.clone()))
        .collect();
    let shared_state = Arc::new(key_auth);

    let app = Router::new()
        .route("/.well-known/acme-challenge/:token", get(challenge))
        .layer(ServiceBuilder::new()
               .layer(TraceLayer::new_for_http())
               .layer(Extension(shared_state)));

    let addr = ([0, 0, 0, 0], port).into();
    axum::Server::try_bind(&addr)
        .map_err(|e| diagnostics::cant_bind_port(e, port))?
        .serve(app.into_make_service())
        .await?;

    Err(eyre::eyre!("Serve returned, it should not"))
}
