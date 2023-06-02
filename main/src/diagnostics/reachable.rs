use std::str::FromStr;
use std::time::Duration;

use color_eyre::{eyre, Help};
use hyper::{body, Body, Response, StatusCode, Uri};
use tokio::time::timeout;
use tracing::debug;

use crate::config::Config;
use crate::renew::server::Http01Challenge;

const APP: &str = env!("CARGO_PKG_NAME");

async fn check_response(resp: Response<Body>, key_auth: &str, domain: &str) -> eyre::Result<()> {
    match resp.status() {
        StatusCode::OK => {
            let body_bytes = body::to_bytes(resp.into_body()).await.unwrap();
            assert_eq!(body_bytes, key_auth.as_bytes());
            Ok(())
        }
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::NOT_FOUND => {
            Err(eyre::eyre!(
                "Could not reach {APP} via {domain}"
            )
            .note("Another server is getting traffic for external port 80")
            .suggestion(format!("Check if port 80 is forwarded to a port on this machine. If it is configure {APP} to use that port with the `--port` option. If not forward port 80 to this machine")))
        }
        _ => unreachable!("got incorrect status code: {resp:?}"),
    }
}

fn error_timeout(domain: &str) -> eyre::Result<()> {
    // we explicitly do not instruct the user to turn the other application off
    // in case it is a revers proxy/load balancer such as HAProxy. Another diagnostic
    // will help them out once we can not bind to port 80.
    Err(eyre::eyre!("Timed out reaching {domain}")
        .note("Another server is getting traffic for external port 80, it is however not functioning")
        .suggestion(format!("Check if port 80 is forwarded to a port on this machine. If it is configure {APP} to use that port with the `--port` option. If not forward port 80 to this machine")))
}

async fn check(path: &str, domain: &str, key_auth: &str) -> eyre::Result<()> {
    let url = format!("http://{domain}{path}");
    debug!("checking: {url}");
    let client = hyper::Client::new();
    let get = client.get(Uri::from_str(&url).unwrap());
    let get = timeout(Duration::from_millis(50), get);
    match get.await {
        Ok(Ok(resp)) => check_response(resp, key_auth, domain).await,
        Ok(Err(e)) if e.is_timeout() => error_timeout(domain),
        Ok(Err(e)) if e.is_connect() => Err(eyre::eyre!("Could not reach {APP} via {domain}"))
            .suggestion("Forward port 80 to this machine"),
        Ok(Err(e)) => unreachable!("reqwest error: {e:?}"),
        Err(_) => error_timeout(domain),
    }
}

pub async fn server(config: &Config, challanges: &[Http01Challenge]) -> eyre::Result<()> {
    let Http01Challenge {
        token, key_auth, ..
    } = challanges
        .first()
        .expect("there is always one domain thus one challange");

    let path = format!("/.well-known/acme-challenge/{token}");
    for domain in &config.domains {
        check(&path, domain, key_auth).await?;
    }

    Ok(())
}
