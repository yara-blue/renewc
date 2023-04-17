use color_eyre::{eyre, Help};
use hyper::StatusCode;
use tracing::debug;

use crate::config::Config;
use crate::server::Http01Challenge;

const APP: &str = env!("CARGO_PKG_NAME");

async fn check(path: &str, domain: &str, key_auth: &str) -> eyre::Result<()> {
    let url = format!("http://{domain}{path}");
    debug!("checking: {url}");
    match reqwest::get(url).await {
        Ok(resp) if resp.status() == StatusCode::OK => {
            assert_eq!(resp.text().await.unwrap(), key_auth);
            return Ok(());
        }
        Ok(resp) if resp.status() == StatusCode::SERVICE_UNAVAILABLE => {
            return Err(eyre::eyre!(
                "Could not reach {APP} via {domain}"
            )
            .note("Another server is getting traffic for external port 80")
            .suggestion(format!("Check if port 80 is forwarded to a port on this machine. If it is configure {APP} to use that port with the `--port` option. If not forward port 80 to this machine")));
        }
        Ok(resp) => unreachable!("got incorrect status code: {resp:?}"),
        Err(e) if e.is_timeout() => {
            // we explicitly do not instruct the user to turn the other application off
            // in case it is a revers proxy/load balancer such as HAProxy. Another diagnostic
            // will help them out once we can not bind to port 80.
            return Err(eyre::eyre!("Timed out reaching {domain}")
                .note("Another server is getting traffic for external port 80, it is however not functioning")
                .suggestion(format!("Check if port 80 is forwarded to a port on this machine. If it is configure {APP} to use that port with the `--port` option. If not forward port 80 to this machine")));
        }
        Err(e) if e.is_connect() => {
            return Err(eyre::eyre!("Could not reach {APP} via {domain}")
                .suggestion(format!("Forword port 80 to this machine")))
        }
        Err(e) => unreachable!("reqwest error: {e:?}"),
    }
}

pub async fn server_reachable(config: &Config, challanges: &[Http01Challenge]) -> eyre::Result<()> {
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
