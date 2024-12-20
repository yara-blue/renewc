use std::io::{Read, Write};
use std::string::String;
use std::time::Duration;

use color_eyre::eyre::{self, Context};
use color_eyre::Help;
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use tokio::time::{sleep, sleep_until, Instant};
use tracing::{debug, error};

use crate::cert::format::PemItem;
use crate::cert::Signed;
use crate::config::Config;
use crate::diagnostics;

pub mod server;
use acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    Order, OrderState, OrderStatus,
};
use instant_acme as acme;
use server::Http01Challenge;

// Create a new account. This will generate a fresh ECDSA key for you.
// Alternatively, restore an account from serialized credentials by
// using `Account::from_credentials()`.
#[tracing::instrument(skip_all)]
async fn account(config: &Config) -> Result<Account, acme::Error> {
    let url = if config.production {
        LetsEncrypt::Production.url()
    } else {
        LetsEncrypt::Staging.url()
    };
    let contact: Vec<_> = config
        .email
        .iter()
        .map(|addr| format!("mailto:{addr}"))
        .collect();

    let (account, _account_credentials) = Account::create(
        &NewAccount {
            contact: contact
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        url,
        None,
    )
    .await?;
    Ok(account)
}

#[tracing::instrument(skip_all)]
async fn order(account: &Account, names: &[String]) -> Result<Order, acme::Error> {
    let identifiers = names
        .iter()
        .map(|name| Identifier::Dns(name.into()))
        .collect::<Vec<_>>();
    let order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await?;

    Ok(order)
}

// Pick the desired challenge type and prepare the response.
#[tracing::instrument(skip_all)]
async fn prepare_challenge(order: &mut Order) -> eyre::Result<Vec<Http01Challenge>> {
    let authorizations = order.authorizations().await.unwrap();
    let mut challenges = Vec::with_capacity(authorizations.len());
    for authz in authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => unreachable!("got unexpected status, authorization: {authz:?}"),
        }

        // We'll use the DNS challenges for this example, but you could
        // pick something else to use here.
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| eyre::eyre!("no http01 challenge found"))?;

        let Identifier::Dns(identifier) = authz.identifier;
        let challenge = Http01Challenge {
            url: challenge.url.clone(),
            token: challenge.token.clone(),
            key_auth: order.key_authorization(challenge).as_str().to_owned(),
            id: identifier.clone(),
        };
        challenges.push(challenge);
    }
    Ok(challenges)
}

trait TimeLeft {
    fn duration_until(&self) -> Duration;
}

impl TimeLeft for Instant {
    fn duration_until(&self) -> Duration {
        Instant::now().saturating_duration_since(*self)
    }
}

// Exponentially back off until the order becomes ready or invalid.
#[tracing::instrument(skip_all)]
async fn wait_for_order_rdy<'a>(
    order: &'a mut Order,
    challenges: &[Http01Challenge],
    stdout: &mut impl Write,
    debug: bool,
) -> eyre::Result<&'a OrderState> {
    // Let the server know we're ready to accept the challenges.
    for Http01Challenge { url, .. } in challenges {
        order.set_challenge_ready(url).await.unwrap();
    }

    const MAX_DURATION: Duration = Duration::from_secs(10);
    let mut next_attempt = Instant::now();
    let deadline = Instant::now() + MAX_DURATION;
    let mut print_info = Some(Instant::now() + Duration::from_secs(2));
    let mut delay = Duration::from_millis(250);
    let mut attempt = 0;
    let state = loop {
        order
            .refresh()
            .await
            .wrap_err("could not get update on order from server")?;

        let status = match &order.state().status {
            OrderStatus::Ready => break Ok(order.state()),
            OrderStatus::Invalid => break Err(eyre::eyre!("order is invalid"))
                .suggestion("sometimes this happens when the challenge server is not reachable. Try the debug flag to investigate"),
            other => other,
        };

        if Instant::now() > deadline {
            break Err(eyre::eyre!("order is not ready in time"))
                .with_note(|| format!("last order status: {status:?}"));
        }
        delay *= 2;
        attempt += 1;
        next_attempt = deadline.min(next_attempt + delay);

        debug!(
            attempt,
            "order is not ready (status: {status:?}), waiting {delay:?} before retrying"
        );

        // None is smaller then all Some
        if print_info.is_some_and(|p| next_attempt > p) {
            print_info = None; // only print info once
            writeln!(
                stdout,
                "certificate authority is taking longer then expected, waiting {} more seconds",
                deadline.duration_until().as_secs()
            )
            .unwrap();
        }
        sleep_until(next_attempt).await;
    };

    if debug && state.is_err() {
        error!(
            "ran into error ({}) while in debug mode, pausing execution so you can investigate.",
            state.as_ref().unwrap_err().to_string()
        );
        debug!("Tip: check if the uri's in the above debug traces are reachable");
        tokio::task::spawn_blocking(move || {
            println!("Press enter to continue");
            std::io::stdin().read_exact(&mut [0]).unwrap();
        })
        .await
        .unwrap();
    }

    state
}

// If the order is ready, we can provision the certificate.
// Use the rcgen library to create a Certificate Signing Request.
#[tracing::instrument(skip_all)]
fn prepare_sign_request(names: &[String]) -> Result<(Certificate, Vec<u8>), rcgen::Error> {
    let mut params = CertificateParams::new(names);
    params.distinguished_name = DistinguishedName::new();
    let cert = Certificate::from_params(params).unwrap();
    let csr = cert.serialize_request_der()?;
    Ok((cert, csr))
}

#[tracing::instrument(skip_all)]
pub async fn renew<P: PemItem>(
    config: &Config,
    stdout: &mut impl Write,
    debug: bool,
) -> eyre::Result<Signed<P>> {
    let account = account(config).await?;
    let mut order = order(&account, &config.domains)
        .await
        .wrap_err("Certificate authority can not issue a certificate")
        .with_note(|| format!("names: {:?}", config.domains))?;

    let challenges = prepare_challenge(&mut order).await?;

    let server = server::run(config, &challenges).await?;
    diagnostics::reachable::server(config, &challenges)
        .await
        .wrap_err("Domain does not route to this application")?;
    write!(
        stdout,
        "waiting: certificate authority is verifing we own the domain"
    )
    .unwrap();
    stdout.flush().unwrap();

    let ready = wait_for_order_rdy(&mut order, &challenges, stdout, debug);
    let state = tokio::select!(
        res = ready => res?,
        e = server => {
            e.expect("server should never panic").wrap_err("Challenge server ran into problem")?;
            unreachable!("server never returns ok");
        }
    );

    if state.status == OrderStatus::Invalid {
        return Err(eyre::eyre!("order is invalid"))
            .suggestion("is the challenge server reachable?");
    }
    writeln!(stdout, ", done").unwrap();
    write!(
        stdout,
        "waiting: certificate authority is signing our certificate"
    )
    .unwrap();
    stdout.flush().unwrap();

    let names: Vec<String> = challenges.into_iter().map(|ch| ch.id).collect();
    let (cert, csr) = prepare_sign_request(&names)?;

    order.finalize(&csr).await.unwrap();
    let full_chain_pem = loop {
        match order.certificate().await? {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => sleep(Duration::from_secs(1)).await,
        }
    };

    writeln!(stdout, ", done").unwrap();
    Signed::from_key_and_fullchain(cert.serialize_private_key_pem(), full_chain_pem)
}

pub struct InstantAcme;

#[async_trait::async_trait]
impl super::ACME for InstantAcme {
    async fn renew<P: PemItem, W: Write + Send>(
        &self,
        config: &Config,
        stdout: &mut W,
        debug: bool,
    ) -> eyre::Result<Signed<P>> {
        renew(config, stdout, debug).await
    }
}
