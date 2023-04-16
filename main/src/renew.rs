use std::io::Read;
use std::time::Duration;

use color_eyre::eyre::{self, Context};
use color_eyre::Help;
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use tokio::time::sleep;
use tracing::{debug, error};

use crate::cert::Signed;
use crate::config::Config;

use super::server::Http01Challenge;
use acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    Order, OrderState, OrderStatus,
};
use instant_acme as acme;

// Create a new account. This will generate a fresh ECDSA key for you.
// Alternatively, restore an account from serialized credentials by
// using `Account::from_credentials()`.
#[tracing::instrument(skip_all)]
async fn account(production: bool) -> Result<Account, acme::Error> {
    let url = match production {
        true => LetsEncrypt::Production.url(),
        false => LetsEncrypt::Staging.url(),
    };
    Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        url,
    )
    .await
}

// Create the ACME order based on the given domain names.
// Note that this only needs an `&Account`, so the library will let you
// process multiple orders in parallel for a single account.
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
        .await
        .unwrap();

    Ok(order)
}

// Pick the desired challenge type and prepare the response.
#[tracing::instrument(skip_all)]
async fn prepare_challenge(
    order: &mut Order,
) -> eyre::Result<Vec<Http01Challenge>> {
    let authorizations = order.authorizations().await.unwrap();
    let mut challenges = Vec::with_capacity(authorizations.len());
    for authz in authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => todo!(),
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

// Exponentially back off until the order becomes ready or invalid.
#[tracing::instrument(skip_all)]
async fn wait_for_order_rdy<'a>(
    order: &'a mut Order,
    challenges: &[Http01Challenge],
    debug: bool,
) -> eyre::Result<&'a OrderState> {
    // Let the server know we're ready to accept the challenges.
    for Http01Challenge { url, .. } in challenges {
        order.set_challenge_ready(url).await.unwrap();
    }

    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    let state = loop {
        if tries >= 5 {
            break Err(eyre::eyre!("order is not ready in time"));
        }

        match &order.state().status {
            OrderStatus::Ready => break Ok(order.state()),
            OrderStatus::Invalid => break Err(eyre::eyre!("order is invalid"))
                .suggestion("sometimes this happens when the challenge server is not reachable. Try the debug flag to investigate"),
            _ => (),
        }

        delay *= 2;
        tries += 1;
        debug!(tries, "order is not ready, waiting {delay:?}");
        sleep(delay).await;
    };

    if debug && state.is_err() {
        error!(
            "ran into error ({}) while in debug mode, pausing execution so you can investigate.",
            state.as_ref().unwrap_err().to_string()
        );
        debug!("Tip: check if the uri's in the above debug traces are reachable");
        tokio::task::spawn_blocking(move || {
            println!("Press enter to continue");
            std::io::stdin().read(&mut [0]).unwrap();
        })
        .await
        .unwrap()
    }

    Ok(state?)
}

// If the order is ready, we can provision the certificate.
// Use the rcgen library to create a Certificate Signing Request.
#[tracing::instrument(skip_all)]
fn prepare_sign_request(names: &[String]) -> Result<(Certificate, Vec<u8>), rcgen::RcgenError> {
    let mut params = CertificateParams::new(names.clone());
    params.distinguished_name = DistinguishedName::new();
    let cert = Certificate::from_params(params).unwrap();
    let csr = cert.serialize_request_der()?;
    Ok((cert, csr))
}

#[tracing::instrument(skip_all)]
pub async fn request(config: &Config, debug: bool) -> eyre::Result<Signed> {
    let Config {
        domains: ref names,
        production,
        ..
    } = config;

    let account = account(*production).await?;
    let mut order = order(&account, names).await?;

    let challenges = prepare_challenge(&mut order).await?;

    let server = super::server::run(config, &challenges);
    let ready = wait_for_order_rdy(&mut order, &challenges, debug);
    let state = tokio::select!(
        res = ready => res?,
        e = server => {
            e.wrap_err("Challenge server ran into problem")?;
            unreachable!("server never returns ok");
        }
    );

    if state.status == OrderStatus::Invalid {
        return Err(eyre::eyre!("order is invalid"))
            .suggestion("is the challenge server reachable?");
    }

    let names: Vec<String> = challenges.into_iter().map(|ch| ch.id).collect();
    let (cert, csr) = prepare_sign_request(&names)?;

    order.finalize(&csr).await.unwrap();
    let cert_chain_pem = loop {
        match order.certificate().await? {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => sleep(Duration::from_secs(1)).await,
        }
    };

    Ok(Signed {
        private_key: cert.serialize_private_key_pem(),
        public_cert_chain: cert_chain_pem,
    })
}
