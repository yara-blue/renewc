use std::io::Read;
use std::time::Duration;

use color_eyre::eyre::{self, Context};
use color_eyre::Help;
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use tokio::time::sleep;
use tracing::{error, debug};

use crate::cert::Signed;

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
async fn account(prod: bool) -> Result<Account, acme::Error> {
    let url = match prod {
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
async fn order(account: &Account, names: &[String]) -> Result<(Order, OrderState), acme::Error> {
    let identifiers = names
        .iter()
        .map(|name| Identifier::Dns(name.into()))
        .collect::<Vec<_>>();
    let (order, state) = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .unwrap();

    debug!("order state: {:#?}", state);
    Ok((order, state))
}

// Pick the desired challenge type and prepare the response.
#[tracing::instrument(skip_all)]
async fn prepare_challenge(
    order: &mut Order,
    state: OrderState,
) -> eyre::Result<Vec<Http01Challenge>> {
    let authorizations = order.authorizations(&state.authorizations).await.unwrap();
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
async fn wait_for_order_rdy(
    order: &mut Order,
    challenges: &[Http01Challenge],
    debug: bool,
) -> eyre::Result<OrderState> {
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

        let state = order.state().await.unwrap();
        match &state.status {
            OrderStatus::Ready => break Ok(state),
            OrderStatus::Invalid => break Err(eyre::eyre!("order is invalid")).suggestion("sometimes this happens when the challenge server is not reachable. Try the debug flag to investigate"),
            _ => (),
        }

        delay *= 2;
        tries += 1;
        debug!(?state, tries, "order is not ready, waiting {delay:?}");
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
pub async fn request(
    names: Vec<String>,
    port: u16,
    prod: bool,
    debug: bool,
) -> eyre::Result<Signed> {
    let account = account(prod).await?;
    let (mut order, state) = order(&account, &names).await?;

    let challenges = prepare_challenge(&mut order, state).await?;

    let server = super::server::run(port, &challenges);
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

    // Finalize the order and print certificate chain, private key and account credentials.
    let cert_chain_pem = order.finalize(&csr, &state.finalize).await.unwrap();
    Ok(Signed {
        private_key: cert.serialize_private_key_pem(),
        public_cert_chain: cert_chain_pem,
    })
}
