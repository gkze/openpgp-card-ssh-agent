// SPDX-FileCopyrightText: 2021-2024 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: 2022-2024 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod card;
mod ssh;

use card_backend_pcsc::PcscBackend;
use clap::Parser;
use openpgp_card::ocard::crypto::{HashAlgo, PublicKeyMaterial, SigningAlgo};
use openpgp_card::ocard::{OpenPGP, Transaction};
use secrecy::ExposeSecret as _;
use sha2::digest::generic_array::GenericArray;
use ssh_agent_lib::agent::service_binding::Binding;
use ssh_agent_lib::agent::{bind, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest, SmartcardKey};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, Signature};

#[derive(Default, Clone)]
struct Backend;

#[cfg(feature = "notify")]
fn notify(msg: &str) {
    if let Err(e) = notify_rust::Notification::new()
        .summary("openpgp-card-ssh-agent")
        .body(msg)
        .timeout(std::time::Duration::from_secs(15))
        .show()
    {
        log::debug!("Failure in notify_rust: {:?}", e);
    }
}

#[cfg(not(feature = "notify"))]
fn notify(_: &str) {}

fn notify_and_log(msg: &str) {
    log::error!("{}", msg);
    notify(msg);
}

fn do_sign(
    tx: &mut Transaction,
    request: &SignRequest,
    pkm: PublicKeyMaterial,
) -> Result<Signature, AgentError> {
    let ard = tx.application_related_data().map_err(|e| {
        log::debug!("failed to get application_related_data: {}", e);
        AgentError::other(e)
    })?;
    let ident = ard
        .application_id()
        .map_err(|e| {
            log::debug!("failed to get application_id: {}", e);
            AgentError::other(e)
        })?
        .ident();

    log::debug!("Using card {:?}", ident);

    if let Some((sig_scheme, digest)) = ssh::signature_request_information(request, &pkm) {
        // Get User PIN from the state backend and present it to the card
        match openpgp_card_state::get_pin(&ident) {
            Ok(Some(pin)) => {
                // Our PIN backend has a User PIN for this ident
                if tx.verify_pw1_user(pin.as_bytes().to_vec().into()).is_err() {
                    // .. but verification against the card failed. Bad PIN?

                    // We drop the PIN from the state backend, to avoid exhausting
                    // the retry counter and locking up the User PIN.
                    let res = openpgp_card_state::drop_pin(&ident);

                    if res.is_ok() {
                        notify_and_log(&format!(
                                        "ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! Dropped it from storage.",
                                        ident));
                    } else {
                        notify_and_log(&format!(
                                        "ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! In addition, dropping it from storage failed.",
                                        ident));
                    }

                    return Err(AgentError::Failure);
                }
            }
            _ => {
                // FIXME: distinguish missing vs. error, later

                log::error!(
                    "No User PIN for card {} found via openpgp_card_state",
                    ident
                );

                notify(&format!(
                                "No User PIN available for this OpenPGP card. You can store a PIN by running 'ssh-add -s {}'",
                                ident));

                return Err(AgentError::Failure);
            }
        }

        // Notification function
        let touch_prompt = || {
            notify(&format!(
                "Touch confirmation needed for ssh auth on card {}",
                ident
            ));

            #[cfg(not(feature = "notify"))]
            println!("Touch confirmation needed for ssh auth on card {}", &ident);
        };

        // Determine UIF setting for the auth slot
        if let Ok(Some(uif)) = ard.uif_pso_aut() {
            // Touch is required if:
            // - the card supports the feature
            // - and the policy requires touch
            if uif.touch_policy().touch_required() {
                touch_prompt();
            }
        };

        // Perform signing operation on the card, and process signature
        if let Ok(signature) = match sig_scheme {
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            } => tx.authenticate_for_hash(SigningAlgo::RSA(HashAlgo::SHA256), &digest),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            } => tx.authenticate_for_hash(SigningAlgo::RSA(HashAlgo::SHA512), &digest),
            _ => tx.internal_authenticate(digest),
        } {
            log::debug!("sig from card: ({}) {:02x?}", signature.len(), signature);

            let data = match sig_scheme {
                Algorithm::Rsa { .. } => signature,
                Algorithm::Ed25519 => signature,
                Algorithm::Ecdsa { curve } => {
                    let len = signature.len();

                    let field_size = match curve {
                        EcdsaCurve::NistP256 => 32,
                        EcdsaCurve::NistP384 => 48,
                        EcdsaCurve::NistP521 => 66,
                    };

                    let r = &signature[0..len / 2];
                    let r = &r[r.len() - field_size..];
                    let s = &signature[len / 2..];
                    let s = &s[s.len() - field_size..];

                    return Ok(match curve {
                        EcdsaCurve::NistP256 => p256::ecdsa::Signature::from_scalars(
                            GenericArray::clone_from_slice(r),
                            GenericArray::clone_from_slice(s),
                        )
                        .map_err(AgentError::other)?
                        .try_into()
                        .map_err(AgentError::other)?,
                        EcdsaCurve::NistP384 => p384::ecdsa::Signature::from_scalars(
                            GenericArray::clone_from_slice(r),
                            GenericArray::clone_from_slice(s),
                        )
                        .map_err(AgentError::other)?
                        .try_into()
                        .map_err(AgentError::other)?,
                        EcdsaCurve::NistP521 => p521::ecdsa::Signature::from_scalars(
                            GenericArray::clone_from_slice(r),
                            GenericArray::clone_from_slice(s),
                        )
                        .map_err(AgentError::other)?
                        .try_into()
                        .map_err(AgentError::other)?,
                    });
                }
                _ => {
                    log::error!("Unexpected sig_scheme {sig_scheme}");
                    return Err(AgentError::Failure);
                }
            };

            let s = Signature::new(sig_scheme, data).map_err(AgentError::other)?;

            log::trace!("ssh signature: {:?}", s);

            Ok(s)
        } else {
            log::debug!("Sign operation failed");

            Err(AgentError::Failure)
        }
    } else {
        Err(AgentError::Failure)
    }
}

#[ssh_agent_lib::async_trait]
impl Session for Backend {
    /// Perform a private key signature operation.
    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        // This is triggered during ssh logins, if the remote server
        // knows any of the identities we offered in RequestIdentities.

        log::debug!("-> SignRequest {:x?}", request);

        let Ok(backends) = PcscBackend::cards(None) else {
            log::debug!("Can't find any cards");
            return Err(AgentError::Failure);
        };

        for b in backends.filter_map(|b| b.ok()) {
            if let Ok(mut card) = OpenPGP::new(b) {
                if let Ok(mut tx) = card.transaction() {
                    if let Some(pkm) = card::match_ssh_blob(&mut tx, request.credential.key_data())
                    {
                        // This card has the key material that we want to sign with,
                        // so we try signing the request with it.
                        return do_sign(&mut tx, &request, pkm);
                    }
                }
            }
        }

        log::debug!("Got a signing request for an identity we don't know about");
        Err(AgentError::Failure)
    }

    /// Add a key stored on a smartcard.
    async fn add_smartcard_key(&mut self, key: SmartcardKey) -> Result<(), AgentError> {
        // When running "ssh-add -s", this call gives us an `id` and a `pin`

        log::debug!("AddSmartcardKey -> {}", key.id);
        let ident = key.id;
        let pin = key.pin;

        // Open the card with identifier `ident`
        let mut opgp = card::card_by_ident(&ident)
            .map_err(|e| {
                notify_and_log(&format!("Couldn't open the card {}: {}", ident, e));
                e
            })
            .map_err(AgentError::other)?;
        let mut tx = opgp
            .transaction()
            .map_err(|e| {
                notify_and_log(&format!(
                    "Couldn't open transaction on card {}: {}",
                    ident, e
                ));
                e
            })
            .map_err(AgentError::other)?;

        // Check if the card contains an AUTH key
        // (using the fingerprint field as an indicator)
        if tx
            .application_related_data()
            .map_err(AgentError::other)?
            .fingerprints()
            .map_err(AgentError::other)?
            .authentication()
            .is_none()
        {
            // Card contains no AUTH key -> error out!
            notify_and_log(&format!(
                "The card {} doesn't seem to contain an authentication key",
                ident
            ));

            return Err(AgentError::Failure);
        }

        // Check if the card agrees with this User PIN
        tx.verify_pw1_user(pin.expose_secret().as_bytes().to_vec().into())
            .map_err(|e| {
                notify_and_log(&format!(
                    "User PIN verification failed on card {}: {}",
                    ident, e
                ));
                e
            })
            .map_err(AgentError::other)?;

        // The card liked this User PIN, we persist it via openpgp_card_state
        openpgp_card_state::set_pin(&ident, pin.expose_secret(), None)
            .map_err(|e| {
                notify_and_log(&format!("Error while storing User PIN: {}", e));
                e
            })
            .map_err(|_| AgentError::Failure)?;

        Ok(())
    }

    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        // This is triggered by "ssh-add -L" (and during login operations)
        log::debug!("RequestIdentities");

        if let Ok(ids) = card::list_ssh_identities() {
            Ok(ids)
        } else {
            log::debug!("failed to list ssh identities of cards");

            Err(AgentError::Failure)
        }
    }
}

#[derive(Debug)]
pub enum BackendError {
    Unknown(String),
}

#[derive(Parser, Debug)]
struct Args {
    /// Specifies the target binding host for the listener.
    /// Commonly used options are: `unix:///tmp/socket` for Unix domain socket
    /// or `fd://` for systemd socket activation.
    #[clap(short = 'H', long)]
    host: Binding,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();
    match bind(args.host.try_into()?, Backend).await {
        Err(e) => log::debug!("fn=main listener=OK at=bind err={:?}", e),
        Ok(_) => log::debug!("Listening done!"),
    }

    Ok(())
}
