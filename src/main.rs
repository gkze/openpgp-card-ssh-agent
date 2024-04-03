// SPDX-FileCopyrightText: 2021-2024 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: 2022-2024 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod card;
mod ssh;

use clap::Parser;
use openpgp_card::crypto_data::Hash;
use service_binding::Binding;
use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::proto::{Blob, Message};

#[derive(Default)]
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

#[ssh_agent_lib::async_trait]
impl Session for Backend {
    async fn handle(&mut self, request: Message) -> Result<Message, Box<dyn std::error::Error>> {
        log::trace!("handle: request {:X?}", request);

        match request {
            Message::AddSmartcardKey(key) => {
                // When running "ssh-add -s", this call gives us an `id` and a `pin`

                log::debug!("AddSmartcardKey -> {}", key.id);
                let ident = key.id;
                let pin = key.pin;

                // Open the card with identifier `ident`
                let mut opgp = card::card_by_ident(&ident).map_err(|e| {
                    notify_and_log(&format!("Couldn't open the card {}: {}", ident, e));
                    e
                })?;
                let mut tx = opgp.transaction().map_err(|e| {
                    notify_and_log(&format!(
                        "Couldn't open transaction on card {}: {}",
                        ident, e
                    ));
                    e
                })?;

                // Check if the card contains an AUTH key
                // (using the fingerprint field as an indicator)
                if tx
                    .application_related_data()?
                    .fingerprints()?
                    .authentication()
                    .is_none()
                {
                    // Card contains no AUTH key -> error out!
                    notify_and_log(&format!(
                        "The card {} doesn't seem to contain an authentication key",
                        ident
                    ));

                    return Ok(Message::Failure);
                }

                // Check if the card agrees with this User PIN
                tx.verify_pw1_user(pin.as_bytes()).map_err(|e| {
                    notify_and_log(&format!(
                        "User PIN verification failed on card {}: {}",
                        ident, e
                    ));
                    e
                })?;

                // The card liked this User PIN, we persist it via openpgp_card_state
                openpgp_card_state::set_pin(&ident, &pin).map_err(|e| {
                    notify_and_log(&format!("Error while storing User PIN: {}", e));
                    e
                })?;

                Ok(Message::Success)
            }

            Message::RequestIdentities => {
                // This is triggered by "ssh-add -L" (and during login operations)
                log::debug!("RequestIdentities");

                if let Ok(ids) = card::list_ssh_identities() {
                    Ok(Message::IdentitiesAnswer(ids))
                } else {
                    log::debug!("failed to list ssh identities of cards");

                    Ok(Message::Failure)
                }
            }

            Message::SignRequest(request) => {
                // This is triggered during ssh logins, if the remote server
                // knows any of the identities we offered in RequestIdentities.

                log::debug!("-> SignRequest {:x?}", request);

                // get card for this pubkey blob
                let res = card::card_by_ssh_blob(&request.pubkey_blob);

                if let Some((mut card, pkm)) = res {
                    let mut tx = card.transaction().map_err(|e| {
                        log::debug!("failed to re-start transaction: {}", e);
                        e
                    })?;

                    let ard = tx.application_related_data().map_err(|e| {
                        log::debug!("failed to get application_related_data: {}", e);
                        e
                    })?;
                    let ident = ard
                        .application_id()
                        .map_err(|e| {
                            log::debug!("failed to get application_id: {}", e);
                            e
                        })?
                        .ident();

                    log::debug!("Using card {:?}", ident);

                    if let Some((sig_scheme, digest)) =
                        ssh::signature_request_information(&request, &pkm)
                    {
                        // Get User PIN from the state backend and present it to the card
                        match openpgp_card_state::get_pin(&ident) {
                            Ok(Some(pin)) => {
                                // Our PIN backend has a User PIN for this ident
                                if tx.verify_pw1_user(pin.as_bytes()).is_err() {
                                    // .. but verification against the card failed. Bad PIN?

                                    // We drop the PIN from the state backend, to avoid exhausting
                                    // the retry counter and locking up the User PIN.
                                    let res = openpgp_card_state::drop_pin(&ident);

                                    if res.is_ok() {
                                        notify_and_log(&format!(
                                            "ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! Dropped it from storage.",
                                            &ident));
                                    } else {
                                        notify_and_log(&format!(
                                            "ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! In addition, dropping it from storage failed.",
                                            &ident));
                                    }

                                    return Ok(Message::Failure);
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
                                    &ident));

                                return Ok(Message::Failure);
                            }
                        }

                        // Notification function
                        let touch_prompt = || {
                            notify(&format!(
                                "Touch confirmation needed for ssh auth on card {}",
                                &ident
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
                            "rsa-sha2-256" => tx.authenticate_for_hash(Hash::SHA256(
                                digest.try_into().map_err(|e| {
                                    log::debug!("failed to map rsa-sha2-256 digest: {:02x?}", e);
                                    std::io::Error::other("convert")
                                })?,
                            )),
                            "rsa-sha2-512" => tx.authenticate_for_hash(Hash::SHA512(
                                digest.try_into().map_err(|e| {
                                    log::debug!("failed to map rsa-sha2-512 digest: {:02x?}", e);
                                    std::io::Error::other("convert")
                                })?,
                            )),
                            _ => tx.internal_authenticate(digest),
                        } {
                            log::debug!("sig from card: {:02x?}", signature);

                            let data = match sig_scheme {
                                "rsa-sha2-256" | "rsa-sha2-512" => signature,
                                "ssh-ed25519" => signature,
                                "ecdsa-sha2-nistp256"
                                | "ecdsa-sha2-nistp384"
                                | "ecdsa-sha2-nistp521" => {
                                    let len = signature.len();

                                    let mut r = signature[0..len / 2].to_vec();
                                    let mut s = signature[len / 2..].to_vec();

                                    // https://datatracker.ietf.org/doc/html/rfc4251#section-5
                                    //
                                    // "If the most significant bit would be set for a positive
                                    // number, the number MUST be preceded by a zero byte."
                                    if r[0] & 128 != 0 {
                                        log::trace!("prepending 0 byte for r");
                                        r.insert(0, 0);
                                    }
                                    if s[0] & 128 != 0 {
                                        log::trace!("prepending 0 byte for s");
                                        s.insert(0, 0);
                                    }

                                    let data = ssh_agent_lib::proto::EcDsaSignatureData { r, s };
                                    log::trace!("{:x?}", data);

                                    data.to_blob().map_err(|e| {
                                        log::debug!(
                                            "failed to get blob for EcDsaSignatureData: {}",
                                            e
                                        );
                                        std::io::Error::other("convert")
                                    })?
                                }
                                _ => {
                                    log::error!("Unexpected sig_scheme {sig_scheme}");
                                    return Ok(Message::Failure);
                                }
                            };

                            let s = ssh_agent_lib::proto::signature::Signature {
                                algorithm: sig_scheme.to_string(),
                                blob: data,
                            };

                            log::trace!("ssh signature: {:?} [len {}]", s, s.blob.len());

                            Ok(Message::SignResponse(s.to_blob()?))
                        } else {
                            log::debug!("Sign operation failed");

                            Ok(Message::Failure)
                        }
                    } else {
                        return Ok(Message::Failure);
                    }
                } else {
                    log::debug!("Got a signing request for an identity we don't know about");
                    Ok(Message::Failure)
                }
            }
            _ => Ok(Message::Failure),
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
    match Backend.bind(args.host.try_into()?).await {
        Err(e) => log::debug!("fn=main listener=OK at=bind err={:?}", e),
        Ok(_) => log::debug!("Listening done!"),
    }

    Ok(())
}
