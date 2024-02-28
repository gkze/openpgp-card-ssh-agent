// SPDX-FileCopyrightText: 2021-2024 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: 2022-2024 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod card;
mod ssh;

use std::time::Duration;

use clap::Parser;
use openpgp_card::crypto_data::Hash;
use service_binding::Binding;
use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Blob, Message};

#[derive(Default)]
struct Backend;

#[ssh_agent_lib::async_trait]
impl Session for Backend {
    async fn handle(&mut self, request: Message) -> Result<Message, AgentError> {
        log::trace!("handle: request {:X?}", request);

        match request {
            Message::AddSmartcardKey(key) => {
                // When running "ssh-add -s", this call gives us an `id` and a `pin`

                log::debug!("AddSmartcardKey -> {}", key.id);
                let ident = key.id;
                let pin = key.pin;

                // try if pin is ok, then remember ident and pin
                let mut opgp = card::card_by_ident(&ident).map_err(|_| AgentError::User)?;
                let mut open = opgp.transaction().map_err(|_| AgentError::User)?;

                open.verify_pw1_user(pin.as_bytes())
                    .map_err(|_| AgentError::User)?;

                openpgp_card_state::put(&ident, &pin).map_err(|_| AgentError::User)?;

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
                    let mut tx = card.transaction().map_err(|_| AgentError::User)?;

                    let ard = tx
                        .application_related_data()
                        .map_err(|_| AgentError::User)?;
                    let ident = ard.application_id().map_err(|_| AgentError::User)?.ident();

                    log::debug!("Using card {:?}", ident);

                    if let Some((sig_scheme, digest)) =
                        ssh::signature_request_information(&request, &pkm)
                    {
                        // Get User PIN from the state backend and present it to the card
                        if let Ok(pin) = openpgp_card_state::get(&ident) {
                            tx.verify_pw1_user(pin.as_bytes())
                                .map_err(|_| AgentError::User)?;
                        } else {
                            log::error!(
                                "No User PIN for card {} found via openpgp_card_state",
                                ident
                            );
                            return Ok(Message::Failure);
                        }

                        // Notification function
                        let touch_prompt = || async {
                            #[cfg(feature = "notify")]
                            if let Err(e) = notify_rust::Notification::new()
                                .summary("openpgp-card-ssh-agent")
                                .body(&format!(
                                    "Touch confirmation needed for ssh auth on card {}",
                                    &ident
                                ))
                                .timeout(Duration::from_secs(15))
                                .show_async()
                                .await
                            {
                                eprintln!("Failure in notify_rust: {:?}", e);
                            }

                            #[cfg(not(feature = "notify"))]
                            println!("Touch confirmation needed for ssh auth on card {}", &ident);
                        };

                        // Determine UIF setting for the auth slot
                        if let Ok(Some(uif)) = ard.uif_pso_aut() {
                            // Touch is required if:
                            // - the card supports the feature
                            // - and the policy requires touch
                            if uif.touch_policy().touch_required() {
                                touch_prompt().await;
                            }
                        };

                        // Perform signing operation on the card, and process signature
                        if let Ok(signature) = match sig_scheme {
                            "rsa-sha2-256" => tx.authenticate_for_hash(Hash::SHA256(
                                digest.try_into().map_err(|_| AgentError::User)?,
                            )),
                            "rsa-sha2-512" => tx.authenticate_for_hash(Hash::SHA512(
                                digest.try_into().map_err(|_| AgentError::User)?,
                            )),
                            _ => tx.internal_authenticate(digest),
                        } {
                            log::debug!("sig from card: {:?}", signature);

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

                                    data.to_blob().map_err(|_| AgentError::User)?
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

                            Ok(Message::SignResponse(
                                s.to_blob().map_err(|_| AgentError::User)?,
                            ))
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

    let listener: service_binding::Listener = args.host.try_into()?;
    let handler = match listener {
        service_binding::Listener::Unix(listener) => {
            Backend.listen(tokio::net::UnixListener::from_std(listener)?)
        }
        service_binding::Listener::Tcp(listener) => {
            Backend.listen(tokio::net::TcpListener::from_std(listener)?)
        }
    };
    match handler.await {
        Err(e) => log::debug!("fn=main listener=OK at=bind err={:?}", e),
        Ok(_) => log::debug!("Listening done!"),
    }

    Ok(())
}
