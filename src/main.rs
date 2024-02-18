// SPDX-FileCopyrightText: 2021-2024 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: 2022-2024 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod pubkey;

use card_backend_pcsc::PcscBackend;
use clap::Parser;
use openpgp_card::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::crypto_data::{EccType, Hash, PublicKeyMaterial};
use openpgp_card::{Card, KeyType};
use service_binding::Binding;
use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::proto::{message::Identity, Blob, Message, SignRequest};

use crate::pubkey::get_ssh_pubkey;

/// Enumerate the ssh identities of all plugged in OpenPGP card AUTH slots
fn list_ssh_identities() -> Result<Vec<Identity>, Box<dyn std::error::Error>> {
    let backends = PcscBackend::cards(None)?;

    let mut ids = vec![];

    for b in backends.filter_map(|c| c.ok()) {
        let mut card = Card::new(b)?;
        let mut tx = card.transaction()?;

        if let Ok(pubkey) = tx.public_key(KeyType::Authentication) {
            if let Ok(ssh) = get_ssh_pubkey(&pubkey) {
                let id = Identity {
                    pubkey_blob: ssh.data(),
                    comment: "".to_string(),
                };

                ids.push(id);
            }
        }
    }

    Ok(ids)
}

fn card_by_ssh_blob(blob: &[u8]) -> Option<(Card, PublicKeyMaterial)> {
    let Ok(backends) = PcscBackend::cards(None) else {
        return None;
    };

    for b in backends.filter_map(|c| c.ok()) {
        if let Ok(mut card) = Card::new(b) {
            // signals that this is the right card
            let mut pkm = None;

            {
                if let Ok(mut tx) = card.transaction() {
                    if let Ok(pubkey) = tx.public_key(KeyType::Authentication) {
                        if let Ok(ssh) = get_ssh_pubkey(&pubkey) {
                            if ssh.data() == blob {
                                pkm = Some(pubkey);
                            }
                        }
                    }
                }
            }

            if let Some(pkm) = pkm {
                return Some((card, pkm));
            }
        }
    }

    None
}

#[derive(Default)]
struct Backend {}

#[async_trait::async_trait]
impl Agent for Backend {
    type Error = openpgp_card::Error;

    async fn handle(&self, request: Message) -> Result<Message, Self::Error> {
        log::trace!("handle: request {:X?}", request);

        match request {
            Message::RequestIdentities => {
                // This is triggered by "ssh-add -L" (and during login operations)
                log::debug!("RequestIdentities");

                if let Ok(ids) = list_ssh_identities() {
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
                let res = card_by_ssh_blob(&request.pubkey_blob);

                if let Some((mut card, pkm)) = res {
                    let mut tx = card.transaction()?;

                    let ard = tx.application_related_data()?;
                    let ident = ard.application_id()?.ident();

                    log::debug!("Using card {:?}", ident);

                    use sha2::Digest;

                    // Signature scheme "rsa-sha2-256" or "rsa-sha2-512" [I-D.ietf-curdle-rsa-sha2]
                    const SSH_AGENT_RSA_SHA2_256: u32 = 2;
                    const SSH_AGENT_RSA_SHA2_512: u32 = 4;

                    fn signature_request_information(
                        request: &SignRequest,
                        pkm: &PublicKeyMaterial,
                    ) -> Option<(&'static str, Vec<u8>)> {
                        match pkm {
                            PublicKeyMaterial::R(_) => {
                                if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                                    let mut hasher = sha2::Sha256::new();
                                    hasher.update(&request.data);
                                    Some(("rsa-sha2-256", hasher.finalize().to_vec()))
                                } else if request.flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                                    let mut hasher = sha2::Sha512::new();
                                    hasher.update(&request.data);
                                    Some(("rsa-sha2-256", hasher.finalize().to_vec()))
                                } else {
                                    log::error!("Unexpected RSA case");
                                    return None;
                                }
                            }
                            PublicKeyMaterial::E(ecc) => {
                                log::trace!(
                                    "ECC data {:x?}, len {}",
                                    request.data,
                                    request.data.len()
                                );

                                if let AlgorithmAttributes::Ecc(ea) = ecc.algo() {
                                    match ea.ecc_type() {
                                        EccType::ECDSA => {
                                            let curve = ea.curve();

                                            log::trace!("ECDSA {:?}", curve);

                                            match curve {
                                                Curve::NistP256r1 => {
                                                    let mut hasher = sha2::Sha256::new();
                                                    hasher.update(&request.data);
                                                    let digest = hasher.finalize().to_vec();

                                                    Some(("ecdsa-sha2-nistp256", digest))
                                                }
                                                Curve::NistP384r1 => {
                                                    let mut hasher = sha2::Sha384::new();
                                                    hasher.update(&request.data);
                                                    let digest = hasher.finalize().to_vec();

                                                    Some(("ecdsa-sha2-nistp384", digest))
                                                }
                                                Curve::NistP521r1 => {
                                                    let mut hasher = sha2::Sha512::new();
                                                    hasher.update(&request.data);
                                                    let digest = hasher.finalize().to_vec();

                                                    Some(("ecdsa-sha2-nistp521", digest))
                                                }
                                                _ => {
                                                    log::error!(
                                                        "Unexpected ECDSA curve {:?}",
                                                        curve
                                                    );
                                                    None
                                                }
                                            }
                                        }
                                        EccType::EdDSA => {
                                            let curve = ea.curve();
                                            assert_eq!(curve, &Curve::Ed25519);

                                            // raw message to be hashed and signed, ed25519
                                            Some(("ssh-ed25519", request.data.clone()))
                                        }
                                        e => {
                                            log::error!("Unexpected EccType {:?}", e);
                                            None
                                        }
                                    }
                                } else {
                                    log::error!("Unexpected ECC case");
                                    None
                                }
                            }
                            _ => {
                                log::error!("Unexpected PublicKeyMaterial case");
                                None
                            }
                        }
                    }

                    if let Some((sig_scheme, digest)) =
                        signature_request_information(&request, &pkm)
                    {
                        // Get User PIN from the state backend and present it to the card
                        let (pin, _) = openpgp_card_state::get(&ident).await;
                        tx.verify_pw1_user(pin.as_bytes())?;

                        // Notification function
                        let touch_prompt = || async {
                            #[cfg(feature = "notify")]
                            if let Err(e) = notify_rust::Notification::new()
                                .summary("openpgp-card-ssh-agent")
                                .body(&format!(
                                    "Touch confirmation needed for ssh auth on card {}",
                                    &ident
                                ))
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
                            "rsa-sha2-256" => {
                                tx.authenticate_for_hash(Hash::SHA256(digest.try_into().unwrap()))
                            }
                            "rsa-sha2-512" => {
                                tx.authenticate_for_hash(Hash::SHA512(digest.try_into().unwrap()))
                            }
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

                                    data.to_blob().unwrap() // FIXME: unwrap
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

                            Ok(Message::SignResponse(s.to_blob().unwrap()))
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

    let agent = Backend::default();

    let listener: service_binding::Listener = args.host.try_into()?;
    let x = match listener {
        service_binding::Listener::Unix(listener) => {
            agent.listen(tokio::net::UnixListener::from_std(listener)?)
        }
        service_binding::Listener::Tcp(listener) => {
            agent.listen(tokio::net::TcpListener::from_std(listener)?)
        }
    };
    match x.await {
        Err(e) => log::debug!("fn=main listener=OK at=bind err={:?}", e),
        Ok(_) => log::debug!("Listening done!"),
    }

    Ok(())
}
