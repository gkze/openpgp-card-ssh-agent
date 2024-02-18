// SPDX-FileCopyrightText: 2021-2022 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: 2022-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::borrow::{Borrow, BorrowMut};
use std::sync::{Arc, Mutex};

use card_backend_pcsc::PcscBackend;
use clap::Parser;
use openpgp_card::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::crypto_data::{EccType, Hash, PublicKeyMaterial};
use openpgp_card::{Card, KeyType};
use service_binding::Binding;
use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::proto::{message::Identity, Blob, Message};

#[derive(Debug)]
struct SshCard {
    ident: String,
    pin: String,
    auth_pub: PublicKeyMaterial,
    ssh_pubkey_blob: Vec<u8>,
}

struct Backend {
    // List of Cards
    cards: Arc<Mutex<Vec<SshCard>>>,
}

impl Backend {
    async fn new() -> Self {
        let mut backend = Self {
            cards: Default::default(),
        };

        let idents = openpgp_card_state::list().await;

        for ident in idents {
            println!("trying to add card {}", ident);

            let (pin, _nick) = openpgp_card_state::get(&ident).await;

            if let Err(e) = backend.add_card(&ident, &pin) {
                println!("failed to add card {:?}, ignoring", e);
            }
        }

        backend
    }

    fn add_card(&mut self, ident: &str, pin: &str) -> Result<(), anyhow::Error> {
        log::debug!("add card {}", ident);

        // try if pin is ok, then remember ident and pin
        let mut opgp = card_by_ident(ident)?;
        let mut open = opgp.transaction()?;

        open.verify_pw1_user(pin.as_bytes())?;

        if let Ok(pubkey) = open.public_key(KeyType::Authentication) {
            // Get ssh public key representation(s)
            match get_ssh_pubkey(&pubkey) {
                Ok(pk) => {
                    let sc = SshCard {
                        ident: ident.to_string(),
                        pin: pin.to_string(),
                        auth_pub: pubkey,
                        ssh_pubkey_blob: pk.data(),
                    };

                    let cards = Arc::clone(&self.cards);
                    let mut cards = cards.lock().unwrap();
                    let cards = cards.borrow_mut();

                    log::debug!("cards insert {:?}", sc);

                    // remove list entries that have the same card ident as this one
                    cards.retain(|c| c.ident != sc.ident);

                    // append new SshCard to our list
                    cards.push(sc);
                }
                Err(e) => {
                    log::debug!("Failed to transform pkm with get_ssh_pubkey: {:?}", e);
                    panic!("Failed to transform pkm with get_ssh_pubkey: {:?}", e);
                }
            }
        } else {
            log::debug!("Couldn't get auth key from card");
            panic!("Couldn't get auth key from card")
        }

        Ok(())
    }
}

fn card_by_ident(ident: &str) -> Result<Card, openpgp_card::Error> {
    let backends = PcscBackend::cards(None)?;

    for b in backends.filter_map(|c| c.ok()) {
        let mut card = Card::new(b)?;

        let aid = {
            let mut tx = card.transaction()?;
            tx.application_related_data()?
        };

        if aid.application_id()?.ident() == ident.to_ascii_uppercase() {
            return Ok(card);
        }
    }

    Err(openpgp_card::Error::NotFound(format!(
        "Couldn't open card '{}'",
        ident
    )))
}

fn get_ssh_pubkey(
    pkm: &PublicKeyMaterial,
) -> Result<openssh_keys::PublicKey, Box<dyn std::error::Error>> {
    match pkm {
        PublicKeyMaterial::R(rsa) => {
            let e = rsa.v().to_vec();
            let n = rsa.n().to_vec();

            Ok(openssh_keys::PublicKey::from_rsa(e, n))
        }
        PublicKeyMaterial::E(ecc) => {
            if let AlgorithmAttributes::Ecc(ecc_attrs) = ecc.algo() {
                match ecc_attrs.ecc_type() {
                    EccType::EdDSA => {
                        let key = ecc.data().to_vec();

                        Ok(openssh_keys::PublicKey {
                            data: openssh_keys::Data::Ed25519 { key },
                            comment: None,
                            options: None,
                        })
                    }
                    EccType::ECDSA => {
                        if let AlgorithmAttributes::Ecc(ecc_attrs) = ecc.algo() {
                            let curve = match ecc_attrs.curve() {
                                Curve::NistP256r1 => openssh_keys::Curve::Nistp256,
                                Curve::NistP384r1 => openssh_keys::Curve::Nistp384,
                                Curve::NistP521r1 => openssh_keys::Curve::Nistp521,
                                _ => {
                                    return Err(anyhow::anyhow!(
                                        "Unsupported ECDSA curve {:?}",
                                        ecc_attrs.curve()
                                    )
                                    .into())
                                }
                            };

                            let key = ecc.data().to_vec();

                            Ok(openssh_keys::PublicKey {
                                data: openssh_keys::Data::Ecdsa { curve, key },
                                comment: None,
                                options: None,
                            })
                        } else {
                            Err(anyhow::anyhow!("Unexpected ecc.algo {:?}", ecc.algo()).into())
                        }
                    }
                    _ => {
                        Err(anyhow::anyhow!("Unexpected EccType {:?}", ecc_attrs.ecc_type()).into())
                    }
                }
            } else {
                Err(anyhow::anyhow!("Unexpected Algo in EccPub {:?}", ecc).into())
            }
        }
        _ => Err(anyhow::anyhow!("Unexpected PublicKeyMaterial type {:?}", pkm).into()),
    }
}

#[async_trait::async_trait]
impl Agent for Backend {
    type Error = openpgp_card::Error;

    async fn handle(&self, request: Message) -> Result<Message, Self::Error> {
        log::trace!("handle: request {:X?}", request);

        match request {
            Message::AddSmartcardKey(_key) => {
                // When running "ssh-add -s", this call gives us an `id` and a `pin`
                todo!();
            }
            Message::RequestIdentities => {
                // This is triggered by "ssh-add -L" (and during login operations)

                log::debug!("RequestIdentities");

                // FIXME: filter out cards that are not currently plugged in?

                let cards = Arc::clone(&self.cards);
                let cards = cards.lock().unwrap();
                let cards = cards.borrow();

                let ids: Vec<_> = cards
                    .iter()
                    .map(|k| Identity {
                        pubkey_blob: k.ssh_pubkey_blob.clone(),
                        comment: "".to_string(),
                    })
                    .collect();

                log::debug!("Offering Identities {:x?}", ids);

                Ok(Message::IdentitiesAnswer(ids))
            }

            Message::SignRequest(request) => {
                // This is triggered during ssh logins, if the remote server
                // knows any of the identities we report in RequestIdentities.

                log::debug!("-> SignRequest {:x?}", request);

                // get card ident for this pubkey blob
                let pubkey_blob = request.pubkey_blob;

                let cards = Arc::clone(&self.cards);
                let mut cards = cards.lock().unwrap();
                let cards = cards.borrow_mut();

                if let Some(sc) = cards.iter().find(|sc| sc.ssh_pubkey_blob == pubkey_blob) {
                    log::debug!("Using card {:?}", sc);

                    use sha2::Digest;

                    // Signature scheme "rsa-sha2-256" or "rsa-sha2-512" [I-D.ietf-curdle-rsa-sha2]
                    const SSH_AGENT_RSA_SHA2_256: u32 = 2;
                    const SSH_AGENT_RSA_SHA2_512: u32 = 4;

                    let (sig_scheme, digest) = match &sc.auth_pub {
                        PublicKeyMaterial::R(_) => {
                            if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                                let mut hasher = sha2::Sha256::new();
                                hasher.update(&request.data);
                                ("rsa-sha2-256", hasher.finalize().to_vec())
                            } else if request.flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                                let mut hasher = sha2::Sha512::new();
                                hasher.update(&request.data);
                                ("rsa-sha2-256", hasher.finalize().to_vec())
                            } else {
                                log::error!("Unexpected RSA case");
                                return Ok(Message::Failure);
                            }
                        }
                        PublicKeyMaterial::E(ecc) => {
                            log::trace!("ECC data {:x?}, len {}", request.data, request.data.len());

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

                                                ("ecdsa-sha2-nistp256", digest)
                                            }
                                            Curve::NistP384r1 => {
                                                let mut hasher = sha2::Sha384::new();
                                                hasher.update(&request.data);
                                                let digest = hasher.finalize().to_vec();

                                                ("ecdsa-sha2-nistp384", digest)
                                            }
                                            Curve::NistP521r1 => {
                                                let mut hasher = sha2::Sha512::new();
                                                hasher.update(&request.data);
                                                let digest = hasher.finalize().to_vec();

                                                ("ecdsa-sha2-nistp521", digest)
                                            }
                                            _ => {
                                                log::error!("Unexpected ECDSA curve {:?}", curve);
                                                return Ok(Message::Failure);
                                            }
                                        }
                                    }
                                    EccType::EdDSA => {
                                        let curve = ea.curve();
                                        assert_eq!(curve, &Curve::Ed25519);

                                        // raw message to be hashed and signed, ed25519
                                        ("ssh-ed25519", request.data)
                                    }
                                    e => {
                                        log::error!("Unexpected EccType {:?}", e);
                                        return Ok(Message::Failure);
                                    }
                                }
                            } else {
                                log::error!("Unexpected ECC case");
                                return Ok(Message::Failure);
                            }
                        }
                        _ => {
                            log::error!("Unexpected PublicKeyMaterial case");
                            return Ok(Message::Failure);
                        }
                    };

                    let mut opgp = card_by_ident(&sc.ident)?;
                    let mut open = opgp.transaction()?;

                    open.verify_pw1_user(sc.pin.as_bytes())?;

                    // Determine UIF setting for the auth slot
                    let ard = open.application_related_data()?;

                    // Notification function
                    let touch_prompt = move || {
                        #[cfg(feature = "notify")]
                        if let Err(e) = notify_rust::Notification::new()
                            .summary("openpgp-card-ssh-agent")
                            .body(&format!(
                                "Touch confirmation needed for ssh auth on card {}",
                                &sc.ident
                            ))
                            .show()
                        {
                            eprintln!("Failure in notify_rust: {:?}", e);
                        }

                        #[cfg(not(feature = "notify"))]
                        println!(
                            "Touch confirmation needed for ssh auth on card {}",
                            &sc.ident
                        );
                    };

                    if let Ok(Some(uif)) = ard.uif_pso_aut() {
                        // Touch is required if:
                        // - the card supports the feature
                        // - and the policy requires touch
                        if uif.touch_policy().touch_required() {
                            touch_prompt();
                        }
                    };

                    // Perform signing operation of card and process signature
                    if let Ok(signature) = match sig_scheme {
                        "rsa-sha2-256" => {
                            open.authenticate_for_hash(Hash::SHA256(digest.try_into().unwrap()))
                        }
                        "rsa-sha2-512" => {
                            open.authenticate_for_hash(Hash::SHA512(digest.try_into().unwrap()))
                        }
                        _ => open.internal_authenticate(digest),
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

                        Ok(Message::SignResponse((s).to_blob().unwrap()))
                    } else {
                        log::debug!("Sign operation failed, removing this card from the agent");
                        cards.retain(|c| c.ssh_pubkey_blob != pubkey_blob);

                        Ok(Message::Failure)
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

    let agent = Backend::new().await;
    let binding = args.host;
    let listener: service_binding::Listener = binding.try_into()?;
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
