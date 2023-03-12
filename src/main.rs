// SPDX-FileCopyrightText: 2021-2022 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: 2022-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::borrow::{Borrow, BorrowMut};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use clap::Parser;
use openpgp_card::algorithm::{Algo, Curve};
use openpgp_card::crypto_data::{EccType, Hash, PublicKeyMaterial};
use openpgp_card::{Error, KeyType, OpenPgp};
use openpgp_card_pcsc::PcscBackend;
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
    fn new() -> Self {
        Self {
            cards: Default::default(),
        }
    }
}

fn get_ssh_pubkey(pkm: &PublicKeyMaterial) -> Result<openssh_keys::PublicKey> {
    match pkm {
        PublicKeyMaterial::R(rsa) => {
            let e = rsa.v().to_vec();
            let n = rsa.n().to_vec();

            Ok(openssh_keys::PublicKey::from_rsa(e, n))
        }
        PublicKeyMaterial::E(ecc) => {
            if let Algo::Ecc(ecc_attrs) = ecc.algo() {
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
                        if let Algo::Ecc(ecc_attrs) = ecc.algo() {
                            let curve = match ecc_attrs.curve() {
                                Curve::NistP256r1 => openssh_keys::Curve::Nistp256,
                                Curve::NistP384r1 => openssh_keys::Curve::Nistp384,
                                Curve::NistP521r1 => openssh_keys::Curve::Nistp521,
                                _ => unimplemented!(),
                            };

                            let key = ecc.data().to_vec();

                            Ok(openssh_keys::PublicKey {
                                data: openssh_keys::Data::Ecdsa { curve, key },
                                comment: None,
                                options: None,
                            })
                        } else {
                            panic!()
                        }
                    }
                    _ => Err(anyhow!("Unexpected EccType {:?}", ecc_attrs.ecc_type())),
                }
            } else {
                Err(anyhow!("Unexpected Algo in EccPub {:?}", ecc))
            }
        }
        _ => Err(anyhow!("Unexpected PublicKeyMaterial type {:?}", pkm)),
    }
}

impl Agent for Backend {
    type Error = Error;

    fn handle(&self, request: Message) -> Result<Message, Self::Error> {
        log::trace!("handle: request {:X?}", request);

        match request {
            Message::AddSmartcardKey(key) => {
                // When running "ssh-add -s", this call gives us an `id` and a `pin`

                log::debug!("AddSmartcardKey -> {}", key.id);
                let ident = key.id;
                let pin = key.pin;

                // try if pin is ok, then remember ident and pin
                let card = PcscBackend::open_by_ident(&ident, None)?;
                let mut opgp = OpenPgp::new(card);
                let mut open = opgp.transaction()?;

                open.verify_pw1_user(pin.as_bytes())?;

                if let Ok(pubkey) = open.public_key(KeyType::Authentication) {
                    // Get ssh public key representation(s)
                    if let Ok(pk) = get_ssh_pubkey(&pubkey) {
                        let sc = SshCard {
                            ident,
                            pin,
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

                        Ok(Message::Success)
                    } else {
                        Ok(Message::Failure)
                    }
                } else {
                    log::debug!("Couldn't get auth key from card");
                    Ok(Message::Failure)
                }
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
                                unimplemented!()
                            }
                        }
                        PublicKeyMaterial::E(ecc) => {
                            log::trace!("ECC data {:x?}, len {}", request.data, request.data.len());

                            if let Algo::Ecc(ea) = ecc.algo() {
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
                                            _ => unimplemented!(),
                                        }
                                    }
                                    EccType::EdDSA => {
                                        let curve = ea.curve();
                                        assert_eq!(curve, Curve::Ed25519);

                                        // raw message to be hashed and signed, ed25519
                                        ("ssh-ed25519", request.data)
                                    }
                                    _ => unimplemented!(),
                                }
                            } else {
                                unimplemented!()
                            }
                        }
                        _ => unimplemented!(),
                    };

                    let card = PcscBackend::open_by_ident(&sc.ident, None)?;
                    let mut opgp = OpenPgp::new(card);
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
                            _ => unimplemented!(),
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    let agent = Backend::new();
    match agent.listen(args.host.try_into()?) {
        Err(e) => log::debug!("fn=main listener=OK at=bind err={:?}", e),
        Ok(_) => log::debug!("Listening done!"),
    }

    Ok(())
}
