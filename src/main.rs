use clap::Parser;
use service_binding::Binding;
use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use openpgp_card::{Error, KeyType, OpenPgp};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;
use openpgp_card_sequoia::util::key_slot;

use sequoia_openpgp::crypto::mpi::{PublicKey, Signature};
use sequoia_openpgp::crypto::Signer;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};

use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::proto::Blob;
use ssh_agent_lib::proto::{message::Identity, Message};

struct Backend {
    // Map: card ident -> user pin
    cards: Arc<Mutex<HashMap<String, String>>>,

    // Map: ssh pubkey_blob -> card ident
    keys: Arc<Mutex<HashMap<Vec<u8>, String>>>,

}

impl Backend {
    fn new() -> Self {
        Self {
            cards: Default::default(),
            keys: Default::default(),
        }
    }
}

/// Get SSH PublicKey representation for a Sequoia public Key
fn key_to_ssh(key: &Key<PublicParts, UnspecifiedRole>) -> openssh_keys::PublicKey {
    if let Key::V4(k) = key {
        match (k.pk_algo(), k.mpis()) {
            (PublicKeyAlgorithm::RSAEncryptSign, mpi) => {
                if let PublicKey::RSA { e, n } = mpi {
                    openssh_keys::PublicKey::from_rsa(e.value().to_vec(), n.value().to_vec())
                } else {
                    unimplemented!()
                }
            }
            (PublicKeyAlgorithm::EdDSA, mpi) => {
                if let PublicKey::EdDSA { curve, q } = mpi {
                    assert_eq!(curve, &Curve::Ed25519); // FIXME

                    openssh_keys::PublicKey {
                        data: openssh_keys::Data::Ed25519 {
                            key: q.value().to_vec()[1..].to_vec(), // FIXME: why?
                        },
                        comment: None,
                        options: None,
                    }
                } else {
                    unimplemented!()
                }
            }
            _ => unimplemented!(),
        }
    } else {
        unimplemented!()
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
                let mut card = PcscBackend::open_by_ident(&ident, None)?;
                let mut pgp = OpenPgp::new(&mut card);

                let mut open = Open::new(pgp.transaction()?)?;

                open.verify_user(pin.as_bytes())?;

                if let Ok(Some(pubkey)) = key_slot(&mut open, KeyType::Authentication) {
                    // Get ssh public key representation(s)
                    let pk = key_to_ssh(&pubkey);

                    let pubkey_blob = pk.data();

                    let keys = Arc::clone(&self.keys);
                    let mut keys = keys.lock().unwrap();
                    let keys = keys.borrow_mut();
                    keys.insert(pubkey_blob.clone(), ident.clone());


                    let cards = Arc::clone(&self.cards);
                    let mut cards = cards.lock().unwrap();
                    let cards = cards.borrow_mut();
                    log::debug!("cards insert {},{}", ident, pin);
                    cards.insert(ident, pin);

                    Ok(Message::Success)
                } else {
                    log::debug!("Couldn't get auth key from card");
                    Ok(Message::Failure)
                }
            }
            Message::RequestIdentities => {
                // This is triggered by "ssh-add -L" (and during login operations)

                log::debug!("RequestIdentities");

                // FIXME: filter out cards that are not currently plugged in?

                let keys = Arc::clone(&self.keys);
                let keys = keys.lock().unwrap();
                let keys = keys.borrow();

                let ids: Vec<_> = keys
                    .keys()
                    .map(|k| Identity {
                        pubkey_blob: k.clone(),
                        comment: "".to_string(),
                    })
                    .collect();

                log::debug!("Offering Identities {:#?}...", ids);

                Ok(Message::IdentitiesAnswer(ids))
            }

            Message::SignRequest(request) => {
                // This is triggered during ssh logins, if the remote server
                // knows any of the identities we report in RequestIdentities.

                log::debug!("-> SignRequest");

                // get card ident for this pubkey blob
                let pubkey_blob = request.pubkey_blob;

                let keys = Arc::clone(&self.keys);
                let mut keys = keys.lock().unwrap();
                let keys = keys.borrow_mut();

                if let Some(ident) = keys.get_mut(&pubkey_blob) {
                    log::debug!("ident {}",ident);

                    use sha2::{Digest, Sha256, Sha512};

                    const SSH_AGENT_RSA_SHA2_256: u32 = 2;
                    const SSH_AGENT_RSA_SHA2_512: u32 = 4;

                    let (content_type, digest) = if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                        let mut hasher = Sha256::new();
                        hasher.update(&request.data);
                        let digest = hasher.finalize().to_vec();

                        ("application/vnd.pks.digest.sha256", digest)
                    } else if request.flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                        let mut hasher = Sha512::new();
                        hasher.update(&request.data);
                        let digest = hasher.finalize().to_vec();

                        ("application/vnd.pks.digest.sha512", digest)
                    } else {
                        // raw message to be hashed and signed
                        // likely ed25519
                        ("application/octet-stream", request.data)
                    };

                    let hash_algo = match content_type {
                        "application/vnd.pks.digest.sha256" => HashAlgorithm::SHA256,
                        "application/vnd.pks.digest.sha512" => HashAlgorithm::SHA512,
                        _ => HashAlgorithm::SHA256, // FIXME?
                    };


                    let cards = Arc::clone(&self.cards);
                    let cards = cards.lock().unwrap();
                    let cards = cards.borrow();
                    let pin = cards.get(ident).expect("this shouldn't happen?");

                    let mut card = PcscBackend::open_by_ident(&ident, None)?;
                    let mut pgp = OpenPgp::new(&mut card);

                    let mut open = Open::new(pgp.transaction()?)?;

                    open.verify_user(pin.as_bytes())?;
                    let mut user = open.user_card().unwrap();

                    if let Ok(mut signer) = user.authenticator(&|| {
                        println!("Touch confirmation needed for authentication")
                    }) {
                        let signature = signer.sign(hash_algo, &digest).expect("failed to sign");

                        log::debug!("SIG: {:?}", signature);

                        let (algorithm, data) = match signature {
                            Signature::RSA { ref s } => match content_type {
                                "application/vnd.pks.digest.sha256" => {
                                    ("rsa-sha2-256", s.value().to_vec())
                                }
                                "application/vnd.pks.digest.sha512" => {
                                    ("rsa-sha2-512", s.value().to_vec())
                                }
                                _ => unimplemented!(),
                            },
                            Signature::EdDSA { ref r, ref s } => {
                                // FIXME
                                let mut v = vec![];
                                v.append(&mut r.value().to_vec());
                                v.append(&mut s.value().to_vec());

                                ("ssh-ed25519", v)
                            }
                            _ => unimplemented!(),
                        };

                        let s = ssh_agent_lib::proto::signature::Signature {
                            algorithm: algorithm.to_string(),
                            blob: data,
                        };

                        log::trace!("ssh signature: {:?} [len {}]", s, s.blob.len());

                        Ok(Message::SignResponse((s).to_blob().unwrap()))
                    } else {
                        log::debug!("Sign operation failed");

                        // FIXME: what should we do? -> unlock this key again?
                        log::debug!("Removing this key from the agent");

                        keys.remove(&pubkey_blob);

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
