use clap::Parser;
use service_binding::Binding;

use sequoia_openpgp::crypto::mpi::{PublicKey, Signature};
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};

use sequoia_keystore_backend::Backend as KeystoreBackend;

use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::proto::Blob;
use ssh_agent_lib::proto::{message::Identity, Message};

struct Backend {
    // OpenPGP card keystore backend
    ocard: Box<sequoia_keystore_ocard::Backend>,

    // Identity (authentication key fingerprint)
    ident: std::sync::Arc<std::sync::Mutex<std::cell::RefCell<Option<String>>>>,

    // Public key
    public: std::sync::Arc<
        std::sync::Mutex<std::cell::RefCell<Option<Key<PublicParts, UnspecifiedRole>>>>,
    >,
}

impl Backend {
    fn new(ocard: Box<sequoia_keystore_ocard::Backend>) -> Self {
        Self {
            ocard,
            public: Default::default(),
            ident: Default::default(),
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
    type Error = BackendError;

    fn handle(&self, request: Message) -> Result<Message, Self::Error> {
        log::trace!("handle: request {:X?}", request);

        match request {
            Message::AddSmartcardKey(key) => {
                // When running "ssh-add -s", this call gives us an `id` and a `pin`

                log::debug!("AddSmartcardKey -> {}", key.id);
                let id = &key.id;
                let pin = key.pin;

                // FIXME: run backend scan to find new cards, if any?
                // -> needs &mut access to backend
                // (*self.ocard).scan().expect("backend scan");

                let mut key = (*self.ocard).find_key(id).expect("find key");

                key.unlock(&Password::from(pin.as_bytes())).expect("unlock");

                let ident = std::sync::Arc::clone(&self.ident);
                let ident = ident.lock().unwrap();

                ident.replace(Some(key.id()));

                let pubkey = key.public_key().expect("public key");

                let public = std::sync::Arc::clone(&self.public);
                let public = public.lock().unwrap();

                public.replace(Some(pubkey));

                log::debug!("AddSmartcardKey <-");

                Ok(Message::Success)
            }
            Message::RequestIdentities => {
                log::debug!("RequestIdentities");

                let public = {
                    let public = std::sync::Arc::clone(&self.public);
                    let public = public.lock().unwrap();
                    let public = public.borrow();
                    if public.is_none() {
                        log::debug!("No identities.");
                        return Ok(Message::IdentitiesAnswer(vec![]));
                    }
                    if let Some(public) = public.clone() {
                        public
                    } else {
                        return Ok(Message::Failure);
                    }
                };

                // Get ssh public key representation(s)
                let pk = key_to_ssh(&public);

                log::debug!("Offering Identity {}...", pk);

                let id = vec![Identity {
                    pubkey_blob: pk.data(),
                    comment: "".to_string(),
                }];

                Ok(Message::IdentitiesAnswer(id))
            }

            Message::SignRequest(request) => {
                log::debug!("-> SignRequest");

                // FIXME: we should sign with *this* key
                // -> Store a mapping from pubkey blob to keystore key?
                let _pubkey_blob = request.pubkey_blob;

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

                // FIXME: keystore key should be looked up by ssh pubkey blob?
                let ident = std::sync::Arc::clone(&self.ident);
                let ident = ident.lock().unwrap();
                let id = ident.borrow().clone();
                let mut key = (*self.ocard).find_key(&id.unwrap()).expect("find key");

                let signature = key.sign(hash_algo, &digest).expect("unlock");

                log::debug!("SIG: {:?}", signature);

                let (algorithm, data) = match signature {
                    Signature::RSA { ref s } => match content_type {
                        "application/vnd.pks.digest.sha256" => ("rsa-sha2-256", s.value().to_vec()),
                        "application/vnd.pks.digest.sha512" => ("rsa-sha2-512", s.value().to_vec()),
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

    let ocard = sequoia_keystore_ocard::Backend::init()?;

    let agent = Backend::new(ocard);
    match agent.listen(args.host.try_into()?) {
        Err(e) => log::debug!("fn=main listener=OK at=bind err={:?}", e),
        Ok(_) => log::debug!("Listening done!"),
    }

    Ok(())
}
