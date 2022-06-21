use clap::Parser;
use service_binding::Binding;

use sequoia_openpgp::crypto::mpi::PublicKey;
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::serialize::MarshalInto;
use sequoia_openpgp::types::PublicKeyAlgorithm;

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

impl Agent for Backend {
    type Error = BackendError;

    fn handle(&self, request: Message) -> Result<Message, Self::Error> {
        eprintln!("-> {:X?}", request);

        match request {
            Message::AddSmartcardKey(key) => {
                // When running "ssh-add -s", this call gives us an `id` and a `pin`

                eprintln!("AddSmartcardKey -> {}", key.id);
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

                eprintln!("AddSmartcardKey <-");

                Ok(Message::Success)
            }
            Message::RequestIdentities => {
                let public = {
                    let public = std::sync::Arc::clone(&self.public);
                    let public = public.lock().unwrap();
                    let public = public.borrow();
                    if public.is_none() {
                        eprintln!("No identities.");
                        return Ok(Message::IdentitiesAnswer(vec![]));
                    }
                    if let Some(public) = public.clone() {
                        public
                    } else {
                        return Ok(Message::Failure);
                    }
                };

                eprintln!("Offering Identity {:?}...", public);

                let pubkey_blob = if let Key::V4(k) = public {
                    match (k.pk_algo(), k.mpis()) {
                        (PublicKeyAlgorithm::RSAEncryptSign, mpi) => {
                            if let PublicKey::RSA { e, n } = mpi {
                                let pub_key = openssh_keys::PublicKey::from_rsa(
                                    e.to_vec().unwrap(),
                                    n.to_vec().unwrap(),
                                );
                                pub_key.data()
                            } else {
                                unimplemented!()
                            }
                        }
                        (PublicKeyAlgorithm::EdDSA, mpi) => {
                            if let PublicKey::EdDSA { curve, q } = mpi {
                                let key_type = sshkeys::KeyType::from_name("ssh-ed25519").unwrap();

                                let kind =
                                    sshkeys::PublicKeyKind::Ed25519(sshkeys::Ed25519PublicKey {
                                        key: q.value().to_vec()[1..].to_vec(), // FIXME: why [1..]?
                                        sk_application: None,
                                    });

                                let pk = sshkeys::PublicKey {
                                    key_type,
                                    comment: None,
                                    kind,
                                };

                                pk.encode()
                            } else {
                                unimplemented!()
                            }
                        }
                        _ => unimplemented!(),
                    }
                } else {
                    unimplemented!()
                };

                let id = vec![Identity {
                    pubkey_blob,
                    comment: "".to_string(),
                }];

                Ok(Message::IdentitiesAnswer(id))
            }

            Message::SignRequest(request) => {
                println!("sign req");

                use sha2::{Digest, Sha256, Sha512};

                const SSH_AGENT_RSA_SHA2_256: u32 = 2;
                const SSH_AGENT_RSA_SHA2_512: u32 = 4;

                let (content_type, body) = if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                    let mut hasher = Sha256::new();
                    hasher.update(&request.data);
                    let body = hasher.finalize().to_vec();

                    ("application/vnd.pks.digest.sha256", body)
                } else if request.flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                    let mut hasher = Sha512::new();
                    hasher.update(&request.data);
                    let body = hasher.finalize().to_vec();

                    ("application/vnd.pks.digest.sha512", body)
                } else {
                    // raw message to be hashed and signed
                    // likely ed25519
                    ("application/octet-stream", request.data)
                };

                unimplemented!();

                // let location = {
                //     let loc = std::sync::Arc::clone(&self.loc);
                //     let loc = loc.lock().unwrap();
                //     let loc = loc.borrow();
                //     if let Some(loc) = &*loc {
                //         loc.to_string()
                //     } else {
                //         return Ok(Message::Failure);
                //     }
                // };
                //
                // let rt = tokio::runtime::Builder::new_current_thread()
                //     .enable_io()
                //     .enable_time()
                //     .build()
                //     .unwrap();
                //
                // let location: hyper::Uri = location.parse().unwrap();
                // let client = Client::unix();
                //
                // let request = Request::builder()
                //     .method("POST")
                //     .uri(location)
                //     .header("Content-Type", content_type)
                //     .body(Body::from(body))
                //     .unwrap();
                // let response = rt.block_on(client.request(request)).unwrap();
                //
                // if !response.status().is_success() {
                //     return Err(BackendError::Unknown("badbad".to_string()));
                // }
                //
                // let response_type = response
                //     .headers()
                //     .get("Content-Type")
                //     .and_then(|v| v.to_str().ok())
                //     .unwrap_or("application/octet-stream")
                //     .to_string();
                // let signature = rt
                //     .block_on(hyper::body::to_bytes(response))
                //     .unwrap()
                //     .to_vec();
                //
                // //let signature = vec![];
                // eprintln!("SIG: {:?} ({})", signature, signature.len());
                // let algorithm = if response_type == "application/vnd.pks.signature.rsa" {
                //     if content_type == "application/vnd.pks.digest.sha256" {
                //         "rsa-sha2-256"
                //     } else {
                //         "rsa-sha2-512"
                //     }
                // } else {
                //     "ssh-ed25519"
                // };
                //
                // Ok(Message::SignResponse(
                //     (ssh_agent_lib::proto::signature::Signature {
                //         algorithm: algorithm.to_string(),
                //         blob: signature,
                //     })
                //         .to_blob()
                //         .unwrap(),
                // ))
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
        Err(e) => eprintln!("fn=main listener=OK at=bind err={:?}", e),
        Ok(_) => eprintln!("Listening done!"),
    }

    Ok(())
}
