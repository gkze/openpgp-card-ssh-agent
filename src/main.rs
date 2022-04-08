use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::proto::Blob;
use ssh_agent_lib::proto::{message::Identity, Message};

use hyper::{Body, Client, Request};
use hyperlocal::{UnixClientExt, Uri};

#[derive(Default)]
struct Backend {
    loc: std::sync::Arc<std::sync::Mutex<std::cell::RefCell<Option<String>>>>,
    public: std::sync::Arc<std::sync::Mutex<std::cell::RefCell<Option<String>>>>,
}

impl Agent for Backend {
    type Error = BackendError;

    fn handle(&self, request: Message) -> Result<Message, Self::Error> {
        eprintln!("-> {:X?}", request);
        //let key = openssh_keys::PublicKey::parse("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHCXBJYlPPkrt2WYyP3SZoMx43lDBB5QALjE762EQlc openpgp:0x0529CE0A").unwrap();
        //eprintln!("LEM = {}", key.data().len());
        //eprintln!("Key = {:X?}", key.data());
        //let data = base64::decode("AAAAC3NzaC1lZDI1NTE5AAAAIPXlzC83a2MfZUYIY/J+Qymr7x4n29Wwix9KW0dl1Yl6").unwrap(); // sig key
        //let data =
        //    base64::decode("AAAAC3NzaC1lZDI1NTE5AAAAILHCXBJYlPPkrt2WYyP3SZoMx43lDBB5QALjE762EQlc")
        //        .unwrap(); // auth key
        match request {
            Message::RequestIdentities => {
                let public = {
                    let public = std::sync::Arc::clone(&self.public);
                    let public = public.lock().unwrap();
                    let public = public.borrow();
                    if public.is_none() {
                        eprintln!("No identities.");
                        return Ok(Message::IdentitiesAnswer(vec![]));
                    }
                    if let Some(public) = &*public {
                        public.to_string()
                    } else {
                        return Ok(Message::Failure);
                    }
                };

                eprintln!("Getting {}...", public);

                let public = Uri::new(std::env::var("PKS_SOCK").unwrap(), &public);
                let client = Client::unix();
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();

                let request = Request::builder()
                    .method("GET")
                    .uri(public)
                    .body(Body::default())
                    .unwrap();
                let response = rt.block_on(client.request(request)).unwrap();

                if !response.status().is_success() {
                    return Err(BackendError::Unknown("badbad".to_string()));
                }

                let content_type =
                    if let Some(content_type) = response.headers().get("Content-Type") {
                        content_type.to_str().unwrap().to_string()
                    } else {
                        return Err(BackendError::Unknown("No Content-Type".to_string()));
                    };
                let exponent = response
                    .headers()
                    .get("Exponent")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(65537);

                let data = rt
                    .block_on(hyper::body::to_bytes(response))
                    .unwrap()
                    .to_vec();
                let pubkey_blob = if content_type == "application/vnd.pks.public.ed25519.compressed"
                {
                    let mut pubkey_blob = vec![0, 0, 0, 0xb];
                    pubkey_blob.extend("ssh-ed25519".as_bytes());
                    pubkey_blob.extend(vec![0, 0, 0, 0x20]);
                    pubkey_blob.extend(data);
                    pubkey_blob
                } else if content_type == "application/vnd.pks.public.rsa.modulus" {
                    let pub_key =
                        openssh_keys::PublicKey::from_rsa(exponent.to_be_bytes().into(), data);
                    pub_key.data()
                } else {
                    return Err(BackendError::Unknown("Unknown Content-Type".to_string()));
                };

                Ok(Message::IdentitiesAnswer(vec![Identity {
                    pubkey_blob,
                    comment: "".to_string(),
                }]))
            }
            Message::AddSmartcardKey(key) => {
                eprintln!("AddSmartcardKey -> {}", key.id);
                let id = &key.id;
                let pin = key.pin;

                let location = id;

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();

                let location = Uri::new(std::env::var("PKS_SOCK").unwrap(), location);
                let client = Client::unix();

                let request = Request::builder()
                    .method("POST")
                    .uri(location)
                    .body(Body::from(pin))
                    .unwrap();
                let response = rt.block_on(client.request(request)).unwrap();
                eprintln!("AddSmartcardKey = {}", response.status());

                if !response.status().is_success() {
                    return Err(BackendError::Unknown("badbad".to_string()));
                }

                let location = if let Some(loc) = response.headers().get("Location") {
                    loc.to_str().unwrap()
                } else {
                    return Ok(Message::Failure);
                };

                let loc = std::sync::Arc::clone(&self.loc);
                let loc = loc.lock().unwrap();

                loc.replace(Some(location.to_string()));
                eprintln!("AddSmartcardKey <- {}", location);

                let public = std::sync::Arc::clone(&self.public);
                let public = public.lock().unwrap();

                public.replace(Some(format!("{}/public", key.id)));

                Ok(Message::Success)
            }
            Message::SignRequest(request) => {
                let body = request.data;
                const SSH_AGENT_RSA_SHA2_256: u32 = 2;
                const SSH_AGENT_RSA_SHA2_512: u32 = 4;
                let content_type = if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                    "application/vnd.pks.digest.sha256"
                } else if request.flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                    "application/vnd.pks.digest.sha512"
                } else {
                    "application/octet-stream"
                };

                let location = {
                    let loc = std::sync::Arc::clone(&self.loc);
                    let loc = loc.lock().unwrap();
                    let loc = loc.borrow();
                    if let Some(loc) = &*loc {
                        loc.to_string()
                    } else {
                        return Ok(Message::Failure);
                    }
                };

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();

                let location: hyper::Uri = location.parse().unwrap();
                let client = Client::unix();

                let request = Request::builder()
                    .method("POST")
                    .uri(location)
                    .header("Content-Type", content_type)
                    .body(Body::from(body))
                    .unwrap();
                let response = rt.block_on(client.request(request)).unwrap();

                if !response.status().is_success() {
                    return Err(BackendError::Unknown("badbad".to_string()));
                }

                let response_type = response
                    .headers()
                    .get("Content-Type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let signature = rt
                    .block_on(hyper::body::to_bytes(response))
                    .unwrap()
                    .to_vec();

                //let signature = vec![];
                eprintln!("SIG: {:?} ({})", signature, signature.len());
                let algorithm = if response_type == "application/vnd.pks.signature.rsa" {
                    if content_type == "application/vnd.pks.digest.sha256" {
                        "rsa-sha2-256"
                    } else {
                        "rsa-sha2-512"
                    }
                } else {
                    "ssh-ed25519"
                };

                Ok(Message::SignResponse(
                    (ssh_agent_lib::proto::signature::Signature {
                        algorithm: algorithm.to_string(),
                        blob: signature,
                    })
                    .to_blob()
                    .unwrap(),
                ))
            }
            _ => Ok(Message::Failure),
        }
    }
}

#[derive(Debug)]
pub enum BackendError {
    Unknown(String),
}

use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short = 'H', long)]
    host: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    use service_listener::Service;

    let service: Service = args.host.parse().unwrap();

    match service {
        Service::UnixListener(listener) => {
            let handle = tokio_reactor::Handle::default();
            let listener = tokio_uds::UnixListener::from_std(listener, &handle)?;

            let agent = Backend::default();
            match agent.run_listener(listener) {
                Err(e) => eprintln!("fn=main listener=OK at=bind err={:?}", e),
                Ok(_) => eprintln!("Listening done!"),
            }
        }
        _ => {
            panic!("Unsupported configuration.");
        }
    }
    Ok(())
}
