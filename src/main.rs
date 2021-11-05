use ssh_agent::agent::Agent;
use std::{fs, path::Path};

use ssh_agent::proto::Blob;
use ssh_agent::proto::{message::Identity, Message};

use hyper::{Body, Client, Request};
use hyper_tls::HttpsConnector;

struct Backend {
    loc: std::sync::Arc<std::sync::Mutex<std::cell::RefCell<Option<String>>>>,
}

impl ssh_agent::agent::Agent for Backend {
    type Error = BackendError;

    fn handle(&self, request: Message) -> Result<Message, Self::Error> {
        eprintln!("-> {:X?}", request);
        let key = openssh_keys::PublicKey::parse("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHCXBJYlPPkrt2WYyP3SZoMx43lDBB5QALjE762EQlc openpgp:0x0529CE0A").unwrap();
        eprintln!("LEM = {}", key.data().len());
        eprintln!("Key = {:X?}", key.data());
        //let data = base64::decode("AAAAC3NzaC1lZDI1NTE5AAAAIPXlzC83a2MfZUYIY/J+Qymr7x4n29Wwix9KW0dl1Yl6").unwrap(); // sig key
        let data =
            base64::decode("AAAAC3NzaC1lZDI1NTE5AAAAILHCXBJYlPPkrt2WYyP3SZoMx43lDBB5QALjE762EQlc")
                .unwrap(); // auth key
        match request {
            Message::RequestIdentities => Ok(Message::IdentitiesAnswer(vec![Identity {
                pubkey_blob: data,
                comment: "".to_string(),
            }])),
	    Message::AddSmartcardKey(key) => {
		eprintln!("KEY => {:?}", key);
		let id = key.id;
		let pin = key.pin;

                let location = id;

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();

                let client = Client::builder().build(HttpsConnector::new());

                let request = Request::builder()
                    .method("POST")
                    .uri(location)
                    .body(Body::from(pin))
                    .unwrap();
                let response = rt.block_on(client.request(request)).unwrap();

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

		Ok(Message::Success)
	    },
            Message::SignRequest(request) => {
                let body = request.data;
		
		let loc = std::sync::Arc::clone(&self.loc);
		let loc = loc.lock().unwrap();
		let loc = loc.borrow();
		let location = if let Some(loc) = &*loc {
		    loc.to_string()
		} else {
		    return Ok(Message::Failure);
		};

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();

                let client = Client::builder().build(HttpsConnector::new());

                let request = Request::builder()
                    .method("POST")
                    .uri(location)
                    .body(Body::from(body))
                    .unwrap();
                let response = rt.block_on(client.request(request)).unwrap();

                if !response.status().is_success() {
                    return Err(BackendError::Unknown("badbad".to_string()));
                }

                let signature = rt
                    .block_on(hyper::body::to_bytes(response))
                    .unwrap()
                    .to_vec();

                //let signature = vec![];
                eprintln!("SIG: {:?} ({})", signature, signature.len());

                Ok(Message::SignResponse(
                    (ssh_agent::proto::signature::Signature {
                        algorithm: "ssh-ed25519".to_string(),
                        blob: signature,
                    })
                    .to_blob()
                    .unwrap(),
                ))
            }
            _ => Err(BackendError::Unknown("bad".to_string())),
        }
    }
}

#[derive(Debug)]
pub enum BackendError {
    Unknown(String),
}

fn main() {
    let pipe = "/tmp/pks-ssh-agent";
    let pipe = Path::new(pipe);

    if fs::metadata(&pipe).is_ok() {
        if let Ok(_) = fs::remove_file(&pipe) {
            println!("fn=main pipe={} at=deleted", pipe.display());
        }
    }

    eprintln!("fn=main pipe={} at=bind", pipe.display());

    let agent = Backend { loc:
			  std::sync::Arc::new(
			      std::sync::Mutex::new(
				  std::cell::RefCell::new(None)
				      ))
    };
    match agent.run_unix(&pipe) {
        Err(e) => eprintln!("fn=main pipe={} at=bind err={:?}", pipe.display(), e),
        Ok(_) => {}
    }

    eprintln!("fn=main pipe={} at=finished", pipe.display());
}
