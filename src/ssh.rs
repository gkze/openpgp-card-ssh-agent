// SPDX-FileCopyrightText: 2021-2024 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: 2022-2024 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use openpgp_card::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::crypto_data::{EccType, PublicKeyMaterial};
use ssh_agent_lib::proto::SignRequest;

pub(crate) fn get_ssh_pubkey(
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

pub(crate) fn signature_request_information(
    request: &SignRequest,
    pkm: &PublicKeyMaterial,
) -> Option<(&'static str, Vec<u8>)> {
    use sha2::Digest;

    // Signature scheme "rsa-sha2-256" or "rsa-sha2-512" [I-D.ietf-curdle-rsa-sha2]
    const SSH_AGENT_RSA_SHA2_256: u32 = 2;
    const SSH_AGENT_RSA_SHA2_512: u32 = 4;

    match pkm {
        PublicKeyMaterial::R(_) => {
            if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                let mut hasher = sha2::Sha256::new();
                hasher.update(&request.data);
                Some(("rsa-sha2-256", hasher.finalize().to_vec()))
            } else if request.flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                let mut hasher = sha2::Sha512::new();
                hasher.update(&request.data);
                Some(("rsa-sha2-512", hasher.finalize().to_vec()))
            } else {
                log::error!("Unexpected RSA case");
                return None;
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
                                log::error!("Unexpected ECDSA curve {:?}", curve);
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
