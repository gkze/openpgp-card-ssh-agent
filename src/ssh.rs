// SPDX-FileCopyrightText: 2021-2024 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko.schaefer@posteo.de>
// SPDX-License-Identifier: MIT OR Apache-2.0

use openpgp_card::ocard::{
    algorithm::{AlgorithmAttributes, Curve},
    crypto::{EccType, PublicKeyMaterial},
};
use ssh_agent_lib::proto::SignRequest;
use ssh_key::{
    Mpint,
    public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey},
    sec1::EncodedPoint,
};

pub(crate) fn get_ssh_pubkey(
    pkm: &PublicKeyMaterial,
) -> Result<KeyData, Box<dyn std::error::Error>> {
    match pkm {
        PublicKeyMaterial::R(rsa) => {
            let e = Mpint::from_positive_bytes(rsa.v())?;
            let n = Mpint::from_positive_bytes(rsa.n())?;

            Ok(KeyData::Rsa(RsaPublicKey { e, n }))
        }
        PublicKeyMaterial::E(ecc) => {
            if let AlgorithmAttributes::Ecc(ecc_attrs) = ecc.algo() {
                match ecc_attrs.ecc_type() {
                    EccType::EdDSA => {
                        let key = ecc.data().to_vec();

                        Ok(KeyData::Ed25519(Ed25519PublicKey(
                            key.try_into().map_err(|_e| anyhow::anyhow!("bad length"))?,
                        )))
                    }
                    EccType::ECDSA => {
                        if let AlgorithmAttributes::Ecc(ecc_attrs) = ecc.algo() {
                            Ok(KeyData::Ecdsa(match ecc_attrs.curve() {
                                Curve::NistP256r1 => {
                                    EcdsaPublicKey::NistP256(EncodedPoint::from_bytes(ecc.data())?)
                                }
                                Curve::NistP384r1 => {
                                    EcdsaPublicKey::NistP384(EncodedPoint::from_bytes(ecc.data())?)
                                }
                                Curve::NistP521r1 => {
                                    EcdsaPublicKey::NistP521(EncodedPoint::from_bytes(ecc.data())?)
                                }
                                _ => {
                                    return Err(anyhow::anyhow!(
                                        "Unsupported ECDSA curve {:?}",
                                        ecc_attrs.curve()
                                    )
                                    .into());
                                }
                            }))
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
    }
}

pub(crate) fn signature_request_information(
    request: &SignRequest,
    pkm: &PublicKeyMaterial,
) -> Option<(ssh_key::Algorithm, Vec<u8>)> {
    use sha2::Digest;

    // Signature scheme "rsa-sha2-256" or "rsa-sha2-512" [I-D.ietf-curdle-rsa-sha2]
    const SSH_AGENT_RSA_SHA2_256: u32 = 2;
    const SSH_AGENT_RSA_SHA2_512: u32 = 4;

    match pkm {
        PublicKeyMaterial::R(_) => {
            if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                let mut hasher = sha2::Sha256::new();
                hasher.update(&request.data);
                Some((
                    ssh_key::Algorithm::Rsa {
                        hash: Some(ssh_key::HashAlg::Sha256),
                    },
                    hasher.finalize().to_vec(),
                ))
            } else if request.flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                let mut hasher = sha2::Sha512::new();
                hasher.update(&request.data);
                Some((
                    ssh_key::Algorithm::Rsa {
                        hash: Some(ssh_key::HashAlg::Sha512),
                    },
                    hasher.finalize().to_vec(),
                ))
            } else {
                log::error!("Unexpected RSA case");
                None
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

                                Some((
                                    ssh_key::Algorithm::Ecdsa {
                                        curve: ssh_key::EcdsaCurve::NistP256,
                                    },
                                    digest,
                                ))
                            }
                            Curve::NistP384r1 => {
                                let mut hasher = sha2::Sha384::new();
                                hasher.update(&request.data);
                                let digest = hasher.finalize().to_vec();

                                Some((
                                    ssh_key::Algorithm::Ecdsa {
                                        curve: ssh_key::EcdsaCurve::NistP384,
                                    },
                                    digest,
                                ))
                            }
                            Curve::NistP521r1 => {
                                let mut hasher = sha2::Sha512::new();
                                hasher.update(&request.data);
                                let digest = hasher.finalize().to_vec();

                                Some((
                                    ssh_key::Algorithm::Ecdsa {
                                        curve: ssh_key::EcdsaCurve::NistP521,
                                    },
                                    digest,
                                ))
                            }
                            _ => {
                                log::error!("Unexpected ECDSA curve {:?}", curve);
                                None
                            }
                        }
                    }
                    EccType::EdDSA => {
                        let curve = ea.curve();
                        if curve != &Curve::Ed25519 {
                            log::error!("Unsupported EdDSA curve {:?}", curve);
                            return None;
                        }

                        // raw message to be hashed and signed, ed25519
                        Some((ssh_key::Algorithm::Ed25519, request.data.clone()))
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v_leading_zero_not_influencing_key_equality() {
        let v = [1, 0, 1];
        let n = [1, 2, 3, 4];
        let e = Mpint::from_positive_bytes(&v).expect("v");
        let n = Mpint::from_positive_bytes(&n).expect("n");

        let first_key = KeyData::Rsa(RsaPublicKey { e, n });

        // additional zero in "v"/"e" should not affect the result
        let v = [0, 1, 0, 1];
        let n = [1, 2, 3, 4];
        let e = Mpint::from_positive_bytes(&v).expect("v");
        let n = Mpint::from_positive_bytes(&n).expect("n");

        let second_key = KeyData::Rsa(RsaPublicKey { e, n });

        assert_eq!(first_key, second_key);
    }
}
