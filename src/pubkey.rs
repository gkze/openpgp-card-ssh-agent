use openpgp_card::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::crypto_data::{EccType, PublicKeyMaterial};

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
