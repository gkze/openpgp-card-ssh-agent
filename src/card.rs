// SPDX-FileCopyrightText: 2022-2024 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use card_backend_pcsc::PcscBackend;
use openpgp_card::crypto_data::PublicKeyMaterial;
use openpgp_card::{Card, KeyType};
use ssh_agent_lib::proto::Identity;

use crate::ssh::get_ssh_pubkey;

/// Enumerate the ssh identities of all plugged in OpenPGP card AUTH slots
pub(crate) fn list_ssh_identities() -> Result<Vec<Identity>, Box<dyn std::error::Error>> {
    let backends = PcscBackend::cards(None)?;

    let mut ids = vec![];

    for b in backends.filter_map(|c| c.ok()) {
        let mut card = Card::new(b)?;
        let mut tx = card.transaction()?;

        if let Ok(pubkey) = tx.public_key(KeyType::Authentication) {
            if let Ok(ssh) = get_ssh_pubkey(&pubkey) {
                let id = Identity {
                    pubkey_blob: ssh.data(),
                    comment: "".to_string(),
                };

                ids.push(id);
            }
        }
    }

    Ok(ids)
}

pub(crate) fn card_by_ssh_blob(blob: &[u8]) -> Option<(Card, PublicKeyMaterial)> {
    let Ok(backends) = PcscBackend::cards(None) else {
        return None;
    };

    for b in backends.filter_map(|c| c.ok()) {
        if let Ok(mut card) = Card::new(b) {
            // signals that this is the right card
            let mut pkm = None;

            {
                if let Ok(mut tx) = card.transaction() {
                    if let Ok(pubkey) = tx.public_key(KeyType::Authentication) {
                        if let Ok(ssh) = get_ssh_pubkey(&pubkey) {
                            if ssh.data() == blob {
                                pkm = Some(pubkey);
                            }
                        }
                    }
                }
            }

            if let Some(pkm) = pkm {
                return Some((card, pkm));
            }
        }
    }

    None
}
