// SPDX-FileCopyrightText: 2022-2024 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::crypto::PublicKeyMaterial;
use openpgp_card::ocard::{KeyType, OpenPGP};
use ssh_agent_lib::proto::Identity;

use crate::ssh::get_ssh_pubkey;

/// Enumerate the ssh identities of all plugged in OpenPGP card AUTH slots
pub(crate) fn list_ssh_identities() -> Result<Vec<Identity>, Box<dyn std::error::Error>> {
    let backends = PcscBackend::cards(None)?;

    let mut ids = vec![];

    for b in backends.filter_map(|c| c.ok()) {
        let mut card = OpenPGP::new(b)?;
        let mut tx = card.transaction()?;

        if let Ok(pubkey) = tx.public_key(KeyType::Authentication) {
            if let Ok(ssh) = get_ssh_pubkey(&pubkey) {
                let id = Identity {
                    pubkey: ssh,
                    comment: tx
                        .application_identifier()
                        .map(|aid| aid.ident())
                        .unwrap_or("Unknown card".to_string()),
                };

                ids.push(id);
            }
        }
    }

    Ok(ids)
}

// FIXME: replace with a filter function, so main can directly iterate over cards.
// Main shouldn't need to re-open a transaction.
pub(crate) fn card_by_ssh_blob(
    blob: &ssh_key::public::KeyData,
) -> Option<(OpenPGP, PublicKeyMaterial)> {
    let Ok(backends) = PcscBackend::cards(None) else {
        return None;
    };

    for b in backends.filter_map(|c| c.ok()) {
        if let Ok(mut card) = OpenPGP::new(b) {
            // signals that this is the right card
            let mut pkm = None;

            {
                if let Ok(mut tx) = card.transaction() {
                    if let Ok(pubkey) = tx.public_key(KeyType::Authentication) {
                        if let Ok(ssh) = get_ssh_pubkey(&pubkey) {
                            log::debug!(
                                "card_by_ssh_blob: requested blob {:02x?}, found on card {:02x?}",
                                blob,
                                &ssh
                            );

                            if &ssh == blob {
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

// FIXME: replace with a filter function, so main can directly iterate over cards.
// Main shouldn't need to re-open a transaction.
pub(crate) fn card_by_ident(ident: &str) -> Result<OpenPGP, openpgp_card::Error> {
    let backends = PcscBackend::cards(None)?;

    for b in backends.filter_map(|c| c.ok()) {
        let mut card = OpenPGP::new(b)?;

        let aid = {
            let mut tx = card.transaction()?;
            tx.application_related_data()?
        };

        if aid.application_id()?.ident() == ident.to_ascii_uppercase() {
            return Ok(card);
        }
    }

    Err(openpgp_card::Error::NotFound(format!(
        "Couldn't open card '{}'",
        ident
    )))
}
