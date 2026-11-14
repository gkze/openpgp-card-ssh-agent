// SPDX-FileCopyrightText: Heiko Schaefer <heiko.schaefer@posteo.de>
// SPDX-License-Identifier: MIT OR Apache-2.0

use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::{KeyType, OpenPGP, Transaction, crypto::PublicKeyMaterial};
use ssh_agent_lib::proto::Identity;

use crate::ssh::get_ssh_pubkey;

/// Enumerate the ssh identities of all plugged in OpenPGP card AUTH slots
pub(crate) fn list_ssh_identities() -> Result<Vec<Identity>, Box<dyn std::error::Error>> {
    let backends = PcscBackend::cards(None)?;

    let mut ids = vec![];

    for b in backends.filter_map(|c| c.ok()) {
        // Skip cards without an OpenPGP card application (e.g. PKCS#15 cards)
        let Ok(mut card) = OpenPGP::new(b).inspect_err(|e| {
            log::debug!("list_ssh_identities: skipping card that failed to open: {e}")
        }) else {
            continue;
        };
        let Ok(mut tx) = card.transaction() else {
            continue;
        };

        if let Ok(pubkey) = tx.public_key(KeyType::Authentication)
            && let Ok(ssh) = get_ssh_pubkey(&pubkey)
        {
            let id = Identity {
                credential: ssh.into(),
                comment: tx
                    .application_identifier()
                    .map(|aid| aid.ident())
                    .unwrap_or("Unknown card".to_string()),
            };

            ids.push(id);
        }
    }

    Ok(ids)
}

// Return the AUT `PublicKeyMaterial` of the card `tx` if the key material matches with `blob`
pub(crate) fn match_ssh_blob(
    tx: &mut Transaction,
    blob: &ssh_key::public::KeyData,
) -> Option<PublicKeyMaterial> {
    if let Ok(pkm) = tx.public_key(KeyType::Authentication)
        && let Ok(ssh) = get_ssh_pubkey(&pkm)
    {
        log::debug!(
            "match_ssh_blob: searching blob {:02x?}, found on card {:02x?}",
            blob,
            ssh
        );

        if &ssh == blob {
            return Some(pkm);
        }
    }

    None
}

// FIXME: replace with a filter function, so main can directly iterate over cards.
// Main shouldn't need to re-open a transaction.
pub(crate) fn card_by_ident(ident: &str) -> Result<OpenPGP, openpgp_card::Error> {
    let backends = PcscBackend::cards(None)?;

    for b in backends.filter_map(|c| c.ok()) {
        // Skip cards without an OpenPGP card application (e.g. PKCS#15 cards)
        let Ok(mut card) = OpenPGP::new(b)
            .inspect_err(|e| log::debug!("card_by_ident: skipping card that failed to open: {e}"))
        else {
            continue;
        };

        let Ok(aid) = card
            .transaction()
            .and_then(|mut tx| tx.application_related_data())
            .and_then(|ard| ard.application_id())
        else {
            continue;
        };

        if aid.ident() == ident.to_ascii_uppercase() {
            return Ok(card);
        }
    }

    Err(openpgp_card::Error::NotFound(format!(
        "Couldn't open card '{}'",
        ident
    )))
}
