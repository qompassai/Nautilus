use anyhow::Result;
use std::convert::TryFrom;

use crate::openpgp::{
    cert::prelude::*,
    packet::{Packet, PacketPile, Signature},
    policy::{Policy, StandardPolicy},
    serialize::SerializeInto,
    types::{HashAlgorithm, KeyFlags, RevocationStatus, SignatureType},
    Cert,
};

use crate::types::Email;

lazy_static::lazy_static! {
    pub static ref POLICY: StandardPolicy = StandardPolicy::new();
}

pub fn is_status_revoked(status: RevocationStatus) -> bool {
    match status {
        RevocationStatus::Revoked(_) => true,
        RevocationStatus::CouldBe(_) => false,
        RevocationStatus::NotAsFarAsWeKnow => false,
    }
}

pub fn tpk_to_string(tpk: &Cert) -> Result<Vec<u8>> {
    tpk.armored().export_to_vec().map_err(Into::into)
}

pub fn tpk_clean(tpk: &Cert) -> Result<Cert> {
    // Iterate over the Cert, pushing packets we want to merge
    // into the accumulator.
    let mut acc = Vec::new();

    // The primary key and related signatures.
    let pk_bundle = tpk.primary_key().bundle();
    acc.push(pk_bundle.key().clone().into());
    for s in pk_bundle.self_signatures() {
        acc.push(s.clone().into())
    }
    for s in pk_bundle.self_revocations() {
        acc.push(s.clone().into())
    }
    for s in pk_bundle.other_revocations() {
        acc.push(s.clone().into())
    }

    // The subkeys and related signatures.
    for skb in tpk.keys().subkeys() {
        acc.push(skb.key().clone().into());
        for s in skb.self_signatures() {
            acc.push(s.clone().into())
        }
        for s in skb.self_revocations() {
            acc.push(s.clone().into())
        }
        for s in skb.other_revocations() {
            acc.push(s.clone().into())
        }
    }

    // The UserIDs.
    for uidb in tpk.userids() {
        acc.push(uidb.userid().clone().into());
        for s in uidb.self_signatures() {
            acc.push(s.clone().into())
        }
        for s in uidb.self_revocations() {
            acc.push(s.clone().into())
        }
        for s in uidb.other_revocations() {
            acc.push(s.clone().into())
        }

        // Reasoning about the currently attested certifications
        // requires a policy.
        if let Ok(vuid) = uidb.with_policy(&POLICY, None) {
            for s in vuid.attestation_key_signatures() {
                acc.push(s.clone().into());
            }
            for s in vuid.attested_certifications() {
                acc.push(s.clone().into());
            }
        }
    }

    Cert::from_packets(acc.into_iter()).map_err(Into::into)
}

/// Filters the Cert, keeping only UserIDs that aren't revoked, and whose emails match the given list
pub fn tpk_filter_alive_emails(tpk: &Cert, emails: &[Email]) -> Cert {
    tpk.clone().retain_userids(|uid| {
        if is_status_revoked(uid.revocation_status(&POLICY, None)) {
            false
        } else if let Ok(email) = Email::try_from(uid.userid()) {
            emails.contains(&email)
        } else {
            false
        }
    })
}

