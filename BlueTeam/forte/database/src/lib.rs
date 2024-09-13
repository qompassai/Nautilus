#![recursion_limit = "1024"]

use std::convert::TryFrom;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use chrono::Utc;
use log::{error, info};
pub use sequoia_openpgp as openpgp; // Re-export for other modules

use openpgp::serialize::SerializeInto;
use openpgp::{packet::UserID, parse::Parse, types::KeyFlags, Cert};

pub mod types;
use crate::types::{Email, Fingerprint, KeyID};

pub mod sync;
pub mod wkd;

pub mod fs;
pub use crate::fs::Filesystem as KeyDatabase;

mod stateful_tokens;
pub use crate::stateful_tokens::StatefulTokens;

mod openpgp_utils;
use crate::openpgp_utils::{
    is_status_revoked, tpk_clean, tpk_filter_alive_emails, tpk_to_string, POLICY,
};

#[cfg(test)]
mod test;

/// Represents a search query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    ByFingerprint(Fingerprint),
    ByKeyID(KeyID),
    ByEmail(Email),
    InvalidShort(),
    Invalid(),
}

impl Query {
    pub fn is_invalid(&self) -> bool {
        matches!(self, Query::Invalid() | Query::InvalidShort())
    }
}

impl FromStr for Query {
    type Err = anyhow::Error;

    fn from_str(term: &str) -> Result<Self, Self::Err> {
        use self::Query::*;

        let looks_like_short_key_id = !term.contains('@')
            && ((term.starts_with("0x") && term.len() < 16) || term.len() == 8);
        if looks_like_short_key_id {
            Ok(InvalidShort())
        } else if let Ok(fp) = Fingerprint::from_str(term) {
            Ok(ByFingerprint(fp))
        } else if let Ok(keyid) = KeyID::from_str(term) {
            Ok(ByKeyID(keyid))
        } else if let Ok(email) = Email::from_str(term) {
            Ok(ByEmail(email))
        } else {
            Ok(Invalid())
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EmailAddressStatus {
    Published,
    NotPublished,
    Revoked,
}

pub enum ImportResult {
    New(TpkStatus),
    Updated(TpkStatus),
    Unchanged(TpkStatus),
}

impl ImportResult {
    pub fn into_tpk_status(self) -> TpkStatus {
        match self {
            ImportResult::New(status) => status,
            ImportResult::Updated(status) => status,
            ImportResult::Unchanged(status) => status,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct TpkStatus {
    pub is_revoked: bool,
    pub email_status: Vec<(Email, EmailAddressStatus)>,
    pub unparsed_uids: usize,
}

pub enum RegenerateResult {
    Updated,
    Unchanged,
}

pub trait Database: Sync + Send {
    type MutexGuard;
    type TempCert;

    /// Lock the DB for a complex update.
    ///
    /// All basic write operations are atomic so we don't need to lock
    /// read operations to ensure that we return something sane.
    fn lock(&self) -> Result<Self::MutexGuard>;

    /// Queries the database using Fingerprint, KeyID, or
    /// email-address, returning the primary fingerprint.
    fn lookup_primary_fingerprint(&self, term: &Query) -> Option<Fingerprint>;

    fn link_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()>;
    fn unlink_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()>;

    fn link_fpr(&self, from: &Fingerprint, to: &Fingerprint) -> Result<()>;
    fn unlink_fpr(&self, from: &Fingerprint, to: &Fingerprint) -> Result<()>;

    fn by_fpr(&self, fpr: &Fingerprint) -> Option<String>;
    fn by_kid(&self, kid: &KeyID) -> Option<String>;
    fn by_email(&self, email: &Email) -> Option<String>;
    fn by_email_wkd(&self, email: &Email) -> Option<Vec<u8>>;
    fn by_domain_and_hash_wkd(&self, domain: &str, hash: &str) -> Option<Vec<u8>>;

    fn check_link_fpr(
        &self,
        fpr: &Fingerprint,
        target: &Fingerprint,
    ) -> Result<Option<Fingerprint>>;

    fn by_fpr_full(&self, fpr: &Fingerprint) -> Option<String>;
    fn by_primary_fpr(&self, fpr: &Fingerprint) -> Option<String>;

    fn write_to_temp(&self, content: &[u8]) -> Result<Self::TempCert>;
    fn move_tmp_to_full(&self, content: Self::TempCert, fpr: &Fingerprint) -> Result<()>;
    fn move_tmp_to_published(&self, content: Self::TempCert, fpr: &Fingerprint) -> Result<()>;
    fn move_tmp_to_published_wkd(
        &self,
        content: Option<Self::TempCert>,
        fpr: &Fingerprint,
    ) -> Result<()>;
    fn write_to_quarantine(&self, fpr: &Fingerprint, content: &[u8]) -> Result<()>;
    fn write_log_append(&self, filename: &str, fpr_primary: &Fingerprint) -> Result<()>;

    fn check_consistency(&self) -> Result<()>;

    /// Queries the database using Fingerprint, KeyID, or
    /// email-address.
    fn lookup(&self, term: &Query) -> Result<Option<Cert>> {
        use self::Query::*;
        let armored = match term {
            ByFingerprint(ref fp) => self.by_fpr(fp),
            ByKeyID(ref keyid) => self.by_kid(keyid),
            ByEmail(ref email) => self.by_email(email),
            _ => None,
        };

        match armored {
            Some(armored) => Ok(Some(Cert::from_bytes(armored.as_bytes())?)),
            None => Ok(None),
        }
    }

    /// Complex operation that updates a Cert in the database.
    ///
    /// 1. Merge new Cert with old, full Cert
    ///    - if old full Cert == new full Cert, stop
    /// 2. Prepare new published Cert
    ///    - retrieve UserIDs from old published Cert
    ///    - create new Cert from full Cert by keeping only published UserIDs
    /// 3. Write full and published Cert to temporary files
    /// 4. Check for fingerprint and long key id collisions for published Cert
    ///    - abort if any problems come up!
    /// 5. Move full and published temporary Cert to their location
    /// 6. Update all symlinks
    fn merge(&self, new_tpk: Cert) -> Result<ImportResult> {
        let fpr_primary = Fingerprint::try_from(new_tpk.primary_key().fingerprint())?;

        let _lock = self.lock()?;

        let known_uids: Vec<UserID> = new_tpk
            .userids()
            .map(|binding| binding.userid().clone())
            .collect();

        let full_tpk_old = self
            .by_fpr_full(&fpr_primary)
            .and_then(|bytes| Cert::from_bytes(bytes.as_bytes()).ok());
        let is_update = full_tpk_old.is_some();
        let (full_tpk_new, full_tpk_unchanged) = if let Some(full_tpk_old) = full_tpk_old {
            let full_tpk_new = new_tpk.merge_public(full_tpk_old.clone())?;
            let full_tpk_unchanged = full_tpk_new == full_tpk_old;
            (full_tpk_new, full_tpk_unchanged)
        } else {
            (new_tpk, false)
        };

        let is_revoked = is_status_revoked(full_tpk_new.revocation_status(&POLICY, None));

        let is_ok = is_revoked
            || full_tpk_new.keys().subkeys().next().is_some()
            || full_tpk_new.userids().next().is_some();
        if !is_ok {
            // self.write_to_quarantine(&fpr_primary, &tpk_to_string(&full_tpk_new)?)?;
            return Err(anyhow!("Not a well-formed key!"));
        }

        let published_tpk_old = self
            .by_fpr(&fpr_primary)
            .and_then(|bytes| Cert::from_bytes(bytes.as_bytes()).ok());
        let published_emails = published_tpk_old
            .as_ref()
            .map(tpk_get_emails)
            .unwrap_or_default();

        let unparsed_uids = full_tpk_new
            .userids()
            .map(|binding| Email::try_from(binding.userid()).is_err())
            .filter(|x| *x)
            .count();

        let mut email_status: Vec<_> = full_tpk_new
            .userids()
            .map(|binding| {
                if let Ok(email) = Email::try_from(binding.userid()) {
                    Some((binding, email))
                } else {
                    None
                }
            })
            .flatten()
            .filter(|(binding, email)| {
                known_uids.contains(binding.userid()) || published_emails.contains(email)
            })
            .flat_map(|(binding, email)| {
                if is_status_revoked(binding.revocation_status(&POLICY, None)) {
                    Some((email, EmailAddressStatus::Revoked))
                } else if !is_revoked && published_emails.contains(&email) {
                    Some((email, EmailAddressStatus::Published))
                } else {
                    Some((email, EmailAddressStatus::NotPublished))
                }
            })
            .collect();
        email_status.sort();
        // EmailAddressStatus is ordered published, unpublished, revoked. if there are multiple for
        // the same address, we keep the first.
        email_status.dedup_by(|(e1, _), (e2, _)| e1 == e2);

        // Abort if no changes were made
        if full_tpk_unchanged {
            return Ok(ImportResult::Unchanged(TpkStatus {
                is_revoked,
                email_status,
                unparsed_uids,
            }));
        }

        let published_tpk_new = if is_revoked {
            tpk_filter_alive_emails(&full_tpk_new, &[])
        } else {
            tpk_filter_alive_emails(&full_tpk_new, &published_emails)
        };

        let newly_revoked_emails: Vec<&Email> = published_emails
            .iter()
            .filter(|email| {
                let has_unrevoked_userid = published_tpk_new
                    .userids()
                    .filter(|binding| !is_status_revoked(binding.revocation_status(&POLICY, None)))
                    .map(|binding| binding.userid())
                    .map(|uid| Email::try_from(uid).ok())
                    .flatten()
                    .any(|unrevoked_email| &unrevoked_email == *email);
                !has_unrevoked_userid
            })
            .collect();

        let fingerprints = tpk_get_linkable_fprs(&published_tpk_new);

        let fpr_checks = fingerprints
            .iter()
            .map(|fpr| self.check_link_fpr(fpr, &fpr_primary))
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>>>();

        if fpr_checks.is_err() {
            self.write_to_quarantine(&fpr_primary, &tpk_to_string(&full_tpk_new)?)?;
        }
        let fpr_checks = fpr_checks?;

        let fpr_not_linked = fpr_checks.into_iter().flatten();

        let full_tpk_tmp = self.write_to_temp(&tpk_to_string(&full_tpk_new)?)?;
        let published_tpk_clean = tpk_clean(&published_tpk_new)?;
        let published_tpk_tmp = self.write_to_temp(&tpk_to_string(&published_tpk_clean)?)?;

        // these are very unlikely to fail. but if it happens,
        // database consistency might be compromised!
        self.move_tmp_to_full(full_tpk_tmp, &fpr_primary)?;
        self.move_tmp_to_published(published_tpk_tmp, &fpr_primary)?;
        self.regenerate_wkd(&fpr_primary, &published_tpk_clean)?;

        let published_tpk_changed = published_tpk_old
            .map(|tpk| tpk != published_tpk_clean)
            .unwrap_or(true);
        if published_tpk_changed {
            self.update_write_log(&fpr_primary);
        }

        for fpr in fpr_not_linked {
            if let Err(e) = self.link_fpr(&fpr, &fpr_primary) {
                info!("Error ensuring symlink! {} {} {:?}", &fpr, &fpr_primary, e);
            }
        }

        for revoked_email in newly_revoked_emails {
            if let Err(e) = self.unlink_email(revoked_email, &fpr_primary) {
                info!(
                    "Error ensuring symlink! {} {} {:?}",
                    &fpr_primary, &revoked_email, e
                );
            }
        }

        if is_update {
            Ok(ImportResult::Updated(TpkStatus {
                is_revoked,
                email_status,
                unparsed_uids,
            }))
        } else {
            Ok(ImportResult::New(TpkStatus {
                is_revoked,
                email_status,
                unparsed_uids,
            }))
        }
    }

    fn update_write_log(&self, fpr_primary: &Fingerprint) {
        let log_name = self.get_current_log_filename();
        println!("{}", log_name);
        if let Err(e) = self.write_log_append(&log_name, fpr_primary) {
            error!("Error writing to log! {} {} {}", &log_name, &fpr_primary, e);
        }
    }

    fn get_current_log_filename(&self) -> String {
        Utc::now().format("%Y-%m-%d").to_string()
    }

    fn get_tpk_status(
        &self,
        fpr_primary: &Fingerprint,
        known_addresses: &[Email],
    ) -> Result<TpkStatus> {
        let tpk_full = self
            .by_fpr_full(fpr_primary)
            .ok_or_else(|| anyhow!("Key not in database!"))
            .and_then(|bytes| Cert::from_bytes(bytes.as_bytes()))?;

        let is_revoked = is_status_revoked(tpk_full.revocation_status(&POLICY, None));

        let unparsed_uids = tpk_full
            .userids()
            .map(|binding| Email::try_from(binding.userid()).is_err())
            .filter(|x| *x)
            .count();

        let published_uids: Vec<UserID> = self
            .by_fpr(fpr_primary)
            .and_then(|bytes| Cert::from_bytes(bytes.as_bytes()).ok())
            .map(|tpk| {
                tpk.userids()
                    .map(|binding| binding.userid().clone())
                    .collect()
            })
            .unwrap_or_default();

        let mut email_status: Vec<_> = tpk_full
            .userids()
            .flat_map(|binding| {
                let uid = binding.userid();
                if let Ok(email) = Email::try_from(uid) {
                    if !known_addresses.contains(&email) {
                        None
                    } else if is_status_revoked(binding.revocation_status(&POLICY, None)) {
                        Some((email, EmailAddressStatus::Revoked))
                    } else if published_uids.contains(uid) {
                        Some((email, EmailAddressStatus::Published))
                    } else {
                        Some((email, EmailAddressStatus::NotPublished))
                    }
                } else {
                    None
                }
            })
            .collect();
        email_status.sort();
        // EmailAddressStatus is ordered published, unpublished, revoked. if there are multiple for
        // the same address, we keep the first.
        email_status.dedup_by(|(e1, _), (e2, _)| e1 == e2);

        Ok(TpkStatus {
            is_revoked,
            email_status,
            unparsed_uids,
        })
    }

    /// Complex operation that publishes some user id for a Cert already in the database.
    ///
    /// 1. Load published Cert
    ///     - if UserID is already in, stop
    /// 2. Load full Cert
    ///     - if requested UserID is not in, stop
    /// 3. Prepare new published Cert
    ///    - retrieve UserIDs from old published Cert
    ///    - create new Cert from full Cert by keeping only published UserIDs
    /// 4. Check for fingerprint and long key id collisions for published Cert
    ///    - abort if any problems come up!
    /// 5. Move full and published temporary Cert to their location
    /// 6. Update all symlinks
    fn set_email_published(&self, fpr_primary: &Fingerprint, email_new: &Email) -> Result<()> {
        let _lock = self.lock()?;

        self.nolock_unlink_email_if_other(fpr_primary, email_new)?;

        let full_tpk = self
            .by_fpr_full(fpr_primary)
            .ok_or_else(|| anyhow!("Key not in database!"))
            .and_then(|bytes| Cert::from_bytes(bytes.as_bytes()))?;

        let published_uids_old: Vec<UserID> = self
            .by_fpr(fpr_primary)
            .and_then(|bytes| Cert::from_bytes(bytes.as_bytes()).ok())
            .map(|tpk| {
                tpk.userids()
                    .map(|binding| binding.userid().clone())
                    .collect()
            })
            .unwrap_or_default();
        let published_emails_old: Vec<Email> = published_uids_old
            .iter()
            .map(|uid| Email::try_from(uid).ok())
            .flatten()
            .collect();

        // println!("publishing: {:?}", &uid_new);
        if published_emails_old.contains(email_new) {
            // UserID already published - just stop
            return Ok(());
        }

        let mut published_emails = published_emails_old;
        published_emails.push(email_new.clone());

        let published_tpk_new = tpk_filter_alive_emails(&full_tpk, &published_emails);

        if !published_tpk_new
            .userids()
            .map(|binding| Email::try_from(binding.userid()))
            .flatten()
            .any(|email| email == *email_new)
        {
            return Err(anyhow!("Requested UserID not found!"));
        }

        let published_tpk_clean = tpk_clean(&published_tpk_new)?;
        let published_tpk_tmp = self.write_to_temp(&tpk_to_string(&published_tpk_clean)?)?;

        self.move_tmp_to_published(published_tpk_tmp, fpr_primary)?;
        self.regenerate_wkd(fpr_primary, &published_tpk_clean)?;

        self.update_write_log(fpr_primary);

        if let Err(e) = self.link_email(email_new, fpr_primary) {
            info!(
                "Error ensuring email symlink! {} -> {} {:?}",
                &email_new, &fpr_primary, e
            );
        }

        Ok(())
    }

    fn nolock_unlink_email_if_other(
        &self,
        fpr_primary: &Fingerprint,
        unlink_email: &Email,
    ) -> Result<()> {
        let current_link_fpr =
            self.lookup_primary_fingerprint(&Query::ByEmail(unlink_email.clone()));
        if let Some(current_fpr) = current_link_fpr {
            if current_fpr != *fpr_primary {
                self.nolock_set_email_unpublished_filter(&current_fpr, |uid| {
                    Email::try_from(uid)
                        .map(|email| email != *unlink_email)
                        .unwrap_or(false)
                })?;
            }
        }
        Ok(())
    }

    /// Complex operation that un-publishes some user id for a Cert already in the database.
    ///
    /// 1. Load published Cert
    ///     - if UserID is not in, stop
    /// 2. Load full Cert
    ///     - if requested UserID is not in, stop
    /// 3. Prepare new published Cert
    ///    - retrieve UserIDs from old published Cert
    ///    - create new Cert from full Cert by keeping only published UserIDs
    /// 4. Check for fingerprint and long key id collisions for published Cert
    ///    - abort if any problems come up!
    /// 5. Move full and published temporary Cert to their location
    /// 6. Update all symlinks
    fn set_email_unpublished_filter(
        &self,
        fpr_primary: &Fingerprint,
        email_remove: impl Fn(&UserID) -> bool,
    ) -> Result<()> {
        let _lock = self.lock()?;
        self.nolock_set_email_unpublished_filter(fpr_primary, email_remove)
    }

    fn nolock_set_email_unpublished_filter(
        &self,
        fpr_primary: &Fingerprint,
        email_remove: impl Fn(&UserID) -> bool,
    ) -> Result<()> {
        let published_tpk_old = self
            .by_fpr(fpr_primary)
            .ok_or_else(|| anyhow!("Key not in database!"))
            .and_then(|bytes| Cert::from_bytes(bytes.as_bytes()))?;

        let published_emails_old: Vec<Email> = published_tpk_old
            .userids()
            .map(|binding| Email::try_from(binding.userid()))
            .flatten()
            .collect();

        let published_tpk_new = published_tpk_old.retain_userids(|uid| email_remove(uid.userid()));

        let published_emails_new: Vec<Email> = published_tpk_new
            .userids()
            .map(|binding| Email::try_from(binding.userid()))
            .flatten()
            .collect();

        let unpublished_emails = published_emails_old
            .iter()
            .filter(|email| !published_emails_new.contains(email));

        let published_tpk_clean = tpk_clean(&published_tpk_new)?;
        let published_tpk_tmp = self.write_to_temp(&tpk_to_string(&published_tpk_clean)?)?;

        self.move_tmp_to_published(published_tpk_tmp, fpr_primary)?;
        self.regenerate_wkd(fpr_primary, &published_tpk_clean)?;

        self.update_write_log(fpr_primary);

        for unpublished_email in unpublished_emails {
            if let Err(e) = self.unlink_email(unpublished_email, fpr_primary) {
                info!(
                    "Error deleting email symlink! {} -> {} {:?}",
                    &unpublished_email, &fpr_primary, e
                );
            }
        }

        Ok(())
    }

    fn set_email_unpublished(&self, fpr_primary: &Fingerprint, email_remove: &Email) -> Result<()> {
        self.set_email_unpublished_filter(fpr_primary, |uid| {
            Email::try_from(uid)
                .map(|email| email != *email_remove)
                .unwrap_or(false)
        })
    }

    fn set_email_unpublished_all(&self, fpr_primary: &Fingerprint) -> Result<()> {
        self.set_email_unpublished_filter(fpr_primary, |_| false)
    }

    fn regenerate_links(&self, fpr_primary: &Fingerprint) -> Result<RegenerateResult> {
        let tpk = self
            .by_primary_fpr(fpr_primary)
            .and_then(|bytes| Cert::from_bytes(bytes.as_bytes()).ok())
            .ok_or_else(|| anyhow!("Key not in database!"))?;

        let published_emails: Vec<Email> = tpk
            .userids()
            .map(|binding| Email::try_from(binding.userid()))
            .flatten()
            .collect();

        self.regenerate_wkd(fpr_primary, &tpk)?;

        let fingerprints = tpk_get_linkable_fprs(&tpk);

        let fpr_checks = fingerprints
            .into_iter()
            .map(|fpr| self.check_link_fpr(&fpr, fpr_primary))
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>>>()?;

        let fpr_not_linked = fpr_checks.into_iter().flatten();

        let mut keys_linked = 0;
        let mut emails_linked = 0;

        for fpr in fpr_not_linked {
            keys_linked += 1;
            self.link_fpr(&fpr, fpr_primary)?;
        }

        for email in published_emails {
            emails_linked += 1;
            self.link_email(&email, fpr_primary)?;
        }

        if keys_linked != 0 || emails_linked != 0 {
            Ok(RegenerateResult::Updated)
        } else {
            Ok(RegenerateResult::Unchanged)
        }
    }

    fn regenerate_wkd(&self, fpr_primary: &Fingerprint, published_tpk: &Cert) -> Result<()> {
        let published_wkd_tpk_tmp = if published_tpk.userids().next().is_some() {
            Some(self.write_to_temp(&published_tpk.export_to_vec()?)?)
        } else {
            None
        };
        self.move_tmp_to_published_wkd(published_wkd_tpk_tmp, fpr_primary)?;

        Ok(())
    }
}

fn tpk_get_emails(cert: &Cert) -> Vec<Email> {
    cert.userids()
        .filter_map(|binding| Email::try_from(binding.userid()).ok())
        .collect()
}

pub fn tpk_get_linkable_fprs(tpk: &Cert) -> Vec<Fingerprint> {
    let signing_capable = &KeyFlags::empty().set_signing().set_certification();
    let fpr_primary = &Fingerprint::try_from(tpk.fingerprint()).unwrap();
    tpk.keys()
        .into_iter()
        .filter_map(|bundle| {
            Fingerprint::try_from(bundle.key().fingerprint()).ok().map(|fpr| {
                (
                    fpr,
                    bundle
                        .binding_signature(&POLICY, None)
                        .ok()
                        .and_then(|sig| sig.key_flags()),
                )
            })
        })
        .filter(|(fpr, flags)| {
            fpr == fpr_primary
                || flags.is_none()
                || !(signing_capable & flags.as_ref().unwrap()).is_empty()
        })
        .map(|(fpr, _)| fpr)
        .collect()
}
