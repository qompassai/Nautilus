// pub, fetch by fpr, verify no uid
// verify uid fetch by fpr fetch by uid
// verify again
// verify other uid fetch by ui1 uid2 fpr
// pub again
// pub with less uid
// pub with new uid
//
// pub & verify
// req del one
// fetch by uid & fpr
// confirm
// fetch by uid & fpr
// confirm again
// fetch by uid & fpr

use anyhow::Result;
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

use openpgp::cert::{CertBuilder, UserIDRevocationBuilder};
use openpgp::types::{KeyFlags, ReasonForRevocation, SignatureType};
use openpgp::{
    packet::{signature::*, UserID},
    parse::Parse,
    types::RevocationStatus,
    Cert, Packet,
};
use std::fs;
use std::path::Path;
use types::{Email, Fingerprint, KeyID};
use Database;
use Query;

use openpgp_utils::POLICY;

use EmailAddressStatus;
use TpkStatus;

fn check_mail_none(db: &impl Database, email: &Email) {
    assert!(db.by_email(email).is_none());
    assert!(db.by_email_wkd(email).is_none());
}

fn check_mail_some(db: &impl Database, email: &Email) {
    assert!(db.by_email(email).is_some());
    assert!(db.by_email_wkd(email).is_some());
}

pub fn test_uid_verification(db: &mut impl Database, log_path: &Path) {
    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let tpk = CertBuilder::new()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let uid1 = UserID::from(str_uid1);
    let uid2 = UserID::from(str_uid2);
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // upload key
    let tpk_status = db.merge(tpk.clone()).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);

    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!(
                (email1.clone(), EmailAddressStatus::NotPublished),
                (email2.clone(), EmailAddressStatus::NotPublished),
            ),
            unparsed_uids: 0,
        },
        tpk_status
    );

    {
        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = Cert::from_bytes(raw.as_bytes()).unwrap();

        assert!(key.userids().next().is_none());
        assert!(key.user_attributes().next().is_none());
        assert!(key.keys().subkeys().next().is_none());
    }

    // fail to fetch by uid
    check_mail_none(db, &email1);
    check_mail_none(db, &email2);

    // verify 1st uid
    db.set_email_published(&fpr, &email1).unwrap();

    {
        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = Cert::from_bytes(raw.as_bytes()).unwrap();

        assert!(key.userids().nth(1).is_none());
        assert!(key.user_attributes().next().is_none());
        assert!(key.keys().subkeys().next().is_none());

        let uid = key.userids().next().unwrap().userid().clone();

        assert!((uid == uid1) ^ (uid == uid2));
        let email = Email::from_str(&String::from_utf8(uid.value().to_vec()).unwrap()).unwrap();
        assert_eq!(db.by_email(&email).unwrap(), raw);

        if email1 == email {
            assert!(db.by_email(&email2).is_none());
        } else if email2 == email {
            assert!(db.by_email(&email1).is_none());
        } else {
            unreachable!()
        }
    }

    // this operation is idempotent - let's try again!
    db.set_email_published(&fpr, &tpk_status.email_status[0].0)
        .unwrap();

    {
        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = Cert::from_bytes(raw.as_bytes()).unwrap();

        assert!(key.userids().nth(1).is_none());
        assert!(key.user_attributes().next().is_none());
        assert!(key.keys().subkeys().next().is_none());

        let uid = key.userids().next().unwrap().userid().clone();

        assert!((uid == uid1) ^ (uid == uid2));
        let email = Email::from_str(&String::from_utf8(uid.value().to_vec()).unwrap()).unwrap();
        assert_eq!(db.by_email(&email).unwrap(), raw);

        if email1 == email {
            assert!(db.by_email(&email2).is_none());
        } else if email2 == email {
            assert!(db.by_email(&email1).is_none());
        } else {
            unreachable!()
        }
    }

    // verify 2nd uid
    db.set_email_published(&fpr, &tpk_status.email_status[1].0)
        .unwrap();

    {
        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = Cert::from_bytes(raw.as_bytes()).unwrap();

        assert_eq!(key.userids().len(), 2);
        assert!(key.user_attributes().next().is_none());
        assert!(key.keys().subkeys().next().is_none());

        let myuid1 = key.userids().next().unwrap().userid().clone();
        let myuid2 = key.userids().nth(1).unwrap().userid().clone();

        assert_eq!(db.by_email(&email1).unwrap(), raw);
        assert_eq!(db.by_email(&email2).unwrap(), raw);
        assert!(((myuid1 == uid1) & (myuid2 == uid2)) ^ ((myuid1 == uid2) & (myuid2 == uid1)));
    }

    let tpk_status = db.merge(tpk.clone()).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!(
                (email1.clone(), EmailAddressStatus::Published),
                (email2.clone(), EmailAddressStatus::Published),
            ),
            unparsed_uids: 0,
        },
        tpk_status
    );

    // publish w/ one uid less
    {
        let short_tpk = cert_without_uid(tpk, &uid1);

        let tpk_status = db.merge(short_tpk).unwrap().into_tpk_status();
        assert_eq!(
            TpkStatus {
                is_revoked: false,
                email_status: vec!(
                    (email1.clone(), EmailAddressStatus::Published),
                    (email2.clone(), EmailAddressStatus::Published),
                ),
                unparsed_uids: 0,
            },
            tpk_status
        );

        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = Cert::from_bytes(raw.as_bytes()).unwrap();

        assert_eq!(key.userids().len(), 2);
        assert!(key.user_attributes().next().is_none());
        assert!(key.keys().subkeys().next().is_none());

        let myuid1 = key.userids().next().unwrap().userid().clone();
        let myuid2 = key.userids().nth(1).unwrap().userid().clone();

        assert_eq!(db.by_email(&email1).unwrap(), raw);
        assert_eq!(db.by_email(&email2).unwrap(), raw);
        assert!(((myuid1 == uid1) & (myuid2 == uid2)) ^ ((myuid1 == uid2) & (myuid2 == uid1)));
    }

    // publish w/one uid more
    // FIXME how to construct a UserIDBinding?
    /*{
        let mut packets = tpk
            .clone()
            .into_packet_pile()
            .into_children()
            .filter(|pkt| {
                match pkt {
                    Packet::UserID(ref uid) => *uid != uid1,
                    _ => true,
                }
            })
            .collect::<Vec<_>>();
        let str_uid3 = "Test C <test_c@example.com>";
        let uid3 = UserID::from(str_uid3);

        let email3 = Email::from_str(str_uid3).unwrap();
        let key = tpk.primary_key();
        let mut signer = key.clone().into_keypair().unwrap();
        let bind = UserIDBinding::default(key, uid3.clone(), &mut signer).unwrap();

        packets.push(Packet::UserID(uid3.clone()));
        packets
            .push(Packet::Signature(bind.selfsigs()[0].clone()));

        let pile : PacketPile = packets.into();
        let ext_tpk = Cert::from_packet_pile(pile).unwrap();
        let tpk_status = db.merge(ext_tpk).unwrap().into_tpk_status();

        assert_eq!(TpkStatus {
            is_revoked: false,
            email_status: vec!(
                (email2.clone(), EmailAddressStatus::Published),
                (email3.clone(), EmailAddressStatus::NotPublished),
            ),
            unparsed_uids: 0,
        }, tpk_status);

        // fetch by fpr
        let raw = db.by_fpr(&fpr).unwrap();
        let key = Cert::from_bytes(raw.as_bytes()).unwrap();

        assert_eq!(key.userids().len(), 2);
        assert!(key.user_attributes().next().is_none());
        assert!(key.keys().subkeys().next().is_none());

        let myuid1 = key.userids().next().unwrap().userid().clone();
        let myuid2 = key.userids().skip(1).next().unwrap().userid().clone();

        assert_eq!(db.by_email(&email1).unwrap(), raw);
        assert_eq!(db.by_email(&email2).unwrap(), raw);
        assert!(
            ((myuid1 == uid1) & (myuid2 == uid2))
                ^ ((myuid1 == uid2) & (myuid2 == uid1))
        );
        assert!(db.by_email(&email3).is_none());
    }*/
}

pub fn test_regenerate(db: &mut impl Database, log_path: &Path) {
    let str_uid1 = "Test A <test_a@example.com>";
    let tpk = CertBuilder::new()
        .add_userid(str_uid1)
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()
        .unwrap()
        .0;
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();
    let email1 = Email::from_str(str_uid1).unwrap();
    let fpr_sign: Fingerprint = tpk
        .keys()
        .with_policy(&POLICY, None)
        .for_signing()
        .map(|amalgamation| amalgamation.key().fingerprint().try_into().unwrap())
        .next()
        .unwrap();
    let fpr_encrypt: Fingerprint = tpk
        .keys()
        .with_policy(&POLICY, None)
        .key_flags(KeyFlags::empty().set_transport_encryption())
        .map(|amalgamation| amalgamation.key().fingerprint().try_into().unwrap())
        .next()
        .unwrap();

    // upload key
    db.merge(tpk).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);

    db.regenerate_links(&fpr).unwrap();
    check_mail_none(db, &email1);
    assert!(db.by_fpr(&fpr).is_some());
    assert!(db.by_fpr(&fpr_sign).is_some());
    assert!(db.by_fpr(&fpr_encrypt).is_none());

    db.set_email_published(&fpr, &email1).unwrap();

    db.unlink_email(&email1, &fpr).unwrap();
    assert!(db.check_consistency().is_err());
    db.regenerate_links(&fpr).unwrap();
    assert!(db.check_consistency().is_ok());

    db.unlink_fpr(&fpr, &fpr).unwrap();
    assert!(db.check_consistency().is_err());
    db.regenerate_links(&fpr).unwrap();
    assert!(db.check_consistency().is_ok());

    db.unlink_fpr(&fpr_sign, &fpr).unwrap();
    assert!(db.check_consistency().is_err());
    db.regenerate_links(&fpr).unwrap();
    assert!(db.check_consistency().is_ok());
}

pub fn test_reupload(db: &mut impl Database, log_path: &Path) {
    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let tpk = CertBuilder::new()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload key
    db.merge(tpk.clone()).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);

    // verify 1st uid
    db.set_email_published(&fpr, &email1).unwrap();
    assert!(db.by_email(&email2).is_none() ^ db.by_email(&email1).is_none());

    // reupload
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();

    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!(
                (email1.clone(), EmailAddressStatus::Published),
                (email2.clone(), EmailAddressStatus::NotPublished),
            ),
            unparsed_uids: 0,
        },
        tpk_status
    );
    assert!(db.by_email(&email2).is_none() ^ db.by_email(&email1).is_none());
}

pub fn test_uid_replacement(db: &mut impl Database, log_path: &Path) {
    let str_uid1 = "Test A <test_a@example.com>";
    let tpk1 = CertBuilder::new()
        .add_userid(str_uid1)
        .generate()
        .unwrap()
        .0;
    let fpr1 = Fingerprint::try_from(tpk1.fingerprint()).unwrap();

    let tpk2 = CertBuilder::new()
        .add_userid(str_uid1)
        .generate()
        .unwrap()
        .0;
    let fpr2 = Fingerprint::try_from(tpk2.fingerprint()).unwrap();

    let pgp_fpr1 = tpk1.fingerprint();
    let pgp_fpr2 = tpk2.fingerprint();

    let email1 = Email::from_str(str_uid1).unwrap();

    // upload both keys
    db.merge(tpk1).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr1);
    db.merge(tpk2).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr2);

    // verify 1st uid
    db.set_email_published(&fpr1, &email1).unwrap();
    check_mail_some(db, &email1);
    assert_eq!(
        Cert::from_bytes(db.by_email(&email1).unwrap().as_bytes())
            .unwrap()
            .fingerprint(),
        pgp_fpr1
    );

    assert_eq!(
        Cert::from_bytes(db.by_fpr(&fpr1).unwrap().as_bytes())
            .unwrap()
            .userids()
            .len(),
        1
    );
    assert_eq!(
        Cert::from_bytes(db.by_fpr(&fpr2).unwrap().as_bytes())
            .unwrap()
            .userids()
            .len(),
        0
    );

    // verify uid on other key
    db.set_email_published(&fpr2, &email1).unwrap();
    check_mail_some(db, &email1);
    assert_eq!(
        Cert::from_bytes(db.by_email(&email1).unwrap().as_bytes())
            .unwrap()
            .fingerprint(),
        pgp_fpr2
    );

    assert_eq!(
        Cert::from_bytes(db.by_fpr(&fpr1).unwrap().as_bytes())
            .unwrap()
            .userids()
            .len(),
        0
    );
    assert_eq!(
        Cert::from_bytes(db.by_fpr(&fpr2).unwrap().as_bytes())
            .unwrap()
            .userids()
            .len(),
        1
    );
}

pub fn test_uid_deletion(db: &mut impl Database, log_path: &Path) {
    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let tpk = CertBuilder::new()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()
        .unwrap()
        .0;
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();
    let n_subkeys = tpk.keys().subkeys().count();
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload key and verify uids
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!(
                (email1.clone(), EmailAddressStatus::NotPublished),
                (email2.clone(), EmailAddressStatus::NotPublished),
            ),
            unparsed_uids: 0,
        },
        tpk_status
    );

    db.set_email_published(&fpr, &email1).unwrap();
    db.set_email_published(&fpr, &email2).unwrap();

    // Check that both Mappings are there, and that the Cert is
    // otherwise intact.
    let tpk = db.lookup(&Query::ByEmail(email2.clone())).unwrap().unwrap();
    assert_eq!(tpk.userids().count(), 2);
    assert_eq!(tpk.keys().subkeys().count(), n_subkeys);

    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // Delete second UID.
    db.set_email_unpublished(&fpr, &email2).unwrap();

    // Check that the second is still there, and that the Cert is
    // otherwise intact.
    let tpk = db.lookup(&Query::ByEmail(email1.clone())).unwrap().unwrap();
    assert_eq!(tpk.userids().count(), 1);
    assert_eq!(tpk.keys().subkeys().count(), n_subkeys);

    // Delete first UID.
    db.set_email_unpublished(&fpr, &email1).unwrap();

    // Check that the second is still there, and that the Cert is
    // otherwise intact.
    let tpk = db
        .lookup(&Query::ByFingerprint(tpk.fingerprint().try_into().unwrap()))
        .unwrap()
        .unwrap();
    assert_eq!(tpk.userids().count(), 0);
    assert_eq!(tpk.keys().subkeys().count(), n_subkeys);
}

pub fn test_subkey_lookup(db: &mut impl Database, _log_path: &Path) {
    let tpk = CertBuilder::new()
        .add_userid("Testy <test@example.com>")
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()
        .unwrap()
        .0;

    // upload key
    let _ = db.merge(tpk.clone()).unwrap().into_tpk_status();

    let fpr_primray = Fingerprint::try_from(tpk.fingerprint()).unwrap();
    let fpr_sign: Fingerprint = tpk
        .keys()
        .with_policy(&POLICY, None)
        .for_signing()
        .map(|amalgamation| amalgamation.key().fingerprint().try_into().unwrap())
        .next()
        .unwrap();
    let fpr_encrypt: Fingerprint = tpk
        .keys()
        .with_policy(&POLICY, None)
        .key_flags(KeyFlags::empty().set_transport_encryption())
        .map(|amalgamation| amalgamation.key().fingerprint().try_into().unwrap())
        .next()
        .unwrap();

    let raw1 = db
        .by_fpr(&fpr_primray)
        .expect("primary fpr must be linked!");
    let raw2 = db
        .by_fpr(&fpr_sign)
        .expect("signing subkey fpr must be linked!");
    // encryption subkey key id must not be linked!
    assert!(db.by_fpr(&fpr_encrypt).is_none());

    assert_eq!(raw1, raw2);
}

pub fn test_kid_lookup(db: &mut impl Database, _log_path: &Path) {
    let tpk = CertBuilder::new()
        .add_userid("Testy <test@example.com>")
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()
        .unwrap()
        .0;

    // upload key
    let _ = db.merge(tpk.clone()).unwrap().into_tpk_status();
    let kid_primray = KeyID::try_from(tpk.fingerprint()).unwrap();
    let kid_sign: KeyID = tpk
        .keys()
        .with_policy(&POLICY, None)
        .for_signing()
        .map(|amalgamation| amalgamation.key().fingerprint().try_into().unwrap())
        .next()
        .unwrap();
    let kid_encrypt: KeyID = tpk
        .keys()
        .with_policy(&POLICY, None)
        .key_flags(KeyFlags::empty().set_transport_encryption())
        .map(|amalgamation| amalgamation.key().fingerprint().try_into().unwrap())
        .next()
        .unwrap();

    let raw1 = db
        .by_kid(&kid_primray)
        .expect("primary key id must be linked!");
    let raw2 = db
        .by_kid(&kid_sign)
        .expect("signing subkey key id must be linked!");
    // encryption subkey key id must not be linked!
    assert!(db.by_kid(&kid_encrypt).is_none());

    assert_eq!(raw1, raw2);
}

pub fn test_upload_revoked_tpk(db: &mut impl Database, log_path: &Path) {
    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let (mut tpk, revocation) = CertBuilder::new()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap();
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // upload and publish one of the email addresses. those should be
    // automatically depublished when we upload the revoked key!
    db.merge(tpk.clone()).unwrap();
    db.set_email_published(&fpr, &email1).unwrap();

    check_mail_some(db, &email1);
    check_mail_none(db, &email2);

    tpk = tpk.insert_packets(revocation).unwrap();
    match tpk.revocation_status(&POLICY, None) {
        RevocationStatus::Revoked(_) => (),
        _ => panic!("expected Cert to be revoked"),
    }

    // upload key
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);
    assert_eq!(
        TpkStatus {
            is_revoked: true,
            email_status: vec!(
                (email1.clone(), EmailAddressStatus::NotPublished),
                (email2.clone(), EmailAddressStatus::NotPublished),
            ),
            unparsed_uids: 0,
        },
        tpk_status
    );

    check_mail_none(db, &email1);
    check_mail_none(db, &email2);
}

pub fn test_uid_revocation(db: &mut impl Database, log_path: &Path) {
    use std::{thread, time};

    let str_uid1 = "Test A <test_a@example.com>";
    let str_uid2 = "Test B <test_b@example.com>";
    let tpk = CertBuilder::new()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let uid2 = UserID::from(str_uid2);
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // upload key
    let tpk_status = db.merge(tpk.clone()).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!(
                (email1.clone(), EmailAddressStatus::NotPublished),
                (email2.clone(), EmailAddressStatus::NotPublished),
            ),
            unparsed_uids: 0,
        },
        tpk_status
    );

    // verify uid
    db.set_email_published(&fpr, &tpk_status.email_status[0].0)
        .unwrap();
    db.set_email_published(&fpr, &tpk_status.email_status[1].0)
        .unwrap();

    // fetch both uids
    check_mail_some(db, &email1);
    check_mail_some(db, &email2);

    thread::sleep(time::Duration::from_secs(2));

    // revoke one uid
    let sig = {
        let policy = &POLICY;
        let uid = tpk
            .userids()
            .with_policy(policy, None)
            .find(|b| *b.userid() == uid2)
            .unwrap();
        assert_eq!(
            RevocationStatus::NotAsFarAsWeKnow,
            uid.revocation_status(&POLICY, None)
        );

        let mut keypair = tpk
            .primary_key()
            .bundle()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        UserIDRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"It was the maid :/")
            .unwrap()
            .build(&mut keypair, &tpk, uid.userid(), None)
            .unwrap()
    };
    assert_eq!(sig.typ(), SignatureType::CertificationRevocation);
    let tpk = tpk.insert_packets(sig).unwrap();
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!(
                (email1.clone(), EmailAddressStatus::Published),
                (email2.clone(), EmailAddressStatus::Revoked),
            ),
            unparsed_uids: 0,
        },
        tpk_status
    );

    // Fail to fetch by the revoked uid, ok by the non-revoked one.
    check_mail_some(db, &email1);
    check_mail_none(db, &email2);
}

/* FIXME I couldn't get this to work.
pub fn test_uid_revocation_fake(db: &mut D) {
    use std::{thread, time};

    let str_uid = "Test A <test_a@example.com>";
    let tpk = CertBuilder::new()
        .add_userid(str_uid)
        .generate()
        .unwrap()
        .0;
    let tpk_fake = CertBuilder::new()
        .generate()
        .unwrap()
        .0;
    let uid = UserID::from(str_uid);
    let email = Email::from_str(str_uid).unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // upload key
    let tpk_status = db.merge(tpk.clone()).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email.clone(), EmailAddressStatus::NotPublished),
        ),
        unparsed_uids: 0,
    }, tpk_status);

    // verify uid
    db.set_email_published(&fpr, &tpk_status.email_status[0].0).unwrap();

    // fetch both uids
    assert!(db.by_email(&email).is_some());

    thread::sleep(time::Duration::from_secs(2));

    // revoke one uid
    let uid = tpk.userids().find(|b| *b.userid() == uid).cloned().unwrap();
    let sig = {
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow, uid.revocation_status(&POLICY, None));

        let mut keypair = tpk.primary_key().clone().into_keypair().unwrap();
        uid.userid().revoke(
            &mut keypair,
            &tpk_fake,
            ReasonForRevocation::UIDRetired,
            b"It was the maid :/",
            None,
            None,
        )
        .unwrap()
    };
    assert_eq!(sig.typ(), SignatureType::CertificationRevocation);
    // XXX how to get the bad revocation into the packet pile?
    let pile: PacketPile = tpk
        .into_packet_pile()
        .replace(&[ 0 ], 3, [
                 uid.userid().clone().into(),
                 uid.binding_signature().unwrap().clone().into(),
                 // sig.into(),
        ].to_vec())
        .unwrap()
        .into();
    println!("{:?}", pile);
    let tpk = Cert::from_packet_pile(pile).unwrap();
    println!("{:?}", tpk);
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    assert_eq!(TpkStatus {
        is_revoked: false,
        email_status: vec!(
            (email.clone(), EmailAddressStatus::Published),
        ),
        unparsed_uids: 0,
    }, tpk_status);

    // Fail to fetch by the revoked uid, ok by the non-revoked one.
    assert!(db.by_email(&email).is_some());
}
*/

pub fn test_unlink_uid(db: &mut impl Database, log_path: &Path) {
    let uid = "Test A <test_a@example.com>";
    let email = Email::from_str(uid).unwrap();

    // Upload key and verify it.
    let tpk = CertBuilder::new().add_userid(uid).generate().unwrap().0;
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    db.merge(tpk.clone()).unwrap().into_tpk_status();
    db.set_email_published(&fpr, &email).unwrap();
    check_mail_some(db, &email);

    // Create a 2nd key with same uid, and revoke the uid.
    let tpk_evil = CertBuilder::new().add_userid(uid).generate().unwrap().0;
    let fpr_evil = Fingerprint::try_from(tpk_evil.fingerprint()).unwrap();
    let sig = {
        let policy = &POLICY;
        let uid = tpk_evil
            .userids()
            .with_policy(policy, None)
            .find(|b| b.userid().value() == uid.as_bytes())
            .unwrap();
        assert_eq!(
            RevocationStatus::NotAsFarAsWeKnow,
            uid.revocation_status(&POLICY, None)
        );

        let mut keypair = tpk_evil
            .primary_key()
            .bundle()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();

        UserIDRevocationBuilder::new()
            .set_reason_for_revocation(
                ReasonForRevocation::UIDRetired,
                b"I just had to quit, I couldn't bear it any longer",
            )
            .unwrap()
            .build(&mut keypair, &tpk_evil, uid.userid(), None)
            .unwrap()
    };
    assert_eq!(sig.typ(), SignatureType::CertificationRevocation);
    let tpk_evil = tpk_evil.insert_packets(sig).unwrap();
    let tpk_status = db.merge(tpk_evil).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr_evil);
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!((email.clone(), EmailAddressStatus::Revoked),),
            unparsed_uids: 0,
        },
        tpk_status
    );

    // Check that when looking up by email, we still get the former
    // Cert.
    assert_eq!(
        db.lookup(&Query::ByEmail(email))
            .unwrap()
            .unwrap()
            .fingerprint(),
        tpk.fingerprint()
    );
}

pub fn get_userids(armored: &str) -> Vec<UserID> {
    let tpk = Cert::from_bytes(armored.as_bytes()).unwrap();
    tpk.userids()
        .map(|binding| binding.userid().clone())
        .collect()
}

// If multiple keys have the same email address, make sure things work
// as expected.
pub fn test_same_email_1(db: &mut impl Database, log_path: &Path) {
    let str_uid1 = "A <test@example.com>";
    let tpk1 = CertBuilder::new()
        .add_userid(str_uid1)
        .generate()
        .unwrap()
        .0;
    let fpr1 = Fingerprint::try_from(tpk1.fingerprint()).unwrap();
    let uid1 = UserID::from(str_uid1);
    let email1 = Email::from_str(str_uid1).unwrap();

    let str_uid2 = "B <test@example.com>";
    let tpk2 = CertBuilder::new()
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let fpr2 = Fingerprint::try_from(tpk2.fingerprint()).unwrap();
    let uid2 = UserID::from(str_uid2);
    let email2 = Email::from_str(str_uid2).unwrap();

    // upload keys.
    let tpk_status1 = db.merge(tpk1).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr1);
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!((email1.clone(), EmailAddressStatus::NotPublished),),
            unparsed_uids: 0,
        },
        tpk_status1
    );
    let tpk_status2 = db.merge(tpk2.clone()).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr2);
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!((email2.clone(), EmailAddressStatus::NotPublished),),
            unparsed_uids: 0,
        },
        tpk_status2
    );

    // verify tpk1
    db.set_email_published(&fpr1, &tpk_status1.email_status[0].0)
        .unwrap();

    // fetch by both user ids.  Even though we didn't verify uid2, the
    // email is the same, and both should return tpk1.
    assert_eq!(
        get_userids(&db.by_email(&email1).unwrap()[..]),
        vec![uid1.clone()]
    );
    assert_eq!(get_userids(&db.by_email(&email2).unwrap()[..]), vec![uid1]);

    // verify tpk2
    db.set_email_published(&fpr2, &tpk_status2.email_status[0].0)
        .unwrap();

    // fetch by both user ids.  We should now get tpk2.
    assert_eq!(
        get_userids(&db.by_email(&email1).unwrap()[..]),
        vec![uid2.clone()]
    );
    assert_eq!(
        get_userids(&db.by_email(&email2).unwrap()[..]),
        vec![uid2.clone()]
    );

    // revoke tpk2's uid
    let sig = {
        let policy = &POLICY;
        let uid = tpk2
            .userids()
            .with_policy(policy, None)
            .find(|b| *b.userid() == uid2)
            .unwrap();
        assert_eq!(
            RevocationStatus::NotAsFarAsWeKnow,
            uid.revocation_status(&POLICY, None)
        );

        let mut keypair = tpk2
            .primary_key()
            .bundle()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();

        UserIDRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::KeyRetired, b"It was the maid :/")
            .unwrap()
            .build(&mut keypair, &tpk2, uid.userid(), None)
            .unwrap()
    };
    assert_eq!(sig.typ(), SignatureType::CertificationRevocation);
    let tpk2 = tpk2.insert_packets(sig).unwrap();
    let tpk_status2 = db.merge(tpk2).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr2);
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!((email2.clone(), EmailAddressStatus::Revoked),),
            unparsed_uids: 0,
        },
        tpk_status2
    );

    // fetch by both user ids.  We should get nothing.
    check_mail_none(db, &email1);
    check_mail_none(db, &email2);
}

// If a key has multiple user ids with the same email address, make
// sure things still work. We do this twice (see above), to
// make sure the order isn't relevant when revoking one user id
// but leaving the other.
pub fn test_same_email_2(db: &mut impl Database, log_path: &Path) {
    use std::{thread, time};

    let str_uid1 = "A <test@example.com>";
    let str_uid2 = "B <test@example.com>";
    let tpk = CertBuilder::new()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let uid1 = UserID::from(str_uid1);
    let uid2 = UserID::from(str_uid2);
    let email = Email::from_str(str_uid1).unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // upload key
    let tpk_status = db.merge(tpk.clone()).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);

    // verify uid1
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!((email.clone(), EmailAddressStatus::NotPublished),),
            unparsed_uids: 0,
        },
        tpk_status
    );
    db.set_email_published(&fpr, &tpk_status.email_status[0].0)
        .unwrap();

    // fetch by both user ids.
    assert_eq!(
        get_userids(&db.by_email(&email).unwrap()[..]),
        vec![uid1.clone(), uid2.clone()]
    );

    thread::sleep(time::Duration::from_secs(2));

    // revoke one uid
    let sig = {
        let policy = &POLICY;
        let uid = tpk
            .userids()
            .with_policy(policy, None)
            .find(|b| *b.userid() == uid2)
            .unwrap();
        assert_eq!(
            RevocationStatus::NotAsFarAsWeKnow,
            uid.revocation_status(&POLICY, None)
        );

        let mut keypair = tpk
            .primary_key()
            .bundle()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        UserIDRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"It was the maid :/")
            .unwrap()
            .build(&mut keypair, &tpk, uid.userid(), None)
            .unwrap()
    };
    assert_eq!(sig.typ(), SignatureType::CertificationRevocation);
    let tpk = tpk.insert_packets(sig).unwrap();
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!((email.clone(), EmailAddressStatus::Published),),
            unparsed_uids: 0,
        },
        tpk_status
    );

    // fetch by both user ids.  We should still get both user ids.
    assert_eq!(get_userids(&db.by_email(&email).unwrap()[..]), vec![uid1]);
}

// If a key has multiple user ids with the same email address, make
// sure things still work. We do this twice (see above), to
// make sure the order isn't relevant when revoking one user id
// but leaving the other.
pub fn test_same_email_3(db: &mut impl Database, log_path: &Path) {
    use std::{thread, time};

    let str_uid1 = "A <test@example.com>";
    let str_uid2 = "B <test@example.com>";
    let tpk = CertBuilder::new()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let uid1 = UserID::from(str_uid1);
    let uid2 = UserID::from(str_uid2);
    let email = Email::from_str(str_uid1).unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // upload key
    let tpk_status = db.merge(tpk.clone()).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);

    // verify uid1
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!((email.clone(), EmailAddressStatus::NotPublished),),
            unparsed_uids: 0,
        },
        tpk_status
    );
    db.set_email_published(&fpr, &tpk_status.email_status[0].0)
        .unwrap();

    // fetch by both user ids.
    assert_eq!(
        get_userids(&db.by_email(&email).unwrap()[..]),
        vec![uid1.clone(), uid2.clone()]
    );

    thread::sleep(time::Duration::from_secs(2));

    // revoke one uid
    let sig = {
        let policy = &POLICY;
        let uid = tpk
            .userids()
            .with_policy(policy, None)
            .find(|b| *b.userid() == uid1)
            .unwrap();
        assert_eq!(
            RevocationStatus::NotAsFarAsWeKnow,
            uid.revocation_status(&POLICY, None)
        );

        let mut keypair = tpk
            .primary_key()
            .bundle()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        UserIDRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"It was the maid :/")
            .unwrap()
            .build(&mut keypair, &tpk, uid.userid(), None)
            .unwrap()
    };
    assert_eq!(sig.typ(), SignatureType::CertificationRevocation);
    let tpk = tpk.insert_packets(sig).unwrap();
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!((email.clone(), EmailAddressStatus::Published),),
            unparsed_uids: 0,
        },
        tpk_status
    );

    assert_eq!(
        get_userids(&db.by_email(&email).unwrap()[..]),
        vec![uid2.clone()]
    );

    // make sure this survives depulication and publication of that same email address
    db.set_email_unpublished(&fpr, &email).unwrap();
    db.set_email_published(&fpr, &email).unwrap();
    assert_eq!(get_userids(&db.by_email(&email).unwrap()[..]), vec![uid2]);
}

// If a key has a verified email address, make sure newly uploaded user
// ids with the same email are published as well.
pub fn test_same_email_4(db: &mut impl Database, log_path: &Path) {
    let str_uid1 = "A <test@example.com>";
    let str_uid2 = "B <test@example.com>";
    let tpk = CertBuilder::new()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .generate()
        .unwrap()
        .0;
    let uid1 = UserID::from(str_uid1);
    let uid2 = UserID::from(str_uid2);
    let email = Email::from_str(str_uid1).unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    let cert_uid_1 = cert_without_uid(tpk.clone(), &uid2);
    let cert_uid_2 = cert_without_uid(tpk, &uid1);

    // upload key
    let tpk_status = db.merge(cert_uid_1).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);
    db.set_email_published(&fpr, &tpk_status.email_status[0].0)
        .unwrap();
    assert_eq!(
        get_userids(&db.by_email(&email).unwrap()[..]),
        vec![uid1.clone()]
    );

    let tpk_status = db.merge(cert_uid_2).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!((email.clone(), EmailAddressStatus::Published),),
            unparsed_uids: 0,
        },
        tpk_status
    );

    // fetch by both user ids.  We should still get both user ids.
    assert_eq!(
        get_userids(&db.by_email(&email).unwrap()[..]),
        vec![uid1, uid2]
    );
}

pub fn test_bad_uids(db: &mut impl Database, log_path: &Path) {
    let str_uid1 = "foo@bar.example <foo@bar.example>";
    let str_uid2 = "A <test@example.com>";
    let str_uid3 = "lalalalaaaaa";
    let tpk = CertBuilder::new()
        .add_userid(str_uid1)
        .add_userid(str_uid2)
        .add_userid(str_uid3)
        .generate()
        .unwrap()
        .0;
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();

    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!(
                (email1.clone(), EmailAddressStatus::NotPublished),
                (email2.clone(), EmailAddressStatus::NotPublished),
            ),
            unparsed_uids: 1,
        },
        tpk_status
    );

    db.set_email_published(&fpr, &email2).unwrap();

    let tpk_status = db
        .get_tpk_status(&fpr, &[email1.clone(), email2.clone()])
        .unwrap();
    assert_eq!(
        TpkStatus {
            is_revoked: false,
            email_status: vec!(
                (email1, EmailAddressStatus::NotPublished),
                (email2, EmailAddressStatus::Published),
            ),
            unparsed_uids: 1,
        },
        tpk_status
    );
}

pub fn test_no_selfsig(db: &mut impl Database, log_path: &Path) {
    let (mut tpk, revocation) = CertBuilder::new().generate().unwrap();
    let fpr = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    // don't allow upload of naked key
    assert!(db.merge(tpk.clone()).is_err());

    // with revocation, it's ok
    tpk = tpk.insert_packets(revocation).unwrap();
    let tpk_status = db.merge(tpk).unwrap().into_tpk_status();
    check_log_entry(log_path, &fpr);
    assert_eq!(
        TpkStatus {
            is_revoked: true,
            email_status: vec!(),
            unparsed_uids: 0
        },
        tpk_status
    );
}

/// Makes sure that attested key signatures are correctly handled.
pub fn attested_key_signatures(db: &mut impl Database, log_path: &Path) -> Result<()> {
    use openpgp::types::*;
    use std::time::{Duration, SystemTime};
    let t0 = SystemTime::now() - Duration::new(5 * 60, 0);
    let t1 = SystemTime::now() - Duration::new(4 * 60, 0);

    let (alice, _) = CertBuilder::new()
        .set_creation_time(t0)
        .add_userid("alice@foo.com")
        .generate()?;
    let mut alice_signer = alice
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()?
        .into_keypair()?;

    let (bob, _) = CertBuilder::new()
        .set_creation_time(t0)
        .add_userid("bob@bar.com")
        .generate()?;
    let bobs_fp = Fingerprint::try_from(bob.fingerprint())?;
    let mut bob_signer = bob
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()?
        .into_keypair()?;

    // Have Alice certify the binding between "bob@bar.com" and
    // Bob's key.
    let alice_certifies_bob = bob.userids().next().unwrap().userid().bind(
        &mut alice_signer,
        &bob,
        SignatureBuilder::new(SignatureType::GenericCertification)
            .set_signature_creation_time(t1)?,
    )?;

    // Have Bob attest that certification.
    let attestations = bob.userids().next().unwrap().attest_certifications(
        &POLICY,
        &mut bob_signer,
        vec![&alice_certifies_bob],
    )?;
    assert_eq!(attestations.len(), 1);
    let attestation = attestations[0].clone();

    // Now for the test.  First, import Bob's cert as is.
    db.merge(bob.clone())?;
    check_log_entry(log_path, &bobs_fp);

    // Confirm the email so that we can inspect the userid component.
    db.set_email_published(&bobs_fp, &Email::from_str("bob@bar.com")?)?;

    // Then, add the certification, merge into the db, check that the
    // certification is stripped.
    let bob = bob.insert_packets(vec![alice_certifies_bob.clone()])?;
    db.merge(bob.clone())?;
    check_log_entry(log_path, &bobs_fp);
    let bob_ = Cert::from_bytes(&db.by_fpr(&bobs_fp).unwrap())?;
    assert_eq!(bob_.bad_signatures().count(), 0);
    assert_eq!(bob_.userids().next().unwrap().certifications().count(), 0);

    // Add the attestation, merge into the db, check that the
    // certification is now included.
    let bob_attested = bob.clone().insert_packets(vec![attestation])?;
    db.merge(bob_attested.clone())?;
    check_log_entry(log_path, &bobs_fp);
    let bob_ = Cert::from_bytes(&db.by_fpr(&bobs_fp).unwrap())?;
    assert_eq!(bob_.bad_signatures().count(), 0);
    assert_eq!(bob_.userids().next().unwrap().certifications().count(), 1);
    assert_eq!(
        bob_.with_policy(&POLICY, None)?
            .userids()
            .next()
            .unwrap()
            .attestation_key_signatures()
            .count(),
        1
    );
    assert_eq!(
        bob_.with_policy(&POLICY, None)?
            .userids()
            .next()
            .unwrap()
            .attested_certifications()
            .count(),
        1
    );

    // Make a random merge with Bob's unattested cert, demonstrating
    // that the attestation still works.
    db.merge(bob.clone())?;
    check_log_entry(log_path, &bobs_fp);
    let bob_ = Cert::from_bytes(&db.by_fpr(&bobs_fp).unwrap())?;
    assert_eq!(bob_.bad_signatures().count(), 0);
    assert_eq!(bob_.userids().next().unwrap().certifications().count(), 1);

    // Finally, withdraw consent by overriding the attestation, merge
    // into the db, check that the certification is now gone.
    let attestations = bob_attested
        .userids()
        .next()
        .unwrap()
        .attest_certifications(&POLICY, &mut bob_signer, &[])?;
    assert_eq!(attestations.len(), 1);
    let clear_attestation = attestations[0].clone();

    let bob = bob.insert_packets(vec![clear_attestation])?;
    assert_eq!(bob.userids().next().unwrap().certifications().count(), 1);
    assert_eq!(
        bob.with_policy(&POLICY, None)?
            .userids()
            .next()
            .unwrap()
            .attestation_key_signatures()
            .count(),
        1
    );
    assert_eq!(
        bob.with_policy(&POLICY, None)?
            .userids()
            .next()
            .unwrap()
            .attested_certifications()
            .count(),
        0
    );

    db.merge(bob)?;
    check_log_entry(log_path, &bobs_fp);
    let bob_ = Cert::from_bytes(&db.by_fpr(&bobs_fp).unwrap())?;
    assert_eq!(bob_.bad_signatures().count(), 0);
    assert_eq!(bob_.userids().next().unwrap().certifications().count(), 0);
    assert_eq!(
        bob_.with_policy(&POLICY, None)?
            .userids()
            .next()
            .unwrap()
            .attestation_key_signatures()
            .count(),
        1
    );
    assert_eq!(
        bob_.with_policy(&POLICY, None)?
            .userids()
            .next()
            .unwrap()
            .attested_certifications()
            .count(),
        0
    );

    Ok(())
}

fn check_log_entry(log_path: &Path, fpr: &Fingerprint) {
    let log_data = fs::read_to_string(log_path).unwrap();
    let last_entry = log_data.lines().last().unwrap().split(' ').last().unwrap();
    assert_eq!(last_entry, fpr.to_string());
}

fn cert_without_uid(cert: Cert, removed_uid: &UserID) -> Cert {
    let packets = cert
        .into_packet_pile()
        .into_children()
        .filter(|pkt| match pkt {
            Packet::UserID(ref uid) => uid != removed_uid,
            _ => true,
        });
    Cert::from_packets(packets).unwrap()
}

pub fn nonexportable_sigs(db: &mut impl Database, _log_path: &Path) -> Result<()> {
    let str_uid1 = "Test A <test_a@example.org>";
    let str_uid2 = "Test B <test_b@example.org>";

    // Generate a cert with two User IDs, the second being bound by a
    // non-exportable binding signature.
    let (cert, _revocation) = CertBuilder::new()
        .add_userid(str_uid1)
        .add_userid_with(
            str_uid2,
            SignatureBuilder::new(SignatureType::PositiveCertification)
                .set_exportable_certification(false)?,
        )?
        .generate()
        .unwrap();
    let email1 = Email::from_str(str_uid1).unwrap();
    let email2 = Email::from_str(str_uid2).unwrap();
    let fpr = Fingerprint::try_from(cert.fingerprint()).unwrap();

    db.merge(cert).unwrap();

    // email1 is exportable, expect success.
    db.set_email_published(&fpr, &email1).unwrap();
    check_mail_some(db, &email1);

    // email2 is non-exportable, expect failure.
    db.set_email_published(&fpr, &email2).unwrap_err();
    check_mail_none(db, &email2);

    Ok(())
}
