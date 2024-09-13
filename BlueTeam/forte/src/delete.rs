//! Deletes (address, key)-binding(s), and/or a key(s).

use std::convert::TryInto;
use std::path::PathBuf;

extern crate anyhow;
use anyhow::Result;

extern crate structopt;
use structopt::StructOpt;

extern crate forte_database as database;
use crate::database::{Database, KeyDatabase, Query};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "forte-delete",
    about = "Deletes (address, key)-binding(s), and/or a key(s)."
)]
pub struct Opt {
    /// Base directory.
    #[structopt(parse(from_os_str))]
    base: PathBuf,

    /// E-Mail address, Fingerprint, or KeyID of the TPK to delete.
    /// If a Fingerprint or KeyID is given, --all is implied.
    query: String,

    /// Also delete all bindings.
    #[structopt(long = "all-bindings")]
    all_bindings: bool,

    /// Also delete all bindings and the key.
    #[structopt(long = "all")]
    all: bool,
}

fn main() {
    if let Err(e) = real_main() {
        eprint!("{}", e);
        let mut cause = e.source();
        while let Some(c) = cause {
            eprint!(":\n  {}", c);
            cause = c.source();
        }
        eprintln!();
        ::std::process::exit(2);
    }
}

fn real_main() -> Result<()> {
    let opt = Opt::from_args();
    let db = KeyDatabase::new_from_base(opt.base.canonicalize()?)?;
    delete(&db, &opt.query.parse()?, opt.all_bindings, opt.all)
}

fn delete(db: &KeyDatabase, query: &Query, all_bindings: bool, mut all: bool) -> Result<()> {
    match query {
        Query::ByFingerprint(_) | Query::ByKeyID(_) => {
            eprintln!(
                "Fingerprint or KeyID given, deleting key and all \
                       bindings."
            );
            all = true;
        }
        _ => (),
    }

    let tpk = db
        .lookup(query)?
        .ok_or_else(|| anyhow::format_err!("No TPK matching {:?}", query))?;

    let fp: database::types::Fingerprint = tpk.fingerprint().try_into()?;
    let mut results = Vec::new();

    // First, delete the bindings.
    if all_bindings || all {
        results.push(("all bindings".into(), db.set_email_unpublished_all(&fp)));
    } else if let Query::ByEmail(ref email) = query {
        results.push((email.to_string(), db.set_email_unpublished(&fp, email)));
    } else {
        unreachable!()
    }

    // Now delete the key(s) itself.
    if all {
        // TODO
        /*for skb in tpk.subkeys() {
            results.push(
                (skb.subkey().fingerprint().to_keyid().to_string(),
                 db.unlink_kid(&skb.subkey().fingerprint().try_into()?,
                               &fp)));
            results.push(
                (skb.subkey().fingerprint().to_string(),
                 db.unlink_fpr(&skb.subkey().fingerprint().try_into()?,
                               &fp)));
        }

        results.push(
            (tpk.fingerprint().to_keyid().to_string(),
             db.unlink_kid(&tpk.fingerprint().try_into()?,
                           &fp)));
        results.push(
            (tpk.fingerprint().to_string(),
             db.update(&fp, None)));
        */
    }

    let mut err = Ok(());
    for (slug, result) in results {
        eprintln!(
            "{}: {}",
            slug,
            if let Err(ref e) = result {
                e.to_string()
            } else {
                "Deleted".into()
            }
        );
        if err.is_ok() {
            if let Err(e) = result {
                err = Err(e);
            }
        }
    }

    err
}
