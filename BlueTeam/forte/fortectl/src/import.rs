use std::cmp::min;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use anyhow::Result;

extern crate tempfile;

extern crate sequoia_openpgp as openpgp;
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openpgp::Packet;

extern crate hagrid_database as database;
use database::{Database, ImportResult, KeyDatabase};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use HagridConfig;

// parsing TPKs takes time, so we benefit from some parallelism. however, the
// database is locked during the entire merge operation, so we get diminishing
// returns after the first few threads.
const NUM_THREADS_MAX: usize = 3;

#[allow(clippy::needless_collect)]
pub fn do_import(config: &HagridConfig, dry_run: bool, input_files: Vec<PathBuf>) -> Result<()> {
    let num_threads = min(NUM_THREADS_MAX, input_files.len());
    let input_file_chunks = setup_chunks(input_files, num_threads);

    let multi_progress = Arc::new(MultiProgress::new());
    let progress_bar = multi_progress.add(ProgressBar::new(0));

    let threads: Vec<_> = input_file_chunks
        .into_iter()
        .map(|input_file_chunk| {
            let config = config.clone();
            let multi_progress = multi_progress.clone();
            thread::spawn(move || {
                import_from_files(&config, dry_run, input_file_chunk, multi_progress).unwrap();
            })
        })
        .collect();

    eprintln!("Importing in {} threads", num_threads);

    thread::spawn(move || multi_progress.join().unwrap());
    threads.into_iter().for_each(|t| t.join().unwrap());
    progress_bar.finish();

    Ok(())
}

fn setup_chunks(mut input_files: Vec<PathBuf>, num_threads: usize) -> Vec<Vec<PathBuf>> {
    let chunk_size = (input_files.len() + (num_threads - 1)) / num_threads;
    (0..num_threads)
        .map(|_| {
            let len = input_files.len();
            input_files.drain(0..min(chunk_size, len)).collect()
        })
        .collect()
}

struct ImportStats<'a> {
    progress: &'a ProgressBar,
    filename: String,
    count_total: u64,
    count_err: u64,
    count_new: u64,
    count_updated: u64,
    count_unchanged: u64,
}

impl<'a> ImportStats<'a> {
    fn new(progress: &'a ProgressBar, filename: String) -> Self {
        ImportStats {
            progress,
            filename,
            count_total: 0,
            count_err: 0,
            count_new: 0,
            count_updated: 0,
            count_unchanged: 0,
        }
    }

    fn update(&mut self, result: Result<ImportResult>) {
        // If a new TPK starts, parse and import.
        self.count_total += 1;
        match result {
            Err(_) => self.count_err += 1,
            Ok(ImportResult::New(_)) => self.count_new += 1,
            Ok(ImportResult::Updated(_)) => self.count_updated += 1,
            Ok(ImportResult::Unchanged(_)) => self.count_unchanged += 1,
        }
        self.progress_update();
    }

    fn progress_update(&self) {
        if (self.count_total % 10) != 0 {
            return;
        }
        self.progress.set_message(&format!(
            "{}, imported {:5} keys, {:5} New {:5} Updated {:5} Unchanged {:5} Errors",
            &self.filename,
            self.count_total,
            self.count_new,
            self.count_updated,
            self.count_unchanged,
            self.count_err
        ));
    }
}

fn import_from_files(
    config: &HagridConfig,
    dry_run: bool,
    input_files: Vec<PathBuf>,
    multi_progress: Arc<MultiProgress>,
) -> Result<()> {
    let db = KeyDatabase::new_internal(
        config.keys_internal_dir.as_ref().unwrap(),
        config.keys_external_dir.as_ref().unwrap(),
        config.tmp_dir.as_ref().unwrap(),
        dry_run,
    )?;

    for input_file in input_files {
        import_from_file(&db, &input_file, &multi_progress)?;
    }

    Ok(())
}

fn import_from_file(db: &KeyDatabase, input: &Path, multi_progress: &MultiProgress) -> Result<()> {
    let input_file = File::open(input)?;

    let bytes_total = input_file.metadata()?.len();
    let progress_bar = multi_progress.add(ProgressBar::new(bytes_total));
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {msg}")
            .progress_chars("##-"),
    );
    progress_bar.set_message("Starting…");

    let input_reader = &mut progress_bar.wrap_read(input_file);
    let filename = input.file_name().unwrap().to_string_lossy().to_string();
    let mut stats = ImportStats::new(&progress_bar, filename.clone());

    read_file_to_tpks(input_reader, &mut |acc| {
        let primary_key = acc[0].clone();
        let result = import_key(db, acc);
        if let Err(ref e) = result {
            let key_fpr = match primary_key {
                Packet::PublicKey(key) => key.fingerprint().to_hex(),
                Packet::SecretKey(key) => key.fingerprint().to_hex(),
                _ => "Unknown".to_owned(),
            };
            let error = format!("{}:{:05}:{}: {}", filename, stats.count_total, key_fpr, e);
            progress_bar.println(error);
        }
        stats.update(result);
    })?;

    progress_bar.finish_and_clear();
    Ok(())
}

fn read_file_to_tpks(
    reader: impl Read + Send + Sync,
    callback: &mut impl FnMut(Vec<Packet>),
) -> Result<()> {
    let mut ppr = PacketParser::from_reader(reader)?;
    let mut acc = Vec::new();

    // Iterate over all packets.
    while let PacketParserResult::Some(pp) = ppr {
        // Get the packet and advance the parser.
        let (packet, tmp) = pp.next()?;
        ppr = tmp;

        if !acc.is_empty() {
            if let Packet::PublicKey(_) | Packet::SecretKey(_) = packet {
                callback(acc);
                acc = vec![];
            }
        }

        acc.push(packet);
    }

    Ok(())
}

fn import_key(db: &KeyDatabase, packets: Vec<Packet>) -> Result<ImportResult> {
    openpgp::Cert::from_packets(packets.into_iter()).and_then(|tpk| db.merge(tpk))
}

/*
#[cfg(test)]
mod import_tests {
    use std::fs::File;
    use tempfile::tempdir;
    use openpgp::serialize::Serialize;
    use super::*;

    #[test]
    fn import() {
        let root = tempdir().unwrap();

        let db = KeyDatabase::new_from_base(root.path().to_path_buf()).unwrap();

        // Generate a key and import it.
        let (tpk, _) = openpgp::tpk::TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com".into()))
            .generate().unwrap();
        let import_me = root.path().join("import-me");
        tpk.serialize(&mut File::create(&import_me).unwrap()).unwrap();

        do_import(root.path().to_path_buf(), vec![import_me]).unwrap();

        let check = |query: &str| {
            let tpk_ = db.lookup(&query.parse().unwrap()).unwrap().unwrap();
            assert_eq!(tpk.fingerprint(), tpk_.fingerprint());
            assert_eq!(tpk.subkeys().map(|skb| skb.subkey().fingerprint())
                       .collect::<Vec<_>>(),
                       tpk_.subkeys().map(|skb| skb.subkey().fingerprint())
                       .collect::<Vec<_>>());
            assert_eq!(tpk_.userids().count(), 0);
        };

        check(&format!("{}", tpk.primary().fingerprint()));
        check(&format!("{}", tpk.primary().fingerprint().to_keyid()));
        check(&format!("{}", tpk.subkeys().nth(0).unwrap().subkey()
                       .fingerprint()));
        check(&format!("{}", tpk.subkeys().nth(0).unwrap().subkey()
                       .fingerprint().to_keyid()));
    }
}
*/
