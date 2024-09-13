use anyhow::Result;

use std::path::Path;
use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

use database::types::Fingerprint;
use database::{Database, KeyDatabase, RegenerateResult};
use HagridConfig;

struct RegenerateStats<'a> {
    progress: &'a ProgressBar,
    prefix: String,
    count_total: u64,
    count_err: u64,
    count_updated: u64,
    count_unchanged: u64,
    count_partial: u64,
    start_time_partial: Instant,
    kps_partial: u64,
}

impl<'a> RegenerateStats<'a> {
    fn new(progress: &'a ProgressBar) -> Self {
        Self {
            progress,
            prefix: "".to_owned(),
            count_total: 0,
            count_err: 0,
            count_updated: 0,
            count_unchanged: 0,
            count_partial: 0,
            start_time_partial: Instant::now(),
            kps_partial: 0,
        }
    }

    fn update(&mut self, result: Result<RegenerateResult>, fpr: Fingerprint) {
        // If a new TPK starts, parse and import.
        self.count_total += 1;
        self.count_partial += 1;
        if (self.count_total % 10) == 0 {
            self.prefix = fpr.to_string()[0..4].to_owned();
        }
        match result {
            Err(e) => {
                self.progress.println(format!("{}: {}", fpr, e));
                self.count_err += 1;
            }
            Ok(RegenerateResult::Updated) => self.count_updated += 1,
            Ok(RegenerateResult::Unchanged) => self.count_unchanged += 1,
        }
        self.progress_update();
    }

    fn progress_update(&mut self) {
        if (self.count_total % 10) != 0 {
            return;
        }
        if self.count_partial >= 1000 {
            let runtime = (self.start_time_partial.elapsed().as_millis() + 1) as u64;
            self.kps_partial = (self.count_partial * 1000) / runtime;
            self.start_time_partial = Instant::now();
            self.count_partial = 0;
        }
        self.progress.set_message(&format!(
                "prefix {} regenerated {:5} keys, {:5} Updated {:5} Unchanged {:5} Errors ({:3} keys/s)",
                self.prefix, self.count_total, self.count_updated, self.count_unchanged, self.count_err, self.kps_partial));
    }
}

pub fn do_regenerate(config: &HagridConfig) -> Result<()> {
    let db = KeyDatabase::new_internal(
        config.keys_internal_dir.as_ref().unwrap(),
        config.keys_external_dir.as_ref().unwrap(),
        config.tmp_dir.as_ref().unwrap(),
        false,
    )?;

    let published_dir = config
        .keys_external_dir
        .as_ref()
        .unwrap()
        .join("links")
        .join("by-email");
    let dirs: Vec<_> = WalkDir::new(published_dir)
        .min_depth(1)
        .max_depth(1)
        .sort_by(|a, b| a.file_name().cmp(b.file_name()))
        .into_iter()
        .flatten()
        .map(|entry| entry.into_path())
        .collect();

    let progress_bar = ProgressBar::new(dirs.len() as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {msg}")
            .progress_chars("##-"),
    );

    let mut stats = RegenerateStats::new(&progress_bar);

    for dir in dirs {
        progress_bar.inc(1);
        regenerate_dir_recursively(&db, &mut stats, &dir)?;
    }
    progress_bar.finish();

    Ok(())
}

fn regenerate_dir_recursively(
    db: &KeyDatabase,
    stats: &mut RegenerateStats,
    dir: &Path,
) -> Result<()> {
    for path in WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|entry| entry.into_path())
    {
        let fpr = KeyDatabase::path_to_primary(&path).unwrap();
        let result = db.regenerate_links(&fpr);
        stats.update(result, fpr);
    }

    Ok(())
}
