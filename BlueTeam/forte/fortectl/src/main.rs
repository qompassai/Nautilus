extern crate anyhow;
extern crate clap;
extern crate hagrid_database as database;
extern crate sequoia_openpgp as openpgp;
extern crate tempfile;
#[macro_use]
extern crate serde_derive;
extern crate indicatif;
extern crate toml;
extern crate walkdir;

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;

use clap::{App, Arg, SubCommand};

mod import;
mod regenerate;

#[derive(Deserialize)]
pub struct HagridConfigs {
    debug: HagridConfig,
    staging: HagridConfig,
    release: HagridConfig,
}

// this is not an exact match - Rocket config has more complicated semantics
// than a plain toml file.
// see also https://github.com/SergioBenitez/Rocket/issues/228
#[derive(Deserialize, Clone)]
pub struct HagridConfig {
    _template_dir: Option<PathBuf>,
    keys_internal_dir: Option<PathBuf>,
    keys_external_dir: Option<PathBuf>,
    _assets_dir: Option<PathBuf>,
    _token_dir: Option<PathBuf>,
    tmp_dir: Option<PathBuf>,
    _maintenance_file: Option<PathBuf>,
}

fn main() -> Result<()> {
    let matches = App::new("Hagrid Control")
        .version("0.1")
        .about("Control hagrid database externally")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("env")
                .short("e")
                .long("env")
                .value_name("ENVIRONMENT")
                .takes_value(true)
                .default_value("prod")
                .possible_values(&["dev", "stage", "prod"]),
        )
        .subcommand(SubCommand::with_name("regenerate").about("Regenerate symlink directory"))
        .subcommand(
            SubCommand::with_name("import")
                .about("Import keys into Hagrid")
                .arg(
                    Arg::with_name("dry run")
                        .short("n")
                        .long("dry-run")
                        .help("don't actually keep imported keys"),
                )
                .arg(
                    Arg::with_name("keyring files")
                        .required(true)
                        .multiple(true),
                ),
        )
        .get_matches();

    let config_file = matches.value_of("config").unwrap_or("Rocket.toml");
    let config_data = fs::read_to_string(config_file).unwrap();
    let configs: HagridConfigs = toml::from_str(&config_data).unwrap();
    let config = match matches.value_of("env").unwrap() {
        "dev" => configs.debug,
        "stage" => configs.staging,
        "prod" => configs.release,
        _ => configs.debug,
    };

    if let Some(matches) = matches.subcommand_matches("import") {
        let dry_run = matches.occurrences_of("dry run") > 0;
        let keyrings: Vec<PathBuf> = matches
            .values_of_lossy("keyring files")
            .unwrap()
            .iter()
            .map(|arg| PathBuf::from_str(arg).unwrap())
            .collect();
        import::do_import(&config, dry_run, keyrings)?;
    } else if let Some(_matches) = matches.subcommand_matches("regenerate") {
        regenerate::do_regenerate(&config)?;
    } else {
        println!("{}", matches.usage());
    }

    Ok(())
}
