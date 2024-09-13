use std::fs::{create_dir_all, remove_file, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str;

use anyhow::Result;
use log::info;

pub struct StatefulTokens {
    token_dir: PathBuf,
}

impl StatefulTokens {
    pub fn new(token_dir: impl Into<PathBuf>) -> Result<Self> {
        let token_dir = token_dir.into();
        create_dir_all(&token_dir)?;

        info!("Opened stateful token store");
        info!("token_dir: '{}'", token_dir.display());

        Ok(StatefulTokens { token_dir })
    }

    pub fn new_token(&self, token_type: &str, payload: &[u8]) -> Result<String> {
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();
        // samples from [a-zA-Z0-9]
        // 43 chars ~ 256 bit
        let name: String = rng.sample_iter(&Alphanumeric).take(43).collect();
        let dir = self.token_dir.join(token_type);
        create_dir_all(&dir)?;

        let mut fd = File::create(dir.join(&name))?;
        fd.write_all(payload)?;

        Ok(name)
    }

    pub fn pop_token(&self, token_type: &str, token: &str) -> Result<String> {
        let path = self.token_dir.join(token_type).join(token);
        let buf = {
            let mut fd = File::open(&path)?;
            let mut buf = Vec::default();

            fd.read_to_end(&mut buf)?;
            buf.into_boxed_slice()
        };

        remove_file(path)?;

        Ok(str::from_utf8(&buf)?.to_string())
    }
}

