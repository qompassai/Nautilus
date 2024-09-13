use ring::aead::{open_in_place, seal_in_place, Algorithm, AES_256_GCM};
use ring::aead::{OpeningKey, SealingKey};
use ring::digest;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

// Keep these in sync, and keep the key len synced with the `private` docs as
// well as the `KEYS_INFO` const in secure::Key.
static ALGO: &Algorithm = &AES_256_GCM;
const NONCE_LEN: usize = 12;

pub struct SealedState {
    sealing_key: SealingKey,
    opening_key: OpeningKey,
}

impl SealedState {
    pub fn new(secret: &str) -> Self {
        let salt = hmac::SigningKey::new(&digest::SHA256, b"hagrid");
        let mut key = vec![0; 32];
        ring::hkdf::extract_and_expand(&salt, secret.as_bytes(), b"", &mut key);

        let sealing_key = SealingKey::new(ALGO, key.as_ref()).expect("sealing key creation");
        let opening_key = OpeningKey::new(ALGO, key.as_ref()).expect("sealing key creation");

        SealedState {
            sealing_key,
            opening_key,
        }
    }

    pub fn unseal(&self, mut data: Vec<u8>) -> Result<String, &'static str> {
        let (nonce, sealed) = data.split_at_mut(NONCE_LEN);
        let unsealed = open_in_place(&self.opening_key, nonce, &[], 0, sealed)
            .map_err(|_| "invalid key/nonce/value: bad seal")?;

        ::std::str::from_utf8(unsealed)
            .map(|s| s.to_string())
            .map_err(|_| "bad unsealed utf8")
    }

    pub fn seal(&self, input: &str) -> Vec<u8> {
        let mut data;
        let output_len = {
            let overhead = ALGO.tag_len();
            data = vec![0; NONCE_LEN + input.len() + overhead];

            let (nonce, in_out) = data.split_at_mut(NONCE_LEN);
            SystemRandom::new()
                .fill(nonce)
                .expect("couldn't random fill nonce");
            in_out[..input.len()].copy_from_slice(input.as_bytes());

            seal_in_place(&self.sealing_key, nonce, &[], in_out, overhead).expect("in-place seal")
        };

        data[..(NONCE_LEN + output_len)].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let sv = SealedState::new("swag");

        let sealed = sv.seal("test");
        let unsealed = sv.unseal(sealed).unwrap();

        assert_eq!("test", unsealed);
    }
}
