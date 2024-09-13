use crate::sealed_state::SealedState;

use crate::Result;
use serde::{de::DeserializeOwned, Serialize};

pub trait StatelessSerializable: Serialize + DeserializeOwned {}

pub struct Service {
    sealed_state: SealedState,
    validity: u64,
}

#[derive(Serialize, Deserialize)]
struct Token {
    #[serde(rename = "c")]
    creation: u64,
    #[serde(rename = "p")]
    payload: String,
}

impl Service {
    pub fn init(secret: &str, validity: u64) -> Self {
        let sealed_state = SealedState::new(secret);
        Service {
            sealed_state,
            validity,
        }
    }

    pub fn create(&self, payload_content: &impl StatelessSerializable) -> String {
        let payload = serde_json::to_string(payload_content).unwrap();
        let creation = current_time();
        let token = Token { creation, payload };
        let token_serialized = serde_json::to_string(&token).unwrap();

        let token_sealed = self.sealed_state.seal(&token_serialized);

        base64::encode_config(&token_sealed, base64::URL_SAFE_NO_PAD)
    }

    pub fn check<T>(&self, token_encoded: &str) -> Result<T>
    where
        T: StatelessSerializable,
    {
        let token_sealed = base64::decode_config(&token_encoded, base64::URL_SAFE_NO_PAD)
            .map_err(|_| anyhow!("invalid b64"))?;
        let token_str = self
            .sealed_state
            .unseal(token_sealed)
            .map_err(|_| anyhow!("failed to validate"))?;
        let token: Token =
            serde_json::from_str(&token_str).map_err(|_| anyhow!("failed to deserialize"))?;

        let elapsed = current_time() - token.creation;
        if elapsed > self.validity {
            return Err(anyhow!("Token has expired!"));
        }

        let payload: T = serde_json::from_str(&token.payload)
            .map_err(|_| anyhow!("failed to deserialize payload"))?;

        Ok(payload)
    }
}

#[cfg(not(test))]
fn current_time() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
fn current_time() -> u64 {
    12345678
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
    struct TestStruct1 {
        payload: String,
    }
    impl StatelessSerializable for TestStruct1 {}

    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
    struct TestStruct2 {
        something: String,
    }
    impl StatelessSerializable for TestStruct2 {}

    #[test]
    fn test_create_check() {
        let payload = TestStruct1 {
            payload: "hello".to_owned(),
        };
        let mt = Service::init("secret", 60);
        let token = mt.create(&payload);
        // println!("{}", &token);
        // assert!(false);

        let check_result = mt.check(&token);

        assert_eq!(payload, check_result.unwrap());
    }

    #[test]
    fn test_ok() {
        let payload = TestStruct1 {
            payload: "hello".to_owned(),
        };
        let token = "rwM_S9gZaRQaf6DLvmWtZSipQhH_G5ronSIJv2FrMdwGBPSYYQ-1jaP58dTHU5WuC14vb8jxmz2Xf_b3pqzpCGTEJj9drm4t";
        let mt = Service::init("secret", 60);

        let check_result = mt.check(token);

        assert_eq!(payload, check_result.unwrap());
    }

    #[test]
    fn test_bad_type() {
        let payload = TestStruct1 {
            payload: "hello".to_owned(),
        };
        let mt = Service::init("secret", 60);

        let token = mt.create(&payload);
        let check_result = mt.check::<TestStruct2>(&token);

        assert!(check_result.is_err());
    }

    #[test]
    fn test_expired() {
        // {"c":12345078,"f":"D4AB192964F76A7F8F8A9B357BD18320DEADFA11"}
        let token = "tqDOpM5mdNSTCDzyyy6El_Chpj1k-ozzw4AHy-3KJhxkXs8A17GJYVq7CHbgsYMc7n5irdzOJ-IvForV_HiVSnZYpnS_BiORWN6FISVmnwlMxDBIGUqa1XDiBLD7UW8";
        let mt = Service::init("secret", 60);

        let check_result = mt.check::<TestStruct1>(token);

        assert!(check_result.is_err());
    }
}
