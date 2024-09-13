use anyhow::anyhow;
use super::Result;
use crate::openpgp::types::HashAlgorithm;
use zbase32;

// cannibalized from
// https://gitlab.com/sequoia-pgp/sequoia/blob/master/net/src/wkd.rs

pub fn encode_wkd(address: impl AsRef<str>) -> Result<(String, String)> {
    let (local_part, domain) = split_address(address)?;

    let local_part_encoded = encode_local_part(local_part);

    Ok((local_part_encoded, domain))
}

fn split_address(email_address: impl AsRef<str>) -> Result<(String, String)> {
    let email_address = email_address.as_ref();
    let v: Vec<&str> = email_address.split('@').collect();
    if v.len() != 2 {
        return Err(anyhow!("Malformed email address".to_owned()));
    };

    // Convert to lowercase without tailoring, i.e. without taking any
    // locale into account. See:
    // https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
    let local_part = v[0].to_lowercase();
    let domain = v[1].to_lowercase();

    Ok((local_part, domain))
}

fn encode_local_part<S: AsRef<str>>(local_part: S) -> String {
    let local_part = local_part.as_ref();

    let mut digest = vec![0; 20];
    let mut ctx = HashAlgorithm::SHA1.context().expect("must be implemented");
    ctx.update(local_part.as_bytes());
    let _ = ctx.digest(&mut digest);

    // After z-base-32 encoding 20 bytes, it will be 32 bytes long.
    zbase32::encode_full_bytes(&digest[..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_local_part_succed() {
        let encoded_part = encode_local_part("test1");
        assert_eq!("stnkabub89rpcphiz4ppbxixkwyt1pic", encoded_part);
        assert_eq!(32, encoded_part.len());
    }

    #[test]
    fn email_address_from() {
        let (local_part, domain) = split_address("test1@example.com").unwrap();
        assert_eq!(local_part, "test1");
        assert_eq!(domain, "example.com");
    }
}
