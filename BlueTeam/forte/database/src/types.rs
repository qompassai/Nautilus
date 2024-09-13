use std::convert::TryFrom;
use std::fmt;
use std::result;
use std::str::FromStr;

use anyhow::Error;
use crate::openpgp::packet::UserID;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use Result;

/// Holds a normalized email address.
///
/// Email addresses should be normalized as follows:
///
///  - Convert to UTF-8 and ignore user ids that are not valid UTF-8
///  - Do puny code normalization
///  - Lower-case the whole thing using the empty locale
///
/// See https://autocrypt.org/level1.html#e-mail-address-canonicalization
#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Email(String);

impl Email {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&UserID> for Email {
    type Error = Error;

    fn try_from(uid: &UserID) -> Result<Self> {
        if let Some(address) = uid.email()? {
            let mut iter = address.split('@');
            let localpart = iter.next().expect("Invalid email address");
            let domain = iter.next().expect("Invalid email address");
            assert!(iter.next().is_none(), "Invalid email address");

            // Normalize Unicode in domains.
            let domain = idna::domain_to_ascii(domain)
                .map_err(|e| anyhow!("punycode conversion failed: {:?}", e))?;

            // TODO this is a hotfix for a lettre vulnerability. remove once fixed upstream.
            if localpart.starts_with('-') {
                return Err(anyhow!("malformed email address: '{:?}'", uid.value()));
            }

            // Join.
            let address = format!("{}@{}", localpart, domain);

            // Convert to lowercase without tailoring, i.e. without taking
            // any locale into account.  See:
            //
            //  - https://www.w3.org/International/wiki/Case_folding
            //  - https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
            //  - http://www.unicode.org/versions/Unicode7.0.0/ch03.pdf#G33992
            let address = address.to_lowercase();

            Ok(Email(address))
        } else {
            Err(anyhow!("malformed email address: '{:?}'", uid.value()))
        }
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Email {
    type Err = Error;

    fn from_str(s: &str) -> Result<Email> {
        Email::try_from(&UserID::from(s))
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Fingerprint([u8; 20]);

impl TryFrom<sequoia_openpgp::Fingerprint> for Fingerprint {
    type Error = Error;

    fn try_from(fpr: sequoia_openpgp::Fingerprint) -> Result<Self> {
        match fpr {
            sequoia_openpgp::Fingerprint::V4(a) => Ok(Fingerprint(a)),
            sequoia_openpgp::Fingerprint::Invalid(_) => Err(anyhow!("invalid fingerprint")),
            _ => Err(anyhow!("unknown fingerprint type")),
        }
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use hex::ToHex;
        self.0.write_hex_upper(f)
    }
}

impl Serialize for Fingerprint {
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer).and_then(|string| {
            Self::from_str(&string).map_err(|err| Error::custom(err.to_string()))
        })
    }
}

impl FromStr for Fingerprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Fingerprint> {
        match sequoia_openpgp::Fingerprint::from_hex(s)? {
            sequoia_openpgp::Fingerprint::V4(a) => Ok(Fingerprint(a)),
            sequoia_openpgp::Fingerprint::Invalid(_) => {
                Err(anyhow!("'{}' is not a valid fingerprint", s))
            }
            _ => Err(anyhow!("unknown fingerprint type")),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct KeyID([u8; 8]);

impl TryFrom<sequoia_openpgp::Fingerprint> for KeyID {
    type Error = Error;

    fn try_from(fpr: sequoia_openpgp::Fingerprint) -> Result<Self> {
        match fpr {
            sequoia_openpgp::Fingerprint::V4(a) => Ok(Fingerprint(a).into()),
            sequoia_openpgp::Fingerprint::Invalid(_) => Err(anyhow!("invalid fingerprint")),
            _ => Err(anyhow!("unknown fingerprint type")),
        }
    }
}

impl From<&Fingerprint> for KeyID {
    fn from(fpr: &Fingerprint) -> KeyID {
        let mut arr = [0u8; 8];

        arr.copy_from_slice(&fpr.0[12..20]);
        KeyID(arr)
    }
}

impl From<Fingerprint> for KeyID {
    fn from(fpr: Fingerprint) -> KeyID {
        let mut arr = [0u8; 8];

        arr.copy_from_slice(&fpr.0[12..20]);
        KeyID(arr)
    }
}

impl fmt::Display for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use hex::ToHex;
        self.0.write_hex_upper(f)
    }
}

impl FromStr for KeyID {
    type Err = Error;

    fn from_str(s: &str) -> Result<KeyID> {
        match sequoia_openpgp::KeyID::from_hex(s)? {
            sequoia_openpgp::KeyID::V4(a) => Ok(KeyID(a)),
            sequoia_openpgp::KeyID::Invalid(_) => {
                Err(anyhow!("'{}' is not a valid long key ID", s))
            }
            _ => Err(anyhow!("unknown keyid type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email() {
        let c = |s| Email::from_str(s).unwrap();
        assert_eq!(c("foo@example.org").as_str(), "foo@example.org");
        assert_eq!(c("<foo@example.org>").as_str(), "foo@example.org");
        assert_eq!(c("Foo <foo@example.org>").as_str(), "foo@example.org");
        assert_eq!(c("Foo Bar <foo@example.org>").as_str(), "foo@example.org");
        // FIXME gotta fix this
        // assert_eq!(c("foo@example.org <foo@example.org>").as_str(), "foo@example.org");
        assert_eq!(
            c("\"Foo Bar\" <foo@example.org>").as_str(),
            "foo@example.org"
        );
        assert_eq!(c("foo@👍.example.org").as_str(), "foo@xn--yp8h.example.org");
        assert_eq!(c("Foo@example.org").as_str(), "foo@example.org");
        assert_eq!(c("foo@EXAMPLE.ORG").as_str(), "foo@example.org");
    }

    #[test]
    fn email_vuln() {
        assert!(Email::from_str("foo <-@EXAMPLE.ORG>").is_err());
        assert!(Email::from_str("-@EXAMPLE.ORG").is_err());
    }
}
