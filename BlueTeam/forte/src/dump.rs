use std::io::{self, Read};

use self::openpgp::crypto::mpi;
use self::openpgp::crypto::{SessionKey, S2K};
use self::openpgp::fmt::hex;
use self::openpgp::packet::header::CTB;
use self::openpgp::packet::prelude::*;
use self::openpgp::packet::signature::subpacket::{Subpacket, SubpacketValue};
use self::openpgp::packet::{header::BodyLength, Header, Signature};
use self::openpgp::parse::{map::Map, PacketParserResult, Parse};
use self::openpgp::types::{Duration, SymmetricAlgorithm, Timestamp};
use self::openpgp::{Packet, Result};
use sequoia_openpgp as openpgp;

#[derive(Debug)]
pub enum Kind {
    Message { encrypted: bool },
    Keyring,
    Cert,
    Unknown,
}

/// Converts sequoia_openpgp types for rendering.
pub trait Convert<T> {
    /// Performs the conversion.
    fn convert(self) -> T;
}

impl Convert<chrono::Duration> for std::time::Duration {
    fn convert(self) -> chrono::Duration {
        chrono::Duration::seconds(self.as_secs() as i64)
    }
}

impl Convert<chrono::Duration> for Duration {
    fn convert(self) -> chrono::Duration {
        chrono::Duration::seconds(self.as_secs() as i64)
    }
}

impl Convert<chrono::DateTime<chrono::offset::Utc>> for std::time::SystemTime {
    fn convert(self) -> chrono::DateTime<chrono::offset::Utc> {
        chrono::DateTime::<chrono::offset::Utc>::from(self)
    }
}

impl Convert<chrono::DateTime<chrono::offset::Utc>> for Timestamp {
    fn convert(self) -> chrono::DateTime<chrono::offset::Utc> {
        std::time::SystemTime::from(self).convert()
    }
}

#[allow(clippy::redundant_pattern_matching)]
pub fn dump<W>(
    input: &mut (dyn io::Read + Sync + Send),
    output: &mut dyn io::Write,
    mpis: bool,
    hex: bool,
    sk: Option<&SessionKey>,
    width: W,
) -> Result<Kind>
where
    W: Into<Option<usize>>,
{
    let mut ppr = self::openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(hex)
        .build()?;
    let mut message_encrypted = false;
    let width = width.into().unwrap_or(80);
    let mut dumper = PacketDumper::new(width, mpis);

    while let PacketParserResult::Some(mut pp) = ppr {
        let additional_fields = match pp.packet {
            Packet::Literal(_) => {
                let mut prefix = vec![0; 40];
                let n = pp.read(&mut prefix)?;
                Some(vec![format!(
                    "Content: {:?}{}",
                    String::from_utf8_lossy(&prefix[..n]),
                    if n == prefix.len() { "..." } else { "" }
                )])
            }
            Packet::SEIP(_) if sk.is_none() => {
                message_encrypted = true;
                Some(vec!["No session key supplied".into()])
            }
            Packet::SEIP(_) if sk.is_some() => {
                message_encrypted = true;
                let sk = sk.as_ref().unwrap();
                let mut decrypted_with = None;
                for algo in 1..20 {
                    let algo = SymmetricAlgorithm::from(algo);
                    if let Ok(size) = algo.key_size() {
                        if size != sk.len() {
                            continue;
                        }
                    } else {
                        continue;
                    }

                    if let Ok(_) = pp.decrypt(algo, sk) {
                        decrypted_with = Some(algo);
                        break;
                    }
                }
                let mut fields = Vec::new();
                fields.push(format!("Session key: {}", hex::encode(sk)));
                if let Some(algo) = decrypted_with {
                    fields.push(format!("Symmetric algo: {}", algo));
                    fields.push("Decryption successful".into());
                } else {
                    fields.push("Decryption failed".into());
                }
                Some(fields)
            }
            Packet::AED(_) if sk.is_none() => {
                message_encrypted = true;
                Some(vec!["No session key supplied".into()])
            }
            Packet::AED(_) if sk.is_some() => {
                message_encrypted = true;
                let sk = sk.as_ref().unwrap();
                let algo = if let Packet::AED(ref aed) = pp.packet {
                    aed.symmetric_algo()
                } else {
                    unreachable!()
                };

                let _ = pp.decrypt(algo, sk);

                let mut fields = Vec::new();
                fields.push(format!("Session key: {}", hex::encode(sk)));
                if pp.encrypted() {
                    fields.push("Decryption failed".into());
                } else {
                    fields.push("Decryption successful".into());
                }
                Some(fields)
            }
            _ => None,
        };

        let header = pp.header().clone();
        let map = pp.take_map();

        let recursion_depth = pp.recursion_depth();
        let packet = pp.packet.clone();

        dumper.packet(
            output,
            recursion_depth as usize,
            header,
            packet,
            map,
            additional_fields,
        )?;

        let (_, ppr_) = match pp.recurse() {
            Ok(v) => Ok(v),
            Err(e) => {
                let _ = dumper.flush(output);
                Err(e)
            }
        }?;
        ppr = ppr_;
    }

    dumper.flush(output)?;

    if let PacketParserResult::EOF(eof) = ppr {
        if eof.is_message().is_ok() {
            Ok(Kind::Message {
                encrypted: message_encrypted,
            })
        } else if eof.is_cert().is_ok() {
            Ok(Kind::Cert)
        } else if eof.is_keyring().is_ok() {
            Ok(Kind::Keyring)
        } else {
            Ok(Kind::Unknown)
        }
    } else {
        unreachable!()
    }
}

struct Node {
    header: Header,
    packet: Packet,
    map: Option<Map>,
    additional_fields: Option<Vec<String>>,
    children: Vec<Node>,
}

impl Node {
    fn new(
        header: Header,
        packet: Packet,
        map: Option<Map>,
        additional_fields: Option<Vec<String>>,
    ) -> Self {
        Node {
            header,
            packet,
            map,
            additional_fields,
            children: Vec::new(),
        }
    }

    fn append(&mut self, depth: usize, node: Node) {
        if depth == 0 {
            self.children.push(node);
        } else {
            self.children
                .iter_mut()
                .last()
                .unwrap()
                .append(depth - 1, node);
        }
    }
}

pub struct PacketDumper {
    width: usize,
    mpis: bool,
    root: Option<Node>,
}

impl PacketDumper {
    pub fn new(width: usize, mpis: bool) -> Self {
        PacketDumper {
            width,
            mpis,
            root: None,
        }
    }

    pub fn packet(
        &mut self,
        output: &mut dyn io::Write,
        depth: usize,
        header: Header,
        p: Packet,
        map: Option<Map>,
        additional_fields: Option<Vec<String>>,
    ) -> Result<()> {
        let node = Node::new(header, p, map, additional_fields);
        if self.root.is_none() {
            assert_eq!(depth, 0);
            self.root = Some(node);
        } else if depth == 0 {
            let root = self.root.take().unwrap();
            self.dump_tree(output, "", &root)?;
            self.root = Some(node);
        } else {
            self.root.as_mut().unwrap().append(depth - 1, node);
        }
        Ok(())
    }

    pub fn flush(&self, output: &mut dyn io::Write) -> Result<()> {
        if let Some(root) = self.root.as_ref() {
            self.dump_tree(output, "", root)?;
        }
        Ok(())
    }

    fn dump_tree(&self, output: &mut dyn io::Write, indent: &str, node: &Node) -> Result<()> {
        let indent_node = format!(
            "{}{} ",
            indent,
            if node.children.is_empty() { " " } else { "│" }
        );
        self.dump_packet(
            output,
            &indent_node,
            Some(&node.header),
            &node.packet,
            node.map.as_ref(),
            node.additional_fields.as_ref(),
        )?;
        if node.children.is_empty() {
            return Ok(());
        }

        let last = node.children.len() - 1;
        for (i, child) in node.children.iter().enumerate() {
            let is_last = i == last;
            write!(output, "{}{}── ", indent, if is_last { "└" } else { "├" })?;
            let indent_child = format!("{}{}   ", indent, if is_last { " " } else { "│" });
            self.dump_tree(output, &indent_child, child)?;
        }
        Ok(())
    }

    fn dump_packet(
        &self,
        mut output: &mut dyn io::Write,
        i: &str,
        header: Option<&Header>,
        p: &Packet,
        map: Option<&Map>,
        additional_fields: Option<&Vec<String>>,
    ) -> Result<()> {
        use self::openpgp::Packet::*;

        if let Some(tag) = p.kind() {
            write!(output, "{}", tag)?;
        } else {
            write!(output, "Unknown or Unsupported Packet")?;
        }

        if let Some(h) = header {
            write!(
                output,
                ", {} CTB, {}{}",
                if let CTB::Old(_) = h.ctb() {
                    "old"
                } else {
                    "new"
                },
                if let Some(map) = map {
                    format!(
                        "{} header bytes + ",
                        map.iter()
                            .take(2)
                            .map(|f| f.as_bytes().len())
                            .sum::<usize>()
                    )
                } else {
                    // XXX: Mapping is disabled.  No can do for
                    // now.  Once we save the header in
                    // packet::Common, we can use this instead of
                    // relying on the map.
                    "".into()
                },
                match h.length() {
                    BodyLength::Full(n) => format!("{} bytes", n),
                    BodyLength::Partial(n) => format!("partial length, {} bytes in first chunk", n),
                    BodyLength::Indeterminate => "indeterminate length".into(),
                }
            )?;
        }
        writeln!(output)?;

        fn dump_key<P, R>(
            pd: &PacketDumper,
            output: &mut dyn io::Write,
            i: &str,
            k: &Key<P, R>,
        ) -> Result<()>
        where
            P: key::KeyParts,
            R: key::KeyRole,
        {
            writeln!(output, "{}  Version: {}", i, k.version())?;
            writeln!(
                output,
                "{}  Creation time: {}",
                i,
                k.creation_time().convert()
            )?;
            writeln!(output, "{}  Pk algo: {}", i, k.pk_algo())?;
            if let Some(bits) = k.mpis().bits() {
                writeln!(output, "{}  Pk size: {} bits", i, bits)?;
            }
            writeln!(output, "{}  Fingerprint: {}", i, k.fingerprint())?;
            writeln!(output, "{}  KeyID: {}", i, k.keyid())?;
            if pd.mpis {
                writeln!(output, "{}", i)?;
                writeln!(output, "{}  Public Key:", i)?;

                let ii = format!("{}    ", i);
                match k.mpis() {
                    mpi::PublicKey::RSA { e, n } => {
                        pd.dump_mpis(output, &ii, &[e.value(), n.value()], &["e", "n"])?
                    }
                    mpi::PublicKey::DSA { p, q, g, y } => pd.dump_mpis(
                        output,
                        &ii,
                        &[p.value(), q.value(), g.value(), y.value()],
                        &["p", "q", "g", "y"],
                    )?,
                    mpi::PublicKey::ElGamal { p, g, y } => pd.dump_mpis(
                        output,
                        &ii,
                        &[p.value(), g.value(), y.value()],
                        &["p", "g", "y"],
                    )?,
                    mpi::PublicKey::EdDSA { curve, q } => {
                        writeln!(output, "{}  Curve: {}", ii, curve)?;
                        pd.dump_mpis(output, &ii, &[q.value()], &["q"])?;
                    }
                    mpi::PublicKey::ECDSA { curve, q } => {
                        writeln!(output, "{}  Curve: {}", ii, curve)?;
                        pd.dump_mpis(output, &ii, &[q.value()], &["q"])?;
                    }
                    mpi::PublicKey::ECDH {
                        curve,
                        q,
                        hash,
                        sym,
                    } => {
                        writeln!(output, "{}  Curve: {}", ii, curve)?;
                        writeln!(output, "{}  Hash algo: {}", ii, hash)?;
                        writeln!(output, "{}  Symmetric algo: {}", ii, sym)?;
                        pd.dump_mpis(output, &ii, &[q.value()], &["q"])?;
                    }
                    mpi::PublicKey::Unknown { mpis, rest } => {
                        let keys: Vec<String> =
                            (0..mpis.len()).map(|i| format!("mpi{}", i)).collect();
                        pd.dump_mpis(
                            output,
                            &ii,
                            &mpis
                                .iter()
                                .map(|m| m.value().iter().as_slice())
                                .collect::<Vec<_>>()[..],
                            &keys.iter().map(|k| k.as_str()).collect::<Vec<_>>()[..],
                        )?;

                        pd.dump_mpis(output, &ii, &[&rest[..]], &["rest"])?;
                    }

                    // crypto::mpi:Publickey is non-exhaustive
                    u => writeln!(output, "{}Unknown variant: {:?}", ii, u)?,
                }
            }

            if let Some(secrets) = k.optional_secret() {
                writeln!(output, "{}", i)?;
                writeln!(output, "{}  Secret Key:", i)?;

                let ii = format!("{}    ", i);
                match secrets {
                    SecretKeyMaterial::Unencrypted(ref u) => {
                        writeln!(output, "{}", i)?;
                        writeln!(output, "{}  Unencrypted", ii)?;
                        if pd.mpis {
                            u.map(|mpis| -> Result<()> {
                                match mpis {
                                    mpi::SecretKeyMaterial::RSA { d, p, q, u } => pd.dump_mpis(
                                        output,
                                        &ii,
                                        &[d.value(), p.value(), q.value(), u.value()],
                                        &["d", "p", "q", "u"],
                                    )?,
                                    mpi::SecretKeyMaterial::DSA { x } => {
                                        pd.dump_mpis(output, &ii, &[x.value()], &["x"])?
                                    }
                                    mpi::SecretKeyMaterial::ElGamal { x } => {
                                        pd.dump_mpis(output, &ii, &[x.value()], &["x"])?
                                    }
                                    mpi::SecretKeyMaterial::EdDSA { scalar } => {
                                        pd.dump_mpis(output, &ii, &[scalar.value()], &["scalar"])?
                                    }
                                    mpi::SecretKeyMaterial::ECDSA { scalar } => {
                                        pd.dump_mpis(output, &ii, &[scalar.value()], &["scalar"])?
                                    }
                                    mpi::SecretKeyMaterial::ECDH { scalar } => {
                                        pd.dump_mpis(output, &ii, &[scalar.value()], &["scalar"])?
                                    }
                                    mpi::SecretKeyMaterial::Unknown { mpis, rest } => {
                                        let keys: Vec<String> =
                                            (0..mpis.len()).map(|i| format!("mpi{}", i)).collect();
                                        pd.dump_mpis(
                                            output,
                                            &ii,
                                            &mpis
                                                .iter()
                                                .map(|m| {
                                                    m.value().iter().as_slice()
                                                })
                                                .collect::<Vec<_>>()[..],
                                            &keys
                                                .iter()
                                                .map(|k| k.as_str())
                                                .collect::<Vec<_>>()[..],
                                        )?;

                                        pd.dump_mpis(output, &ii, &[rest], &["rest"])?;
                                    }

                                    // crypto::mpi::SecretKeyMaterial is non-exhaustive.
                                    u => writeln!(output, "{}Unknown variant: {:?}", ii, u)?,
                                }
                                Ok(())
                            })?;
                        }
                    }
                    SecretKeyMaterial::Encrypted(ref e) => {
                        writeln!(output, "{}", i)?;
                        writeln!(output, "{}  Encrypted", ii)?;
                        write!(output, "{}  S2K: ", ii)?;
                        pd.dump_s2k(output, &ii, e.s2k())?;
                        writeln!(output, "{}  Sym. algo: {}", ii, e.algo())?;
                        if pd.mpis {
                            if let Ok(ciphertext) = e.ciphertext() {
                                pd.dump_mpis(output, &ii, &[ciphertext], &["ciphertext"])?;
                            }
                        }
                    }
                }
            }

            Ok(())
        }

        match p {
            Unknown(ref u) => {
                writeln!(output, "{}  Tag: {}", i, u.tag())?;
                writeln!(output, "{}  Error: {}", i, u.error())?;
            }

            PublicKey(ref k) => dump_key(self, output, i, k)?,
            PublicSubkey(ref k) => dump_key(self, output, i, k)?,
            SecretKey(ref k) => dump_key(self, output, i, k)?,
            SecretSubkey(ref k) => dump_key(self, output, i, k)?,

            Signature(ref s) => {
                writeln!(output, "{}  Version: {}", i, s.version())?;
                writeln!(output, "{}  Type: {}", i, s.typ())?;
                writeln!(output, "{}  Pk algo: {}", i, s.pk_algo())?;
                writeln!(output, "{}  Hash algo: {}", i, s.hash_algo())?;
                if s.hashed_area().iter().count() > 0 {
                    writeln!(output, "{}  Hashed area:", i)?;
                    for pkt in s.hashed_area().iter() {
                        self.dump_subpacket(output, i, pkt, s)?;
                    }
                }
                if s.unhashed_area().iter().count() > 0 {
                    writeln!(output, "{}  Unhashed area:", i)?;
                    for pkt in s.unhashed_area().iter() {
                        self.dump_subpacket(output, i, pkt, s)?;
                    }
                }
                writeln!(
                    output,
                    "{}  Digest prefix: {}",
                    i,
                    hex::encode(s.digest_prefix())
                )?;
                write!(output, "{}  Level: {} ", i, s.level())?;
                match s.level() {
                    0 => writeln!(output, "(signature over data)")?,
                    1 => writeln!(
                        output,
                        "(notarization over signatures \
                                           level 0 and data)"
                    )?,
                    n => writeln!(
                        output,
                        "(notarization over signatures \
                                           level <= {} and data)",
                        n - 1
                    )?,
                }
                if self.mpis {
                    writeln!(output, "{}", i)?;
                    writeln!(output, "{}  Signature:", i)?;

                    let ii = format!("{}    ", i);
                    match s.mpis() {
                        mpi::Signature::RSA { s } => {
                            self.dump_mpis(output, &ii, &[s.value()], &["s"])?
                        }
                        mpi::Signature::DSA { r, s } => {
                            self.dump_mpis(output, &ii, &[r.value(), s.value()], &["r", "s"])?
                        }
                        mpi::Signature::ElGamal { r, s } => {
                            self.dump_mpis(output, &ii, &[r.value(), s.value()], &["r", "s"])?
                        }
                        mpi::Signature::EdDSA { r, s } => {
                            self.dump_mpis(output, &ii, &[r.value(), s.value()], &["r", "s"])?
                        }
                        mpi::Signature::ECDSA { r, s } => {
                            self.dump_mpis(output, &ii, &[r.value(), s.value()], &["r", "s"])?
                        }
                        mpi::Signature::Unknown { mpis, rest } => {
                            let keys: Vec<String> =
                                (0..mpis.len()).map(|i| format!("mpi{}", i)).collect();
                            self.dump_mpis(
                                output,
                                &ii,
                                &mpis
                                    .iter()
                                    .map(|m| m.value().iter().as_slice())
                                    .collect::<Vec<_>>()[..],
                                &keys.iter().map(|k| k.as_str()).collect::<Vec<_>>()[..],
                            )?;

                            self.dump_mpis(output, &ii, &[&rest[..]], &["rest"])?;
                        }

                        // crypto::mpi::Signature is non-exhaustive.
                        u => writeln!(output, "{}Unknown variant: {:?}", ii, u)?,
                    }
                }
            }

            OnePassSig(ref o) => {
                writeln!(output, "{}  Version: {}", i, o.version())?;
                writeln!(output, "{}  Type: {}", i, o.typ())?;
                writeln!(output, "{}  Pk algo: {}", i, o.pk_algo())?;
                writeln!(output, "{}  Hash algo: {}", i, o.hash_algo())?;
                writeln!(output, "{}  Issuer: {}", i, o.issuer())?;
                writeln!(output, "{}  Last: {}", i, o.last())?;
            }

            Trust(ref p) => {
                writeln!(output, "{}  Value:", i)?;
                let mut hd = hex::Dumper::new(
                    &mut output,
                    self.indentation_for_hexdump(&format!("{}  ", i), 16),
                );
                hd.write_ascii(p.value())?;
            }

            UserID(ref u) => {
                writeln!(
                    output,
                    "{}  Value: {}",
                    i,
                    String::from_utf8_lossy(u.value())
                )?;
            }

            UserAttribute(ref u) => {
                use self::openpgp::packet::user_attribute::{Image, Subpacket};

                for subpacket in u.subpackets() {
                    match subpacket {
                        Ok(Subpacket::Image(image)) => match image {
                            Image::JPEG(data) => {
                                writeln!(output, "{}    JPEG: {} bytes", i, data.len())?
                            }
                            Image::Private(n, data) => writeln!(
                                output,
                                "{}    Private image({}): {} bytes",
                                i,
                                n,
                                data.len()
                            )?,
                            Image::Unknown(n, data) => writeln!(
                                output,
                                "{}    Unknown image({}): {} bytes",
                                i,
                                n,
                                data.len()
                            )?,
                        },
                        Ok(Subpacket::Unknown(n, data)) => writeln!(
                            output,
                            "{}    Unknown subpacket({}): {} bytes",
                            i,
                            n,
                            data.len()
                        )?,
                        Err(e) => writeln!(output, "{}    Invalid subpacket encoding: {}", i, e)?,
                    }
                }
            }

            Marker(_) => {}

            Literal(ref l) => {
                writeln!(output, "{}  Format: {}", i, l.format())?;
                if let Some(filename) = l.filename() {
                    writeln!(
                        output,
                        "{}  Filename: {}",
                        i,
                        String::from_utf8_lossy(filename)
                    )?;
                }
                if let Some(timestamp) = l.date() {
                    writeln!(output, "{}  Timestamp: {}", i, timestamp.convert())?;
                }
            }

            CompressedData(ref c) => {
                writeln!(output, "{}  Algorithm: {}", i, c.algo())?;
            }

            PKESK(ref p) => {
                writeln!(output, "{}  Version: {}", i, p.version())?;
                writeln!(output, "{}  Recipient: {}", i, p.recipient())?;
                writeln!(output, "{}  Pk algo: {}", i, p.pk_algo())?;
                if self.mpis {
                    writeln!(output, "{}", i)?;
                    writeln!(output, "{}  Encrypted session key:", i)?;

                    let ii = format!("{}    ", i);
                    match p.esk() {
                        mpi::Ciphertext::RSA { c } => {
                            self.dump_mpis(output, &ii, &[c.value()], &["c"])?
                        }
                        mpi::Ciphertext::ElGamal { e, c } => {
                            self.dump_mpis(output, &ii, &[e.value(), c.value()], &["e", "c"])?
                        }
                        mpi::Ciphertext::ECDH { e, key } => {
                            self.dump_mpis(output, &ii, &[e.value(), key], &["e", "key"])?
                        }
                        mpi::Ciphertext::Unknown { mpis, rest } => {
                            let keys: Vec<String> =
                                (0..mpis.len()).map(|i| format!("mpi{}", i)).collect();
                            self.dump_mpis(
                                output,
                                &ii,
                                &mpis
                                    .iter()
                                    .map(|m| m.value().iter().as_slice())
                                    .collect::<Vec<_>>()[..],
                                &keys.iter().map(|k| k.as_str()).collect::<Vec<_>>()[..],
                            )?;

                            self.dump_mpis(output, &ii, &[rest], &["rest"])?;
                        }

                        // crypto::mpi::Ciphertext is non-exhaustive.
                        u => writeln!(output, "{}Unknown variant: {:?}", ii, u)?,
                    }
                }
            }

            SKESK(ref s) => {
                writeln!(output, "{}  Version: {}", i, s.version())?;
                match s {
                    self::openpgp::packet::SKESK::V4(ref s) => {
                        writeln!(output, "{}  Symmetric algo: {}", i, s.symmetric_algo())?;
                        write!(output, "{}  S2K: ", i)?;
                        self.dump_s2k(output, i, s.s2k())?;
                        if let Ok(Some(esk)) = s.esk() {
                            writeln!(output, "{}  ESK: {}", i, hex::encode(esk))?;
                        }
                    }

                    self::openpgp::packet::SKESK::V5(ref s) => {
                        writeln!(output, "{}  Symmetric algo: {}", i, s.symmetric_algo())?;
                        writeln!(output, "{}  AEAD: {}", i, s.aead_algo())?;
                        write!(output, "{}  S2K: ", i)?;
                        self.dump_s2k(output, i, s.s2k())?;
                        if let Ok(iv) = s.aead_iv() {
                            writeln!(output, "{}  IV: {}", i, hex::encode(iv))?;
                        }
                        if let Ok(Some(esk)) = s.esk() {
                            writeln!(output, "{}  ESK: {}", i, hex::encode(esk))?;
                        }
                        writeln!(output, "{}  Digest: {}", i, hex::encode(s.aead_digest()))?;
                    }

                    // SKESK is non-exhaustive.
                    u => writeln!(output, "{}    Unknown variant: {:?}", i, u)?,
                }
            }

            SEIP(ref s) => {
                writeln!(output, "{}  Version: {}", i, s.version())?;
            }

            MDC(ref m) => {
                writeln!(output, "{}  Digest: {}", i, hex::encode(m.digest()))?;
                writeln!(
                    output,
                    "{}  Computed digest: {}",
                    i,
                    hex::encode(m.computed_digest())
                )?;
            }

            AED(ref a) => {
                writeln!(output, "{}  Version: {}", i, a.version())?;
                writeln!(output, "{}  Symmetric algo: {}", i, a.symmetric_algo())?;
                writeln!(output, "{}  AEAD: {}", i, a.aead())?;
                writeln!(output, "{}  Chunk size: {}", i, a.chunk_size())?;
                writeln!(output, "{}  IV: {}", i, hex::encode(a.iv()))?;
            }

            // openpgp::Packet is non-exhaustive.
            u => writeln!(output, "{}    Unknown variant: {:?}", i, u)?,
        }

        if let Some(fields) = additional_fields {
            for field in fields {
                writeln!(output, "{}  {}", i, field)?;
            }
        }

        if let Some(map) = map {
            writeln!(output, "{}", i)?;
            let mut hd = hex::Dumper::new(
                output,
                self.indentation_for_hexdump(
                    i,
                    map.iter()
                        .map(|f| {
                            if f.name() == "body" {
                                16
                            } else {
                                f.name().len()
                            }
                        })
                        .max()
                        .expect("we always have one entry"),
                ),
            );

            for field in map.iter() {
                if field.name() == "body" {
                    hd.write_ascii(field.as_bytes())?;
                } else {
                    hd.write(field.as_bytes(), field.name())?;
                }
            }

            let output = hd.into_inner();
            writeln!(output, "{}", i)?;
        } else {
            writeln!(output, "{}", i)?;
        }

        Ok(())
    }

    fn dump_subpacket(
        &self,
        output: &mut dyn io::Write,
        i: &str,
        s: &Subpacket,
        sig: &Signature,
    ) -> Result<()> {
        use self::SubpacketValue::*;

        let hexdump_unknown = |output: &mut dyn io::Write, buf| -> Result<()> {
            let mut hd = hex::Dumper::new(
                output,
                self.indentation_for_hexdump(&format!("{}    ", i), 0),
            );
            hd.write_labeled(buf, |_, _| None)?;
            Ok(())
        };

        match s.value() {
            Unknown { body, .. } => {
                writeln!(
                    output,
                    "{}    {:?}{}:",
                    i,
                    s.tag(),
                    if s.critical() { " (critical)" } else { "" }
                )?;
                hexdump_unknown(output, body.as_slice())?;
            }
            SignatureCreationTime(t) => write!(
                output,
                "{}    Signature creation time: {}",
                i,
                (*t).convert()
            )?,
            SignatureExpirationTime(t) => write!(
                output,
                "{}    Signature expiration time: {} ({})",
                i,
                t.convert(),
                if let Some(creation) = sig.signature_creation_time() {
                    (creation + std::time::Duration::from(*t))
                        .convert()
                        .to_string()
                } else {
                    " (no Signature Creation Time subpacket)".into()
                }
            )?,
            ExportableCertification(e) => {
                write!(output, "{}    Exportable certification: {}", i, e)?
            }
            TrustSignature { level, trust } => write!(
                output,
                "{}    Trust signature: level {} trust {}",
                i, level, trust
            )?,
            RegularExpression(ref r) => write!(
                output,
                "{}    Regular expression: {}",
                i,
                String::from_utf8_lossy(r)
            )?,
            Revocable(r) => write!(output, "{}    Revocable: {}", i, r)?,
            KeyExpirationTime(t) => {
                write!(output, "{}    Key expiration time: {}", i, t.convert())?
            }
            PreferredSymmetricAlgorithms(ref c) => write!(
                output,
                "{}    Symmetric algo preferences: {}",
                i,
                c.iter()
                    .map(|c| format!("{:?}", c))
                    .collect::<Vec<String>>()
                    .join(", ")
            )?,
            RevocationKey(rk) => {
                let (pk_algo, fp) = rk.revoker();
                write!(output, "{}    Revocation key: {}/{}", i, fp, pk_algo)?;
                if rk.sensitive() {
                    write!(output, ", sensitive")?;
                }
            }
            Issuer(ref is) => write!(output, "{}    Issuer: {}", i, is)?,
            NotationData(n) => {
                if n.flags().human_readable() {
                    write!(output, "{}    Notation: {}", i, n)?;
                    if s.critical() {
                        write!(output, " (critical)")?;
                    }
                    writeln!(output)?;
                } else {
                    write!(output, "{}    Notation: {}", i, n.name())?;
                    let flags = format!("{:?}", n.flags());
                    if !flags.is_empty() {
                        write!(output, "{}", flags)?;
                    }
                    if s.critical() {
                        write!(output, " (critical)")?;
                    }
                    writeln!(output)?;
                    hexdump_unknown(output, n.value())?;
                }
            }
            PreferredHashAlgorithms(ref h) => write!(
                output,
                "{}    Hash preferences: {}",
                i,
                h.iter()
                    .map(|h| format!("{:?}", h))
                    .collect::<Vec<String>>()
                    .join(", ")
            )?,
            PreferredCompressionAlgorithms(ref c) => write!(
                output,
                "{}    Compression preferences: {}",
                i,
                c.iter()
                    .map(|c| format!("{:?}", c))
                    .collect::<Vec<String>>()
                    .join(", ")
            )?,
            KeyServerPreferences(ref p) => {
                write!(output, "{}    Keyserver preferences: {:?}", i, p)?
            }
            PreferredKeyServer(ref k) => write!(
                output,
                "{}    Preferred keyserver: {}",
                i,
                String::from_utf8_lossy(k)
            )?,
            PrimaryUserID(p) => write!(output, "{}    Primary User ID: {}", i, p)?,
            PolicyURI(ref p) => write!(
                output,
                "{}    Policy URI: {}",
                i,
                String::from_utf8_lossy(p)
            )?,
            KeyFlags(ref k) => write!(output, "{}    Key flags: {:?}", i, k)?,
            SignersUserID(ref u) => write!(
                output,
                "{}    Signer's User ID: {}",
                i,
                String::from_utf8_lossy(u)
            )?,
            ReasonForRevocation { code, ref reason } => {
                let reason = String::from_utf8_lossy(reason);
                write!(
                    output,
                    "{}    Reason for revocation: {}{}{}",
                    i,
                    code,
                    if reason.len() > 0 { ", " } else { "" },
                    reason
                )?
            }
            Features(ref f) => write!(output, "{}    Features: {:?}", i, f)?,
            SignatureTarget {
                pk_algo,
                hash_algo,
                ref digest,
            } => write!(
                output,
                "{}    Signature target: {}, {}, {}",
                i,
                pk_algo,
                hash_algo,
                hex::encode(digest)
            )?,
            EmbeddedSignature(_) =>
            // Embedded signature is dumped below.
            {
                write!(output, "{}    Embedded signature: ", i)?
            }
            IssuerFingerprint(ref fp) => write!(output, "{}    Issuer Fingerprint: {}", i, fp)?,
            PreferredAEADAlgorithms(ref c) => write!(
                output,
                "{}    AEAD preferences: {}",
                i,
                c.iter()
                    .map(|c| format!("{:?}", c))
                    .collect::<Vec<String>>()
                    .join(", ")
            )?,
            IntendedRecipient(ref fp) => write!(output, "{}    Intended Recipient: {}", i, fp)?,
            AttestedCertifications(digests) => {
                write!(output, "{}    Attested Certifications:", i)?;
                if digests.is_empty() {
                    writeln!(output, " None")?;
                } else {
                    writeln!(output)?;
                    for d in digests {
                        writeln!(output, "{}      {}", i, hex::encode(d))?;
                    }
                }
            }

            // SubpacketValue is non-exhaustive.
            u => writeln!(output, "{}    Unknown variant: {:?}", i, u)?,
        }

        match s.value() {
            Unknown { .. } => (),
            NotationData { .. } => (),
            EmbeddedSignature(ref sig) => {
                if s.critical() {
                    write!(output, " (critical)")?;
                }
                writeln!(output)?;
                let indent = format!("{}      ", i);
                write!(output, "{}", indent)?;
                self.dump_packet(output, &indent, None, &sig.clone().into(), None, None)?;
            }
            _ => {
                if s.critical() {
                    write!(output, " (critical)")?;
                }
                writeln!(output)?;
            }
        }

        Ok(())
    }

    fn dump_s2k(&self, output: &mut dyn io::Write, i: &str, s2k: &S2K) -> Result<()> {
        use self::S2K::*;
        #[allow(deprecated)]
        match s2k {
            Simple { hash } => {
                writeln!(output, "Simple")?;
                writeln!(output, "{}    Hash: {}", i, hash)?;
            }
            Salted { hash, ref salt } => {
                writeln!(output, "Salted")?;
                writeln!(output, "{}    Hash: {}", i, hash)?;
                writeln!(output, "{}    Salt: {}", i, hex::encode(salt))?;
            }
            Iterated {
                hash,
                ref salt,
                hash_bytes,
            } => {
                writeln!(output, "Iterated")?;
                writeln!(output, "{}    Hash: {}", i, hash)?;
                writeln!(output, "{}    Salt: {}", i, hex::encode(salt))?;
                writeln!(output, "{}    Hash bytes: {}", i, hash_bytes)?;
            }
            Private { tag, parameters } => {
                writeln!(output, "Private")?;
                writeln!(output, "{}    Tag: {}", i, tag)?;
                if let Some(p) = parameters.as_ref() {
                    writeln!(output, "{}    Parameters: {:?}", i, p)?;
                }
            }
            Unknown { tag, parameters } => {
                writeln!(output, "Unknown")?;
                writeln!(output, "{}    Tag: {}", i, tag)?;
                if let Some(p) = parameters.as_ref() {
                    writeln!(output, "{}    Parameters: {:?}", i, p)?;
                }
            }

            // S2K is non-exhaustive
            u => writeln!(output, "{}    Unknown variant: {:?}", i, u)?,
        }
        Ok(())
    }

    fn dump_mpis(
        &self,
        output: &mut dyn io::Write,
        i: &str,
        chunks: &[&[u8]],
        keys: &[&str],
    ) -> Result<()> {
        assert_eq!(chunks.len(), keys.len());
        if chunks.is_empty() {
            return Ok(());
        }

        let max_key_len = keys.iter().map(|k| k.len()).max().unwrap();

        for (chunk, key) in chunks.iter().zip(keys.iter()) {
            writeln!(output, "{}", i)?;
            let mut hd = hex::Dumper::new(Vec::new(), self.indentation_for_hexdump(i, max_key_len));
            hd.write(*chunk, *key)?;
            output.write_all(&hd.into_inner())?;
        }

        Ok(())
    }

    /// Returns indentation for hex dumps.
    ///
    /// Returns a prefix of `i` so that a hexdump with labels no
    /// longer than `max_label_len` will fit into the target width.
    fn indentation_for_hexdump(&self, i: &str, max_label_len: usize) -> String {
        let amount = ::std::cmp::max(
            0,
            ::std::cmp::min(
                self.width as isize
                    - 63 // Length of address, hex digits, and whitespace.
                    - max_label_len as isize,
                i.len() as isize,
            ),
        ) as usize;

        format!("{}  ", &i.chars().take(amount).collect::<String>())
    }
}
