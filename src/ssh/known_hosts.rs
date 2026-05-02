//! TOFU known_hosts store.
//!
//! Format (one entry per line):
//!     <host>:<port> <key_type> <base64_key> [# fingerprint sha256:<hex>]
//!
//! Intentionally simpler than `~/.ssh/known_hosts` — no hashed hostnames,
//! no wildcards. proxxx owns this file; users are expected to grep/edit it
//! directly to revoke a host.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    pub key_type: String,
    pub key_blob: Vec<u8>,
}

impl HostKey {
    /// SHA-256 fingerprint, hex lowercase. Format: `sha256:<64 hex chars>`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(&self.key_blob);
        let digest = h.finalize();
        format!("sha256:{}", hex::encode(digest))
    }

    /// Human-friendly fingerprint (sha256:base64, 12-char prefix) for UI.
    #[must_use]
    pub fn fingerprint_short(&self) -> String {
        let fp = self.fingerprint();
        // Show first 16 hex chars after the prefix → "sha256:xxxxxxxxxxxxxxxx"
        match fp.split_once(':') {
            Some((p, h)) => format!("{p}:{}", h.get(..16).unwrap_or(h)),
            None => fp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMatch {
    /// Host is unknown — TOFU prompt or strict reject.
    Unknown,
    /// Host known with the same key — proceed.
    Match,
    /// Host known but key differs — possible MitM, hard reject.
    Mismatch,
}

#[derive(Debug, Default)]
pub struct KnownHosts {
    path: PathBuf,
    entries: HashMap<String, HostKey>,
}

impl KnownHosts {
    /// Load from disk. Missing file is OK (returns empty store).
    pub fn load(path: PathBuf) -> Result<Self> {
        let mut entries = HashMap::new();
        if !path.exists() {
            return Ok(Self { path, entries });
        }
        let f = std::fs::File::open(&path)
            .with_context(|| format!("opening known_hosts {}", path.display()))?;
        for (lineno, line) in BufReader::new(f).lines().enumerate() {
            let line = line.with_context(|| format!("reading known_hosts line {}", lineno + 1))?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let mut parts = trimmed.split_whitespace();
            let host = match parts.next() {
                Some(h) => h.to_string(),
                None => continue,
            };
            let key_type = match parts.next() {
                Some(t) => t.to_string(),
                None => continue,
            };
            let b64 = match parts.next() {
                Some(b) => b,
                None => continue,
            };
            let Ok(key_blob) = base64_decode(b64) else {
                continue;
            };
            entries.insert(host, HostKey { key_type, key_blob });
        }
        Ok(Self { path, entries })
    }

    #[must_use]
    pub fn check(&self, host: &str, port: u16, key: &HostKey) -> HostMatch {
        let id = host_id(host, port);
        match self.entries.get(&id) {
            None => HostMatch::Unknown,
            Some(known) if known == key => HostMatch::Match,
            Some(_) => HostMatch::Mismatch,
        }
    }

    /// Trust a host key (TOFU accept) and persist.
    pub fn trust(&mut self, host: &str, port: u16, key: HostKey) -> Result<()> {
        let id = host_id(host, port);
        let fp = key.fingerprint();
        self.entries.insert(id.clone(), key.clone());
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&self.path)
            .with_context(|| format!("opening known_hosts for write {}", self.path.display()))?;
        let line = format!(
            "{} {} {} # {}\n",
            id,
            key.key_type,
            base64_encode(&key.key_blob),
            fp,
        );
        f.write_all(line.as_bytes())
            .context("writing known_hosts entry")?;
        Ok(())
    }
}

fn host_id(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

// Minimal base64 (RFC 4648, no padding handling beyond '=').
// Avoids pulling another crate just for this.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];
        let b2 = bytes[i + 2];
        out.push(ALPH[(b0 >> 2) as usize] as char);
        out.push(ALPH[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPH[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        out.push(ALPH[(b2 & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let b0 = bytes[i];
        out.push(ALPH[(b0 >> 2) as usize] as char);
        out.push(ALPH[((b0 & 0x03) << 4) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];
        out.push(ALPH[(b0 >> 2) as usize] as char);
        out.push(ALPH[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPH[((b1 & 0x0f) << 2) as usize] as char);
        out.push('=');
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|b| *b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let v0 = val(bytes[i]).ok_or_else(|| anyhow::anyhow!("invalid base64"))?;
        let v1 = val(bytes[i + 1]).ok_or_else(|| anyhow::anyhow!("invalid base64"))?;
        let v2 = val(bytes[i + 2]).ok_or_else(|| anyhow::anyhow!("invalid base64"))?;
        let v3 = val(bytes[i + 3]).ok_or_else(|| anyhow::anyhow!("invalid base64"))?;
        out.push((v0 << 2) | (v1 >> 4));
        out.push((v1 << 4) | (v2 >> 2));
        out.push((v2 << 6) | v3);
        i += 4;
    }
    let rem = bytes.len() - i;
    if rem == 2 {
        let v0 = val(bytes[i]).ok_or_else(|| anyhow::anyhow!("invalid base64"))?;
        let v1 = val(bytes[i + 1]).ok_or_else(|| anyhow::anyhow!("invalid base64"))?;
        out.push((v0 << 2) | (v1 >> 4));
    } else if rem == 3 {
        let v0 = val(bytes[i]).ok_or_else(|| anyhow::anyhow!("invalid base64"))?;
        let v1 = val(bytes[i + 1]).ok_or_else(|| anyhow::anyhow!("invalid base64"))?;
        let v2 = val(bytes[i + 2]).ok_or_else(|| anyhow::anyhow!("invalid base64"))?;
        out.push((v0 << 2) | (v1 >> 4));
        out.push((v1 << 4) | (v2 >> 2));
    }
    Ok(out)
}

#[allow(dead_code)]
pub fn path_for_default() -> PathBuf {
    directories::ProjectDirs::from("dev", "proxxx", "proxxx").map_or_else(
        || PathBuf::from("/tmp/proxxx/known_hosts"),
        |d| d.config_dir().join("known_hosts"),
    )
}

#[allow(dead_code)]
pub fn write_default(path: &Path, host_id: &str, key: &HostKey) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    let line = format!(
        "{} {} {} # {}\n",
        host_id,
        key.key_type,
        base64_encode(&key.key_blob),
        key.fingerprint(),
    );
    f.write_all(line.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let cases: &[&[u8]] = &[
            b"",
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0u8, 1, 2, 3, 250, 251, 252, 253, 254, 255],
        ];
        for c in cases {
            let enc = base64_encode(c);
            let dec = base64_decode(&enc).expect("decode");
            assert_eq!(c, &dec.as_slice(), "roundtrip for {c:?}");
        }
    }

    #[test]
    fn fingerprint_stable() {
        let k = HostKey {
            key_type: "ssh-ed25519".to_string(),
            key_blob: b"abc".to_vec(),
        };
        assert_eq!(
            k.fingerprint(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn tofu_accept_and_reload() {
        let dir = tempfile_dir();
        let path = dir.join("known_hosts");
        let mut store = KnownHosts::load(path.clone()).expect("load empty");
        let key = HostKey {
            key_type: "ssh-ed25519".to_string(),
            key_blob: vec![1, 2, 3, 4],
        };
        assert_eq!(store.check("pve1", 22, &key), HostMatch::Unknown);
        store.trust("pve1", 22, key.clone()).expect("trust");
        assert_eq!(store.check("pve1", 22, &key), HostMatch::Match);

        let reloaded = KnownHosts::load(path).expect("reload");
        assert_eq!(reloaded.check("pve1", 22, &key), HostMatch::Match);
        let bad = HostKey {
            key_type: "ssh-ed25519".to_string(),
            key_blob: vec![9, 9, 9, 9],
        };
        assert_eq!(reloaded.check("pve1", 22, &bad), HostMatch::Mismatch);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("proxxx-test-{nano}"));
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }
}
