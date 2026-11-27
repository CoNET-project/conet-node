//! Node-side delivery evidence (`--evidence-log <path>`), off unless the flag is given.
//!
//! One JSON object per line, closed field set, written for tests that must show which node a
//! message went through. A node never sees a message ID, sender, recipient wallet or content, so
//! rows carry only hashes of the armors it handled (keccak256 of the UTF-8 armor text, `0x`+64
//! lowercase hex, the same function as the `gossip_delivery_ack` armor hash), public node key IDs,
//! counts and times.
//!
//! Redaction (enforced here, not by callers): no wallet, no user PGP key ID, no client address, no
//! armor text, no stream key, no device token. A row can only be built from the typed fields of
//! [`Row`]; `reason` is a `&'static str` from [`reason`]. The log stops at [`MAX_BYTES`] and says so once.
use serde::Serialize;
use si_crypto::eth::keccak_hex;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The log stops growing here (about 200 bytes a row).
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Entry,
    Mailbox,
    Node,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    Refused,
    Fail,
}

/// How an entry passed an armor on.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Forward {
    /// Forwarded the armor it received, unchanged.
    SameArmor,
    /// Peeled one layer addressed to this node and forwarded the inner armor.
    InnerArmor,
    /// Several mailbox slots, delivered by plan.
    Plan,
}

/// Closed reason codes. Anything else is `other`.
pub mod reason {
    pub const CLOSED: [&str; 16] = [
        "body_json",
        "body_data",
        "not_pgp",
        "decrypt",
        "same_node",
        "hop_limit",
        "hop_count",
        "hop_header",
        "recipient_count",
        "inner_recipient_count",
        "mailbox_work_inner",
        "unknown_command",
        "signature",
        "format",
        "route_unknown",
        "lookup_unavailable",
    ];

    /// Maps a protocol reason onto the closed list; unknown text becomes `other`.
    pub fn closed(r: &str) -> &'static str {
        CLOSED.iter().copied().find(|c| *c == r).unwrap_or("other")
    }
}

/// `ev` values.
pub mod ev {
    pub const POST: &str = "post";
    pub const STORE: &str = "store";
    pub const LISTEN_ATTACH: &str = "listen_attach";
    pub const ACK: &str = "ack";
    pub const ONLINE_QUERY: &str = "online_query";
    pub const EVIDENCE_FULL: &str = "evidence_full";
    pub const START: &str = "start";
}

#[derive(Serialize, Default)]
pub struct Row {
    pub ev: &'static str,
    pub role: Option<Role>,
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// keccak256 of the `data` string exactly as received on `/post`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h_raw: Option<String>,
    /// keccak256 of the received armor after SI's normalisation (trim, cut after the END line).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h_recv: Option<String>,
    /// keccak256 of the armor this node passed on to the next hop.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h_fwd: Option<String>,
    /// keccak256 of the armor string exactly as stored and delivered to the recipient (the `data`
    /// of the SSE frame); equals the `gossip_delivery_ack` hash. Mailbox work: the inner armor
    /// trimmed and cut after its END line. A bare armor post: the posted string byte for byte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h_in: Option<String>,
    /// Public route key ID (the domain label) of the next-hop node, looked up from the node table by
    /// the address the armor was sent to, when there is exactly one hop. Never the key ID the post
    /// carried (it may be the recipient's user key), never an IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hops: Option<u32>,
    /// Armor length rounded up to a multiple of 256 bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub len_bucket: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward: Option<Forward>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_sessions: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_enqueued: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessions: Option<u32>,
    /// First 8 hex characters of keccak256(instanceId): tells listens apart, reveals nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    /// `start` row only: the package version this node reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<&'static str>,
}

#[derive(Serialize)]
struct Line<'a> {
    ts_ms: u64,
    utc: String,
    seq: u64,
    key_id: &'a str,
    #[serde(flatten)]
    row: &'a Row,
}

pub fn bucket(len: usize) -> u32 {
    (len.div_ceil(256) * 256).min(u32::MAX as usize) as u32
}

pub fn hash(text: &str) -> String {
    keccak_hex(text)
}

pub fn instance_tag(instance_id: &str) -> String {
    keccak_hex(instance_id)[2..10].to_string()
}

/// `YYYY-MM-DDThh:mm:ss.mmmZ` from Unix milliseconds (civil-from-days, no time-zone data).
pub fn utc(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        ms % 1000
    )
}

pub struct EvidenceLog {
    key_id: String,
    inner: Mutex<Inner>,
}

struct Inner {
    file: File,
    written: u64,
    seq: u64,
    full: bool,
}

impl EvidenceLog {
    /// Opens (appends to) the file, mode 0640. The caller decides who may read it.
    pub fn open(path: &Path, key_id: &str) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            key_id: key_id.to_string(),
            inner: Mutex::new(Inner {
                file,
                written,
                seq: 0,
                full: false,
            }),
        })
    }

    /// Best effort: a write failure never affects delivery.
    pub fn emit(&self, row: Row) {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut g = self.inner.lock().expect("evidence");
        if g.full {
            return;
        }
        g.seq += 1;
        let full_row = Row {
            ev: ev::EVIDENCE_FULL,
            role: Some(Role::Node),
            outcome: Some(Outcome::Fail),
            ..Default::default()
        };
        let stop = g.written >= MAX_BYTES;
        let row = if stop { &full_row } else { &row };
        let line = Line {
            ts_ms: ms,
            utc: utc(ms),
            seq: g.seq,
            key_id: &self.key_id,
            row,
        };
        let Ok(mut text) = serde_json::to_string(&line) else {
            return;
        };
        text.push('\n');
        if g.file.write_all(text.as_bytes()).is_ok() {
            g.written += text.len() as u64;
        }
        if stop {
            g.full = true;
        }
    }
}

/// The armor a `/post` carried: the `data` string as received and its SI-normalised form.
pub struct Received {
    pub h_raw: String,
    pub h_recv: String,
    pub len: usize,
}

impl Received {
    /// None when the body has no string `data` (such a post is refused before any evidence row).
    pub fn of_body(body: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(body).ok()?;
        let raw = v.get("data")?.as_str()?;
        let norm = si_proto::as_pgp_message_armor(raw).unwrap_or(raw.trim());
        Some(Self {
            h_raw: hash(raw),
            h_recv: hash(norm),
            len: norm.len(),
        })
    }
}

impl EvidenceLog {
    pub fn start(&self, version: &'static str) {
        self.emit(Row {
            ev: ev::START,
            role: Some(Role::Node),
            outcome: Some(Outcome::Ok),
            version: Some(version),
            ..Default::default()
        });
    }

    /// An entry passed an armor on (or a mailbox plan was started).
    pub fn post_forward(
        &self,
        rcv: Option<&Received>,
        armor: &str,
        next_node: Option<String>,
        hops: usize,
        forward: Forward,
    ) {
        let h_fwd = hash(armor);
        // A forwarded armor is the received `data` string byte for byte; a peeled layer is not.
        let same = rcv.map(|r| r.h_raw == h_fwd).unwrap_or(false);
        self.emit(Row {
            ev: ev::POST,
            role: Some(Role::Entry),
            outcome: Some(Outcome::Ok),
            h_raw: rcv.map(|r| r.h_raw.clone()),
            h_recv: rcv.map(|r| r.h_recv.clone()),
            h_fwd: Some(h_fwd),
            next_node,
            hops: Some(hops as u32),
            len_bucket: Some(bucket(armor.len())),
            forward: Some(match forward {
                Forward::SameArmor if !same => Forward::InnerArmor,
                f => f,
            }),
            ..Default::default()
        });
    }

    /// This node stored an armor as the mailbox.
    pub fn store(
        &self,
        rcv: Option<&Received>,
        armor: &str,
        report: crate::mailbox::DeliverReport,
    ) {
        self.emit(Row {
            ev: ev::STORE,
            role: Some(Role::Mailbox),
            outcome: Some(Outcome::Ok),
            h_raw: rcv.map(|r| r.h_raw.clone()),
            h_recv: rcv.map(|r| r.h_recv.clone()),
            h_in: Some(hash(armor)),
            len_bucket: Some(bucket(armor.len())),
            stored: Some(report.fresh),
            live_sessions: Some(report.live_sessions),
            push_enqueued: Some(report.push_enqueued),
            ..Default::default()
        });
    }

    /// A post that failed or was refused. `reason` is mapped onto the closed list.
    pub fn post_refused(&self, rcv: Option<&Received>, refused: bool, why: &str) {
        self.emit(Row {
            ev: ev::POST,
            role: Some(Role::Node),
            outcome: Some(if refused {
                Outcome::Refused
            } else {
                Outcome::Fail
            }),
            reason: Some(reason::closed(why)),
            h_raw: rcv.map(|r| r.h_raw.clone()),
            h_recv: rcv.map(|r| r.h_recv.clone()),
            ..Default::default()
        });
    }

    pub fn listen_attach(&self, instance_id: &str, sessions: usize) {
        self.emit(Row {
            ev: ev::LISTEN_ATTACH,
            role: Some(Role::Mailbox),
            outcome: Some(Outcome::Ok),
            instance: Some(instance_tag(instance_id)),
            sessions: Some(sessions as u32),
            ..Default::default()
        });
    }

    /// `armor_hash` is the client-supplied hash of the inner armor (`gossip_delivery_ack`).
    pub fn ack(&self, armor_hash: &str, removed: bool) {
        self.emit(Row {
            ev: ev::ACK,
            role: Some(Role::Mailbox),
            outcome: Some(Outcome::Ok),
            h_in: Some(armor_hash.to_ascii_lowercase()),
            removed: Some(removed),
            ..Default::default()
        });
    }

    pub fn online_query(&self, online: bool) {
        self.emit(Row {
            ev: ev::ONLINE_QUERY,
            role: Some(Role::Mailbox),
            outcome: Some(Outcome::Ok),
            online: Some(online),
            ..Default::default()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_is_correct_at_known_instants() {
        assert_eq!(utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(utc(1_000_000_000_123), "2001-09-09T01:46:40.123Z");
        // 2026-11-27T17:45:24Z
        assert_eq!(utc(1_795_801_524_000), "2026-11-27T17:45:24.000Z");
        // leap day
        assert_eq!(utc(1_709_164_800_000), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn buckets_round_up_to_256() {
        assert_eq!(
            (bucket(0), bucket(1), bucket(256), bucket(257)),
            (0, 256, 256, 512)
        );
    }

    #[test]
    fn unknown_reasons_become_other() {
        assert_eq!(reason::closed("decrypt"), "decrypt");
        assert_eq!(reason::closed("0xabc wallet leak"), "other");
    }

    #[test]
    fn rows_have_the_closed_shape_and_stop_at_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        let log = EvidenceLog::open(&p, "ABCDEF0123456789").unwrap();
        log.emit(Row {
            ev: ev::STORE,
            role: Some(Role::Mailbox),
            outcome: Some(Outcome::Ok),
            h_in: Some(hash("x")),
            stored: Some(true),
            live_sessions: Some(1),
            ..Default::default()
        });
        let text = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "ts_ms",
                "utc",
                "seq",
                "key_id",
                "ev",
                "role",
                "outcome",
                "h_in",
                "stored",
                "live_sessions"
            ]
        );
        assert_eq!(v["role"], "mailbox");
        assert_eq!(v["h_in"], hash("x"));
        // The cap: pretend the file is full.
        log.inner.lock().unwrap().written = MAX_BYTES;
        log.emit(Row {
            ev: ev::POST,
            ..Default::default()
        });
        log.emit(Row {
            ev: ev::POST,
            ..Default::default()
        });
        let lines: Vec<String> = std::fs::read_to_string(&p)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(lines.len(), 2, "one more row: evidence_full, then silence");
        assert!(lines[1].contains("evidence_full"));
    }
}
