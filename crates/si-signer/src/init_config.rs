//! Node-provided initialization config (`/etc/conet-node/init.json`): the public parameters a
//! TypeScript node asked for at first start (listening port, public address) plus the node's
//! public settings (RPC, API base) and the identity source for `conet-signer first-start`.
//!
//! It holds NO secrets. Unknown keys are refused, so a pasted password or key never hides in it;
//! an error names the offending key (an identifier only) or a fixed code, never a value.
//! Parsing is by hand over `serde_json::Value`, because serde's own errors can echo values.
//!
//! Absent file (`NotFound` only) means "no node-provided config". Anything else that is wrong
//! (unreadable, not a regular file, writable by others, too large, not UTF-8, not JSON, a bad
//! value) refuses to start: a damaged config never falls back to defaults.
//!
//! Schema (version 1), all optional except `version`:
//! ```text
//! { "version": 1,
//!   "http_port": 80,            // 1..65535, default 80   (TS ipV4Port)
//!   "https_port": 443,          // 0..65535, 0 = off, default 443
//!   "public_ip": ["203.0.113.10"] | "auto",   // TS ipV4 (auto = local interface probe)
//!   "rpc": "https://...", "api_base": "https://...",
//!   "identity": { "mode": "auto"|"generate"|"ts-import",
//!                 "confirm_generate_on_ts_host": true,   // only with "generate"
//!                 "ts_service_account": "name" | "ts_setup_path": "/abs/nodeSetup.json",
//!                 "expect_wallet": "0x..", "expect_key_id": "16 hex" } }
//! ```
//! TS `nodeSetup.json` field names are also understood at the top level, so a setup carried over
//! from a TS node never has a field silently dropped: each has a fixed [`Disposition`] in
//! [`TS_FIELDS`] (consumed into a Rust setting, ignored with its name reported, or refused because
//! it is a secret). The two TS prices are accepted and ignored: no Rust code consumes them.
use serde_json::{Map, Value};
use si_crypto::eth;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const MAX_BYTES: u64 = 64 * 1024;
pub const DEFAULT_PATH: &str = "/etc/conet-node/init.json";

#[derive(Debug, PartialEq, Eq)]
pub struct InitConfigError(pub String);

impl std::fmt::Display for InitConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "init config refused: {}", self.0)
    }
}
impl std::error::Error for InitConfigError {}

/// What happens to a TS `nodeSetup.json` field name that appears in `init.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Becomes the named init setting.
    Consumed(&'static str),
    /// Validated, then ignored; the name is reported at start. The reason is for the map.
    Ignored(&'static str),
    /// Never accepted here: it carries or names secret material.
    Refused,
}

/// Every field of the TS `ICoNET_NodeSetup` (CoNET-SI 74c6cfda `src/define.d.ts:3-24`).
pub const TS_FIELDS: [(&str, Disposition); 17] = [
    ("ipV4", Disposition::Consumed("public_ip")),
    ("ipV4Port", Disposition::Consumed("http_port")),
    (
        "ipV6",
        Disposition::Ignored("always empty in TS; listening is dual-stack [::]"),
    ),
    (
        "ipV6Port",
        Disposition::Ignored("TS never read it; one HTTP port, dual-stack"),
    ),
    ("keychain", Disposition::Refused),
    ("keyObj", Disposition::Refused),
    (
        "storage_price",
        Disposition::Ignored("no Rust consumer; no billing business added"),
    ),
    (
        "outbound_price",
        Disposition::Ignored("no Rust consumer; no billing business added"),
    ),
    (
        "DL_registeredData",
        Disposition::Ignored("TS DL registration is not implemented in Rust"),
    ),
    ("pgpKeyObj", Disposition::Refused),
    (
        "cpus",
        Disposition::Ignored("no Rust consumer; the runtime sizes itself"),
    ),
    ("pgpKey", Disposition::Refused),
    ("passwd", Disposition::Refused),
    (
        "platform_verison",
        Disposition::Ignored("Rust reports its own package version"),
    ),
    (
        "dl_publicKeyArmored",
        Disposition::Ignored("TS DL registration is not implemented in Rust"),
    ),
    (
        "sslDate",
        Disposition::Ignored("Rust runs ACME in process with its own cache"),
    ),
    (
        "restartBlockNumber",
        Disposition::Ignored("Rust reads the chain value directly"),
    ),
];

pub fn disposition(ts_field: &str) -> Option<Disposition> {
    TS_FIELDS
        .iter()
        .find(|(n, _)| *n == ts_field)
        .map(|(_, d)| *d)
}

fn bad<T>(code: impl Into<String>) -> Result<T, InitConfigError> {
    Err(InitConfigError(code.into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicIp {
    Auto,
    List(Vec<IpAddr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Generate on a fresh node; refuse when TS traces are found (decided by the root stage).
    Auto,
    /// Generate on a fresh node; the operator said so explicitly.
    Generate,
    /// Import the identity of a TS node; never falls back to generating.
    TsImport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsSource {
    Account(String),
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub mode: Mode,
    pub source: Option<TsSource>,
    pub expect_wallet: Option<String>,
    pub expect_key_id: Option<String>,
    /// Second confirmation that a NEW identity may be generated on a host with TS traces.
    pub confirm_generate_on_ts_host: bool,
}

impl Default for Identity {
    fn default() -> Self {
        Identity {
            mode: Mode::Auto,
            source: None,
            expect_wallet: None,
            expect_key_id: None,
            confirm_generate_on_ts_host: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InitConfig {
    pub http_port: Option<u16>,
    pub https_port: Option<u16>,
    pub public_ip: Option<PublicIp>,
    pub rpc: Option<String>,
    pub api_base: Option<String>,
    pub identity: Identity,
    /// TS field names that were present and ignored (names only), for the start report.
    pub legacy_ignored: Vec<&'static str>,
    /// TS field names that were present and consumed into the named setting.
    pub ts_consumed: Vec<&'static str>,
}

/// An identifier-looking key name for error messages; anything else is not echoed.
fn key_label(k: &str) -> String {
    if !k.is_empty() && k.len() <= 32 && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        k.to_string()
    } else {
        "<non-identifier key>".to_string()
    }
}

fn only_keys(
    obj: &Map<String, Value>,
    allowed: &[&str],
    scope: &str,
) -> Result<(), InitConfigError> {
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            return bad(format!("unknown_key:{scope}{}", key_label(k)));
        }
    }
    Ok(())
}

fn port(v: &Value, name: &str, min: u64) -> Result<u16, InitConfigError> {
    match v.as_u64() {
        Some(n) if n >= min && n <= 65535 => Ok(n as u16),
        _ => bad(format!("bad_value:{name}")),
    }
}

fn url(v: &Value, name: &str) -> Result<String, InitConfigError> {
    let s = v
        .as_str()
        .ok_or_else(|| InitConfigError(format!("bad_value:{name}")))?;
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"));
    let ok = rest.is_some_and(|r| !r.is_empty())
        && s.len() <= 2048
        && !s
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control());
    if ok {
        Ok(s.to_string())
    } else {
        bad(format!("bad_value:{name}"))
    }
}

fn account_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

fn identity(v: &Value) -> Result<Identity, InitConfigError> {
    let obj = v
        .as_object()
        .ok_or_else(|| InitConfigError("bad_value:identity".into()))?;
    only_keys(
        obj,
        &[
            "mode",
            "ts_service_account",
            "ts_setup_path",
            "expect_wallet",
            "expect_key_id",
            "confirm_generate_on_ts_host",
        ],
        "identity.",
    )?;
    let mode = match obj.get("mode").map(|m| m.as_str()) {
        None => Mode::Auto,
        Some(Some("auto")) => Mode::Auto,
        Some(Some("generate")) => Mode::Generate,
        Some(Some("ts-import")) => Mode::TsImport,
        Some(_) => return bad("bad_value:identity.mode"),
    };
    let account = obj.get("ts_service_account");
    let path = obj.get("ts_setup_path");
    if account.is_some() && path.is_some() {
        return bad("identity.ts_source_ambiguous");
    }
    let source = match (account, path) {
        (Some(a), None) => {
            let s = a.as_str().filter(|s| account_name_ok(s));
            Some(TsSource::Account(
                s.ok_or_else(|| InitConfigError("bad_value:identity.ts_service_account".into()))?
                    .to_string(),
            ))
        }
        (None, Some(p)) => {
            let s = p
                .as_str()
                .filter(|s| s.starts_with('/') && s.len() <= 4096 && !s.contains('\0'))
                .ok_or_else(|| InitConfigError("bad_value:identity.ts_setup_path".into()))?;
            Some(TsSource::Path(PathBuf::from(s)))
        }
        _ => None,
    };
    let expect_wallet = match obj.get("expect_wallet") {
        None => None,
        Some(w) => Some(
            w.as_str()
                .filter(|s| eth::is_address(s))
                .ok_or_else(|| InitConfigError("bad_value:identity.expect_wallet".into()))?
                .to_string(),
        ),
    };
    let expect_key_id = match obj.get("expect_key_id") {
        None => None,
        Some(k) => Some(
            k.as_str()
                .map(|s| s.trim().to_ascii_uppercase())
                .filter(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or_else(|| InitConfigError("bad_value:identity.expect_key_id".into()))?,
        ),
    };
    let confirm = match obj.get("confirm_generate_on_ts_host") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return bad("bad_value:identity.confirm_generate_on_ts_host"),
    };
    if confirm && mode != Mode::Generate {
        return bad("identity.confirm_without_generate");
    }
    if mode == Mode::TsImport {
        if source.is_none() {
            return bad("identity.ts_import_needs_source");
        }
        if expect_wallet.is_none() || expect_key_id.is_none() {
            return bad("identity.ts_import_needs_expected_public_values");
        }
    } else if source.is_some() {
        return bad("identity.ts_source_without_ts_import");
    }
    Ok(Identity {
        mode,
        source,
        expect_wallet,
        expect_key_id,
        confirm_generate_on_ts_host: confirm,
    })
}

/// Validate a parsed document.
pub fn parse_value(root: &Value) -> Result<InitConfig, InitConfigError> {
    let obj = root
        .as_object()
        .ok_or_else(|| InitConfigError("not_an_object".into()))?;
    for k in obj.keys() {
        let native = [
            "version",
            "http_port",
            "https_port",
            "public_ip",
            "rpc",
            "api_base",
            "identity",
        ]
        .contains(&k.as_str());
        match disposition(k) {
            Some(Disposition::Refused) => {
                return bad(format!("secret_field_not_allowed:{}", key_label(k)))
            }
            Some(_) => {}
            None if native => {}
            None => return bad(format!("unknown_key:{}", key_label(k))),
        }
    }
    if obj.get("version").and_then(Value::as_u64) != Some(1) {
        return bad("bad_value:version");
    }
    let mut c = InitConfig::default();
    if let Some(v) = obj.get("http_port") {
        c.http_port = Some(port(v, "http_port", 1)?);
    }
    if let Some(v) = obj.get("ipV4Port") {
        if c.http_port.is_some() {
            return bad("conflict:ipV4Port,http_port");
        }
        c.http_port = Some(port(v, "ipV4Port", 1)?);
        c.ts_consumed.push("ipV4Port");
    }
    if let Some(v) = obj.get("https_port") {
        c.https_port = Some(port(v, "https_port", 0)?);
    }
    if let Some(v) = obj.get("public_ip") {
        c.public_ip = Some(match v {
            Value::String(s) if s == "auto" => PublicIp::Auto,
            Value::Array(items) if !items.is_empty() => PublicIp::List(
                items
                    .iter()
                    .map(|i| {
                        i.as_str()
                            .and_then(|s| s.parse::<IpAddr>().ok())
                            .ok_or_else(|| InitConfigError("bad_value:public_ip".into()))
                    })
                    .collect::<Result<_, _>>()?,
            ),
            _ => return bad("bad_value:public_ip"),
        });
    }
    if let Some(v) = obj.get("ipV4") {
        // TS wrote "" when it found no global address: that is "unset", not an address.
        match v.as_str() {
            Some("") => c.legacy_ignored.push("ipV4"),
            Some(s) => {
                let ip = s
                    .parse::<std::net::Ipv4Addr>()
                    .map_err(|_| InitConfigError("bad_value:ipV4".into()))?;
                if c.public_ip.is_some() {
                    return bad("conflict:ipV4,public_ip");
                }
                c.public_ip = Some(PublicIp::List(vec![IpAddr::V4(ip)]));
                c.ts_consumed.push("ipV4");
            }
            None => return bad("bad_value:ipV4"),
        }
    }
    if let Some(v) = obj.get("rpc") {
        c.rpc = Some(url(v, "rpc")?);
    }
    if let Some(v) = obj.get("api_base") {
        c.api_base = Some(url(v, "api_base")?);
    }
    if let Some(v) = obj.get("identity") {
        c.identity = identity(v)?;
    }
    // Ignored TS fields: validated by type so a damaged carry-over is not waved through, then
    // named in the report.
    for (name, d) in TS_FIELDS {
        let Disposition::Ignored(_) = d else { continue };
        let Some(v) = obj.get(name) else { continue };
        let ok = match name {
            "ipV6" | "platform_verison" => v.as_str().is_some_and(|s| s.len() <= 256),
            "DL_registeredData" | "dl_publicKeyArmored" => {
                v.as_str().is_some_and(|s| s.len() <= MAX_BYTES as usize)
            }
            "ipV6Port" => v.as_u64().is_some_and(|n| n <= 65535),
            "storage_price" | "outbound_price" | "sslDate" => {
                v.as_f64().is_some_and(|n| n.is_finite() && n >= 0.0)
            }
            "cpus" | "restartBlockNumber" => v.as_u64().is_some(),
            _ => false,
        };
        if !ok {
            return bad(format!("bad_value:{name}"));
        }
        c.legacy_ignored.push(name);
    }
    Ok(c)
}

pub fn parse_bytes(bytes: &[u8]) -> Result<InitConfig, InitConfigError> {
    if bytes.len() as u64 > MAX_BYTES {
        return bad("file_too_large");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| InitConfigError("not_utf8".into()))?;
    let root: Value = serde_json::from_str(text).map_err(|_| InitConfigError("not_json".into()))?;
    parse_value(&root)
}

/// Load the file. `Ok(None)` only when it does not exist. Everything else wrong is an error.
pub fn load(path: &Path) -> Result<Option<InitConfig>, InitConfigError> {
    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return bad("unreadable"),
    };
    if !md.is_file() {
        return bad("not_a_regular_file");
    }
    if md.permissions().mode() & 0o022 != 0 {
        return bad("writable_by_group_or_others");
    }
    if md.len() > MAX_BYTES {
        return bad("file_too_large");
    }
    let bytes = std::fs::read(path).map_err(|_| InitConfigError("unreadable".into()))?;
    parse_bytes(&bytes).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok(v: Value) -> InitConfig {
        parse_value(&v).unwrap()
    }
    fn err(v: Value) -> String {
        parse_value(&v).unwrap_err().0
    }

    #[test]
    fn minimal_and_full_documents_parse() {
        assert_eq!(ok(json!({"version": 1})), InitConfig::default());
        let c = ok(json!({
            "version": 1, "http_port": 8080, "https_port": 0,
            "public_ip": ["203.0.113.7", "2001:db8::1"],
            "rpc": "https://rpc.example", "api_base": "https://api.example",
            "storage_price": 0.01, "outbound_price": 0,
        }));
        assert_eq!(c.http_port, Some(8080));
        assert_eq!(c.https_port, Some(0));
        assert_eq!(c.legacy_ignored, vec!["storage_price", "outbound_price"]);
        assert!(c.ts_consumed.is_empty());
        assert_eq!(
            ok(json!({"version":1,"public_ip":"auto"})).public_ip,
            Some(PublicIp::Auto)
        );
    }

    #[test]
    fn unknown_keys_are_refused_and_only_the_name_is_echoed() {
        let e = err(json!({"version": 1, "passwd": "hunter2-secret"}));
        assert_eq!(e, "secret_field_not_allowed:passwd");
        let e = err(json!({"version": 1, "password": "hunter2-secret"}));
        assert_eq!(e, "unknown_key:password");
        assert!(!e.contains("hunter2"));
        let e = err(json!({"version": 1, "identity": {"privateKey": "x"}}));
        assert_eq!(e, "unknown_key:identity.privateKey");
        let e = err(json!({"version": 1, "keychain": "SECRET-JSON"}));
        assert_eq!(e, "secret_field_not_allowed:keychain");
        assert!(!e.contains("SECRET"));
        let e = err(json!({"version": 1, "a b c": 1}));
        assert!(e.contains("non-identifier"));
    }

    #[test]
    fn bad_values_are_refused_without_echoing_them() {
        for (doc, code) in [
            (json!({"version": 2}), "bad_value:version"),
            (json!({}), "bad_value:version"),
            (json!({"version": 1, "http_port": 0}), "bad_value:http_port"),
            (
                json!({"version": 1, "http_port": 70000}),
                "bad_value:http_port",
            ),
            (
                json!({"version": 1, "http_port": "80"}),
                "bad_value:http_port",
            ),
            (
                json!({"version": 1, "https_port": 65536}),
                "bad_value:https_port",
            ),
            (
                json!({"version": 1, "public_ip": []}),
                "bad_value:public_ip",
            ),
            (
                json!({"version": 1, "public_ip": ["not-an-ip"]}),
                "bad_value:public_ip",
            ),
            (
                json!({"version": 1, "public_ip": "SECRET"}),
                "bad_value:public_ip",
            ),
            (json!({"version": 1, "rpc": "ftp://x"}), "bad_value:rpc"),
            (json!({"version": 1, "rpc": "https://"}), "bad_value:rpc"),
            (json!({"version": 1, "rpc": "https://a b"}), "bad_value:rpc"),
            (json!({"version": 1, "api_base": " "}), "bad_value:api_base"),
            (
                json!({"version": 1, "storage_price": -1}),
                "bad_value:storage_price",
            ),
            (
                json!({"version": 1, "outbound_price": "x"}),
                "bad_value:outbound_price",
            ),
        ] {
            assert_eq!(err(doc), code);
        }
    }

    const W: &str = "0x00000000000000000000000000000000000000a1";

    #[test]
    fn ts_import_needs_source_and_public_values_and_never_falls_back() {
        assert_eq!(
            err(json!({"version":1,"identity":{"mode":"ts-import"}})),
            "identity.ts_import_needs_source"
        );
        assert_eq!(
            err(json!({"version":1,"identity":{"mode":"ts-import","ts_service_account":"peter"}})),
            "identity.ts_import_needs_expected_public_values"
        );
        let c = ok(json!({"version":1,"identity":{
            "mode":"ts-import","ts_service_account":"peter",
            "expect_wallet":W,"expect_key_id":"0123456789abcdef"}}));
        assert_eq!(
            c.identity.expect_key_id.as_deref(),
            Some("0123456789ABCDEF")
        );
        assert_eq!(c.identity.source, Some(TsSource::Account("peter".into())));
        let c = ok(json!({"version":1,"identity":{
            "mode":"ts-import","ts_setup_path":"/home/peter/.CoNET-SI/nodeSetup.json",
            "expect_wallet":W,"expect_key_id":"0123456789ABCDEF"}}));
        assert!(matches!(c.identity.source, Some(TsSource::Path(_))));
    }

    #[test]
    fn identity_fields_are_checked() {
        for (id, code) in [
            (json!({"mode":"yolo"}), "bad_value:identity.mode"),
            (
                json!({"ts_service_account":"peter"}),
                "identity.ts_source_without_ts_import",
            ),
            (
                json!({"mode":"ts-import","ts_service_account":"a","ts_setup_path":"/x"}),
                "identity.ts_source_ambiguous",
            ),
            (
                json!({"mode":"ts-import","ts_service_account":"Peter!"}),
                "bad_value:identity.ts_service_account",
            ),
            (
                json!({"mode":"ts-import","ts_setup_path":"relative/x"}),
                "bad_value:identity.ts_setup_path",
            ),
            (
                json!({"expect_wallet":"0x12"}),
                "bad_value:identity.expect_wallet",
            ),
            (
                json!({"expect_key_id":"zz"}),
                "bad_value:identity.expect_key_id",
            ),
        ] {
            assert_eq!(err(json!({"version":1,"identity":id})), code);
        }
        assert_eq!(ok(json!({"version":1})).identity, Identity::default());
        assert_eq!(
            ok(json!({"version":1,"identity":{"mode":"generate"}}))
                .identity
                .mode,
            Mode::Generate
        );
    }

    #[test]
    fn load_distinguishes_absent_from_damaged() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("init.json");
        assert_eq!(load(&p), Ok(None));
        std::fs::write(&p, br#"{"version":1,"http_port":81}"#).unwrap();
        assert_eq!(load(&p).unwrap().unwrap().http_port, Some(81));
        // Truncated (half-written) file.
        std::fs::write(&p, br#"{"version":1,"http_po"#).unwrap();
        assert_eq!(load(&p).unwrap_err().0, "not_json");
        std::fs::write(&p, [0xff, 0xfe]).unwrap();
        assert_eq!(load(&p).unwrap_err().0, "not_utf8");
        std::fs::write(&p, vec![b' '; MAX_BYTES as usize + 1]).unwrap();
        assert_eq!(load(&p).unwrap_err().0, "file_too_large");
        // Writable by others.
        std::fs::write(&p, br#"{"version":1}"#).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(load(&p).unwrap_err().0, "writable_by_group_or_others");
        // Directory and symlink are not regular files.
        let dir = d.path().join("dir.json");
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(load(&dir).unwrap_err().0, "not_a_regular_file");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = d.path().join("link.json");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert_eq!(load(&link).unwrap_err().0, "not_a_regular_file");
        // Unreadable: not NotFound, so not "absent".
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&p).is_err() {
            assert_eq!(load(&p).unwrap_err().0, "unreadable");
        }
    }

    /// Every field of the TS setup is accounted for. The real TS-shaped fixture (a synthetic
    /// nodeSetup.json made with the TS libraries) is the source of the field list.
    #[test]
    fn every_ts_field_has_a_disposition_and_none_is_dropped_silently() {
        let fixture = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ts-setup/setup-small.json"),
        )
        .unwrap();
        let ts: Value = serde_json::from_slice(&fixture).unwrap();
        for k in ts.as_object().unwrap().keys() {
            assert!(disposition(k).is_some(), "TS field {k} has no disposition");
        }
        // And the declared list covers define.d.ts, including the in-memory-only fields.
        for k in [
            "ipV4",
            "ipV4Port",
            "ipV6",
            "ipV6Port",
            "keychain",
            "keyObj",
            "storage_price",
            "outbound_price",
            "DL_registeredData",
            "pgpKeyObj",
            "cpus",
            "pgpKey",
            "passwd",
            "platform_verison",
            "dl_publicKeyArmored",
            "sslDate",
            "restartBlockNumber",
        ] {
            assert!(disposition(k).is_some(), "{k}");
        }
        assert_eq!(TS_FIELDS.len(), 17);
    }

    #[test]
    fn each_ts_field_in_init_json_is_consumed_ignored_or_refused() {
        let samples = [
            ("ipV4", json!("203.0.113.9")),
            ("ipV4Port", json!(8081)),
            ("ipV6", json!("")),
            ("ipV6Port", json!(8081)),
            ("keychain", json!("{}")),
            ("keyObj", json!({})),
            ("storage_price", json!(0.01)),
            ("outbound_price", json!(0.00001)),
            ("DL_registeredData", json!("")),
            ("pgpKeyObj", json!({})),
            ("cpus", json!(4)),
            ("pgpKey", json!({"privateKey": "x"})),
            ("passwd", json!("x")),
            ("platform_verison", json!("1.0.0")),
            ("dl_publicKeyArmored", json!("")),
            ("sslDate", json!(1700000000000u64)),
            ("restartBlockNumber", json!(0)),
        ];
        assert_eq!(samples.len(), TS_FIELDS.len());
        for (name, value) in samples {
            let r = parse_value(&json!({"version": 1, name: value}));
            match disposition(name).unwrap() {
                Disposition::Refused => {
                    assert_eq!(r.unwrap_err().0, format!("secret_field_not_allowed:{name}"));
                }
                Disposition::Consumed(setting) => {
                    let c = r.unwrap();
                    assert_eq!(c.ts_consumed, vec![name], "{name}");
                    match setting {
                        "http_port" => assert_eq!(c.http_port, Some(8081)),
                        "public_ip" => assert_eq!(
                            c.public_ip,
                            Some(PublicIp::List(vec!["203.0.113.9".parse().unwrap()]))
                        ),
                        other => panic!("unmapped setting {other}"),
                    }
                }
                Disposition::Ignored(_) => {
                    let c = r.unwrap();
                    assert_eq!(c.legacy_ignored, vec![name], "{name} was dropped silently");
                }
            }
        }
    }

    #[test]
    fn ts_aliases_conflict_with_their_native_names_and_empty_ipv4_is_unset() {
        assert_eq!(
            err(json!({"version":1,"http_port":80,"ipV4Port":81})),
            "conflict:ipV4Port,http_port"
        );
        assert_eq!(
            err(json!({"version":1,"public_ip":"auto","ipV4":"203.0.113.9"})),
            "conflict:ipV4,public_ip"
        );
        let c = ok(json!({"version":1,"ipV4":""}));
        assert_eq!(c.public_ip, None);
        assert_eq!(c.legacy_ignored, vec!["ipV4"]);
        assert_eq!(
            err(json!({"version":1,"ipV4":"2001:db8::1"})),
            "bad_value:ipV4"
        );
        assert_eq!(err(json!({"version":1,"cpus":-1})), "bad_value:cpus");
    }

    #[test]
    fn generate_confirmation_only_belongs_to_generate() {
        assert!(ok(json!({"version":1,"identity":{"mode":"generate","confirm_generate_on_ts_host":true}}))
            .identity
            .confirm_generate_on_ts_host);
        assert_eq!(
            err(json!({"version":1,"identity":{"mode":"auto","confirm_generate_on_ts_host":true}})),
            "identity.confirm_without_generate"
        );
        assert_eq!(
            err(
                json!({"version":1,"identity":{"mode":"generate","confirm_generate_on_ts_host":"yes"}})
            ),
            "bad_value:identity.confirm_generate_on_ts_host"
        );
    }
}
