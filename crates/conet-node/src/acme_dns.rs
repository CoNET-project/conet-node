//! ACME DNS-01 through the project's DNS daemon (decision W42; Q74 keeps TLS-ALPN-01 for nodes
//! that hold :443). Several nodes can share one IP on different ports, and only one of them can
//! answer TLS-ALPN-01 on :443, so the others prove the name through DNS instead.
//!
//! The certificate key is made and kept here; the daemon never sees it. The node only asks the
//! daemon, with a wallet-signed request (`si_proto::acme::dns01_text`, signed by the signer
//! process), to set or delete `_acme-challenge.{keyId}.conet.network`.
use crate::server::NodeCtx;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use si_core::NodeNotices;
use si_proto::acme as pa;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// How the HTTPS listener gets its certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcmeMode {
    /// TLS-ALPN-01, answered on the listener itself; works only on port 443.
    Alpn,
    /// DNS-01 through the DNS daemon; any port.
    Dns01,
}

/// `--acme-mode`: `alpn`, `dns01`, or `auto` (the default): ALPN when the HTTPS listener is on
/// 443, DNS-01 otherwise (Q74).
pub fn choose_mode(flag: Option<&str>, tls_port: u16) -> Result<AcmeMode, String> {
    match flag.unwrap_or("auto") {
        "alpn" if tls_port != 443 => {
            Err("--acme-mode alpn needs the HTTPS listener on port 443".into())
        }
        "alpn" => Ok(AcmeMode::Alpn),
        "dns01" => Ok(AcmeMode::Dns01),
        "auto" if tls_port == 443 => Ok(AcmeMode::Alpn),
        "auto" => Ok(AcmeMode::Dns01),
        other => Err(format!("--acme-mode {other}: use alpn, dns01 or auto")),
    }
}

#[derive(Clone, Debug)]
pub struct Dns01Opts {
    /// Must be `{keyId}.conet.network`: the daemon derives the TXT name from the key ID.
    pub domain: String,
    /// Account credentials and the current certificate live here (key files mode 0600).
    pub cache: PathBuf,
    pub contact: Vec<String>,
    pub directory: String,
    /// Extra root for the ACME server's own HTTPS (test servers such as Pebble only).
    pub directory_root: Option<PathBuf>,
    /// Base URL of the DNS daemon; requests go to `{daemon}/acme/dns01`.
    pub daemon: String,
    /// Renew this long before the certificate expires.
    pub renew_before: Duration,
    /// Extra wait after the daemon confirms the TXT record, before asking for validation.
    pub settle: Duration,
}

impl Dns01Opts {
    pub fn new(domain: String, cache: PathBuf, daemon: String) -> Self {
        Self {
            domain,
            cache,
            contact: Vec::new(),
            directory: LETS_ENCRYPT.into(),
            directory_root: None,
            daemon,
            renew_before: Duration::from_secs(30 * 86400),
            settle: Duration::from_secs(5),
        }
    }
}

/// Certificate the listener serves; replaced in place on renewal.
#[derive(Debug, Default)]
pub struct CertSlot(RwLock<Option<Arc<CertifiedKey>>>);

impl CertSlot {
    pub fn get(&self) -> Option<Arc<CertifiedKey>> {
        self.0.read().expect("cert slot").clone()
    }
    fn set(&self, ck: Arc<CertifiedKey>) {
        *self.0.write().expect("cert slot") = Some(ck);
    }
}

impl ResolvesServerCert for CertSlot {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.get()
    }
}

/// Node side of the daemon protocol.
pub struct DnsDaemon {
    url: String,
    key_id: String,
    wallet: String,
    notices: Arc<dyn NodeNotices>,
    http: reqwest::Client,
}

impl DnsDaemon {
    pub fn new(url: &str, key_id: &str, wallet: &str, notices: Arc<dyn NodeNotices>) -> Self {
        Self {
            url: format!("{}/acme/dns01", url.trim_end_matches('/')),
            key_id: key_id.to_ascii_uppercase(),
            wallet: wallet.to_ascii_lowercase(),
            notices,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("http client"),
        }
    }

    /// Signed request body (JSON) for one TXT operation.
    pub async fn request_body(&self, value: &str, op: &str) -> Result<String, String> {
        let exp = now_secs() + 300;
        let (n, k, v, o) = (
            self.notices.clone(),
            self.key_id.clone(),
            value.to_string(),
            op.to_string(),
        );
        let sig = tokio::task::spawn_blocking(move || n.sign_acme_dns01(&k, &v, &o, exp))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "v": 1,
            "keyId": self.key_id,
            "wallet": self.wallet,
            "value": value,
            "op": op,
            "exp": exp,
            "signature": sig,
        })
        .to_string())
    }

    /// The daemon answers 200 once the record is set (or removed) and visible.
    pub async fn call(&self, value: &str, op: &str) -> Result<(), String> {
        let body = self.request_body(value, op).await?;
        let rsp = self
            .http
            .post(&self.url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("dns daemon: {e}"))?;
        if !rsp.status().is_success() {
            return Err(format!("dns daemon: {op} answered {}", rsp.status()));
        }
        Ok(())
    }
}

/// A checked daemon request.
#[derive(Debug, PartialEq, Eq)]
pub struct Dns01Request {
    pub key_id: String,
    pub wallet: String,
    pub value: String,
    pub op: String,
    pub name: String,
}

/// Daemon side: check one request body. The caller must still confirm that `wallet` is the
/// registered node for `key_id` (node table) before writing `name`.
pub fn verify_dns01_request(body: &str, now: i64) -> Result<Dns01Request, String> {
    let j: serde_json::Value = serde_json::from_str(body).map_err(|_| "json")?;
    let s = |k: &str| j[k].as_str().map(str::to_string).ok_or(k.to_string());
    let (key_id, wallet, value, op, sig) = (
        s("keyId")?,
        s("wallet")?,
        s("value")?,
        s("op")?,
        s("signature")?,
    );
    let exp = j["exp"].as_i64().ok_or("exp")?;
    if j["v"].as_i64() != Some(1) {
        return Err("version".into());
    }
    if key_id.is_empty()
        || !key_id.bytes().all(|b| b.is_ascii_hexdigit())
        || !pa::valid_txt_value(&value)
        || !pa::valid_op(&op)
    {
        return Err("fields".into());
    }
    if exp <= now || exp > now + pa::DNS01_MAX_VALID_SEC {
        return Err("expired".into());
    }
    let text = pa::dns01_text(&key_id, &wallet, &value, &op, exp);
    let signer = si_crypto::eth::recover_message(&text, &sig).map_err(|_| "signature")?;
    if !signer.eq_ignore_ascii_case(&wallet) {
        return Err("signature".into());
    }
    Ok(Dns01Request {
        name: pa::challenge_name(&key_id),
        key_id: key_id.to_ascii_uppercase(),
        wallet: wallet.to_ascii_lowercase(),
        value,
        op,
    })
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    std::io::Write::write_all(&mut o.open(&tmp)?, data)?;
    std::fs::rename(tmp, path)
}

/// Parsed certificate in the cache: what the listener serves, and when it runs out.
pub struct Issued {
    pub key: Arc<CertifiedKey>,
    pub not_after: i64,
}

fn load_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Issued, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let leaf = chain.first().ok_or("empty chain")?;
    let (_, x509) = x509_parser::parse_x509_certificate(leaf).map_err(|e| e.to_string())?;
    let not_after = x509.validity().not_after.timestamp();
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| e.to_string())?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let ck = CertifiedKey::from_der(chain, key, &provider).map_err(|e| e.to_string())?;
    Ok(Issued {
        key: Arc::new(ck),
        not_after,
    })
}

fn cert_paths(cache: &Path) -> (PathBuf, PathBuf) {
    (cache.join("dns01-cert.pem"), cache.join("dns01-key.pem"))
}

/// The cached certificate, if there is one for this domain.
pub fn load_cached(opts: &Dns01Opts) -> Option<Issued> {
    let (c, k) = cert_paths(&opts.cache);
    let (c, k) = (std::fs::read(c).ok()?, std::fs::read(k).ok()?);
    let issued = load_pem(&c, &k).ok()?;
    let leaf = issued.key.cert.first()?;
    let (_, x509) = x509_parser::parse_x509_certificate(leaf).ok()?;
    let names_ok = x509
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value.general_names.iter().any(|n| {
                matches!(n, x509_parser::extensions::GeneralName::DNSName(d)
                    if d.eq_ignore_ascii_case(&opts.domain))
            })
        })
        .unwrap_or(false);
    names_ok.then_some(issued)
}

async fn account(opts: &Dns01Opts) -> Result<Account, String> {
    let builder = || match &opts.directory_root {
        Some(root) => Account::builder_with_root(root),
        None => Account::builder(),
    };
    let path = opts.cache.join("dns01-account.json");
    if let Ok(raw) = std::fs::read(&path) {
        let creds: AccountCredentials = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        return builder()
            .map_err(|e| e.to_string())?
            .from_credentials(creds)
            .await
            .map_err(|e| e.to_string());
    }
    let contact: Vec<String> = opts.contact.iter().map(|c| format!("mailto:{c}")).collect();
    let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (acct, creds) = builder()
        .map_err(|e| e.to_string())?
        .create(
            &NewAccount {
                contact: &contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            opts.directory.clone(),
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
    write_private(
        &path,
        &serde_json::to_vec(&creds).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(acct)
}

/// One issuance: order, TXT through the daemon, validation, CSR from a key made here.
/// TXT records are removed afterwards whether or not the order succeeded.
pub async fn issue(opts: &Dns01Opts, daemon: &DnsDaemon) -> Result<Issued, String> {
    std::fs::create_dir_all(&opts.cache).map_err(|e| e.to_string())?;
    let acct = account(opts).await?;
    let ids = [Identifier::Dns(opts.domain.clone())];
    let mut order = acct
        .new_order(&NewOrder::new(&ids))
        .await
        .map_err(|e| e.to_string())?;
    let mut set_values = Vec::new();
    let result = async {
        let mut authz = order.authorizations();
        while let Some(a) = authz.next().await {
            let mut a = a.map_err(|e| e.to_string())?;
            match a.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => return Err(format!("authorization {other:?}")),
            }
            let mut ch = a
                .challenge(ChallengeType::Dns01)
                .ok_or("no dns-01 challenge offered")?;
            let value = ch.key_authorization().dns_value();
            daemon.call(&value, pa::OP_SET).await?;
            set_values.push(value);
            tokio::time::sleep(opts.settle).await;
            ch.set_ready().await.map_err(|e| e.to_string())?;
        }
        let retry = RetryPolicy::new()
            .initial_delay(Duration::from_millis(500))
            .timeout(Duration::from_secs(180));
        let status = order.poll_ready(&retry).await.map_err(|e| e.to_string())?;
        if status != OrderStatus::Ready {
            return Err(format!("order {status:?}"));
        }
        let key_pem = order.finalize().await.map_err(|e| e.to_string())?;
        let cert_pem = order
            .poll_certificate(&retry)
            .await
            .map_err(|e| e.to_string())?;
        Ok((cert_pem, key_pem))
    }
    .await;
    for v in &set_values {
        if let Err(e) = daemon.call(v, pa::OP_DELETE).await {
            warn!(%e, "acme dns-01: TXT cleanup");
        }
    }
    let (cert_pem, key_pem) = result?;
    let issued = load_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
    let (c, k) = cert_paths(&opts.cache);
    write_private(&k, key_pem.as_bytes()).map_err(|e| e.to_string())?;
    write_private(&c, cert_pem.as_bytes()).map_err(|e| e.to_string())?;
    Ok(issued)
}

/// Keep `slot` filled: serve the cached certificate, issue when missing, renew before expiry,
/// back off on failure (1 min doubling to 6 h).
pub async fn run(opts: Dns01Opts, daemon: DnsDaemon, slot: Arc<CertSlot>) {
    let mut not_after = match load_cached(&opts) {
        Some(c) => {
            slot.set(c.key);
            info!(domain = %opts.domain, "acme dns-01: cached certificate loaded");
            c.not_after
        }
        None => 0,
    };
    let mut backoff = Duration::from_secs(60);
    loop {
        let renew_at = not_after - opts.renew_before.as_secs() as i64;
        let wait = renew_at - now_secs();
        if wait > 0 {
            tokio::time::sleep(Duration::from_secs(wait.min(12 * 3600) as u64)).await;
            continue;
        }
        match issue(&opts, &daemon).await {
            Ok(c) => {
                info!(domain = %opts.domain, not_after = c.not_after, "acme dns-01: certificate issued");
                not_after = c.not_after;
                slot.set(c.key);
                backoff = Duration::from_secs(60);
            }
            Err(e) => {
                warn!(%e, retry_in = backoff.as_secs(), "acme dns-01");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(6 * 3600));
            }
        }
    }
}

/// Wire DNS-01 for a node: the daemon client signs through the node's notices.
pub fn daemon_for(ctx: &NodeCtx, url: &str) -> DnsDaemon {
    DnsDaemon::new(url, &ctx.key_id, &ctx.wallet.address(), ctx.notices.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_follows_the_port() {
        assert_eq!(choose_mode(None, 443), Ok(AcmeMode::Alpn));
        assert_eq!(choose_mode(None, 8443), Ok(AcmeMode::Dns01));
        assert_eq!(choose_mode(Some("auto"), 443), Ok(AcmeMode::Alpn));
        assert_eq!(choose_mode(Some("dns01"), 443), Ok(AcmeMode::Dns01));
        assert!(choose_mode(Some("alpn"), 8443).is_err());
        assert!(choose_mode(Some("http01"), 443).is_err());
    }
}
