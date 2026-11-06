//! HTTPS listener (:443) with in-process ACME (decision Q13): each node gets a certificate for
//! `{routeKeyID}.conet.network` through TLS-ALPN-01, so nothing else (no certbot, no sudo,
//! issue S4) and no extra port is involved. Browsers on HTTPS pages, browser SIs in particular,
//! can only reach nodes this way. Behaviour on :443 is identical to :80.
use crate::server::{handle, NodeCtx};
use futures_util::StreamExt;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_acme::caches::DirCache;
use rustls_acme::{is_tls_alpn_challenge, AcmeConfig};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::LazyConfigAcceptor;
use tracing::{debug, info, warn};

pub enum TlsSource {
    /// Let's Encrypt via TLS-ALPN-01. `cache` keeps the account and certificate across restarts,
    /// so a restart never re-issues (rate limits).
    Acme {
        domain: String,
        cache: PathBuf,
        contact: Vec<String>,
        production: bool,
    },
    /// Fixed PEM files (tests, local networks).
    Static { cert_pem: Vec<u8>, key_pem: Vec<u8> },
}

/// Default certificate name: the route key ID, as live SI uses (`{keyID}.conet.network`).
pub fn node_domain(route_key_id: &str) -> String {
    format!("{}.conet.network", route_key_id.to_ascii_lowercase())
}

fn static_config(cert_pem: &[u8], key_pem: &[u8]) -> std::io::Result<Arc<ServerConfig>> {
    let bad = |e: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, e);
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| bad(e.to_string()))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| bad(e.to_string()))?;
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| bad(e.to_string()))?;
    Ok(Arc::new(cfg))
}

pub async fn serve_tls(
    listener: TcpListener,
    ctx: Arc<NodeCtx>,
    src: TlsSource,
) -> std::io::Result<()> {
    let (default_cfg, challenge_cfg) = match src {
        TlsSource::Static { cert_pem, key_pem } => (static_config(&cert_pem, &key_pem)?, None),
        TlsSource::Acme {
            domain,
            cache,
            contact,
            production,
        } => {
            let mut state = AcmeConfig::new([domain.clone()])
                .contact(contact.into_iter().map(|c| format!("mailto:{c}")))
                .cache(DirCache::new(cache))
                .directory_lets_encrypt(production)
                .state();
            let challenge = state.challenge_rustls_config();
            let default = state.default_rustls_config();
            tokio::spawn(async move {
                while let Some(ev) = state.next().await {
                    match ev {
                        Ok(ok) => info!(?ok, "acme"),
                        Err(err) => warn!(%err, "acme"),
                    }
                }
            });
            info!(%domain, production, "acme certificate management started");
            (default, Some(challenge))
        }
    };
    let slots = Arc::new(Semaphore::new(ctx.max_connections));
    loop {
        let (tcp, peer) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let Some(slot) = ctx
            .ip_limiter
            .admit(peer.ip(), ctx.routes.is_node_ip(peer.ip()))
        else {
            continue;
        };
        let (ctx, default_cfg, challenge_cfg) =
            (ctx.clone(), default_cfg.clone(), challenge_cfg.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let _slot = slot;
            let _ = tcp.set_nodelay(true);
            let start = match tokio::time::timeout(
                Duration::from_secs(10),
                LazyConfigAcceptor::new(Default::default(), tcp),
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => return,
            };
            if is_tls_alpn_challenge(&start.client_hello()) {
                if let Some(cfg) = challenge_cfg {
                    debug!("tls-alpn-01 validation");
                    if let Ok(mut s) = start.into_stream(cfg).await {
                        let _ = s.shutdown().await;
                    }
                }
                return;
            }
            match tokio::time::timeout(Duration::from_secs(10), start.into_stream(default_cfg))
                .await
            {
                Ok(Ok(tls)) => handle(Box::new(tls), peer, ctx).await,
                _ => debug!("tls handshake failed"),
            }
        });
    }
}
