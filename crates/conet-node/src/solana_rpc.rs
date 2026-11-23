//! HTTP-only port of CoNET-SI `forwardToSolanaRpc` (`/solana-rpc`).
//!
//! The upstream is fixed to HTTPS `api.mainnet-beta.solana.com`. Redirects are not followed,
//! response status and body are preserved, and request/response hop-by-hop headers are rebuilt.
//! WebSocket is intentionally unsupported; `server::handle` rejects Upgrade before this module
//! can make any upstream request.
use crate::http::Request;
use futures_util::StreamExt;
use reqwest::header::{HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING};
use reqwest::{Client, Method, StatusCode, Url};
use std::time::Duration;

pub const SOLANA_RPC_UPSTREAM: &str = "https://api.mainnet-beta.solana.com";
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum ProxyError {
    BadRequest,
    Upstream,
    Redirect,
    TooLarge,
}

#[derive(Debug)]
pub struct ProxyReply {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone)]
pub struct SolanaRpcProxy {
    client: Client,
}

impl SolanaRpcProxy {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_timeout(Duration::from_secs(30))
    }

    fn with_timeout(timeout: Duration) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: Client::builder()
                .timeout(timeout)
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    pub async fn forward(&self, request: &Request) -> Result<ProxyReply, ProxyError> {
        self.forward_at(request, SOLANA_RPC_UPSTREAM).await
    }

    async fn forward_at(&self, request: &Request, base: &str) -> Result<ProxyReply, ProxyError> {
        if request_has_upgrade(request) {
            return Err(ProxyError::BadRequest);
        }
        let method =
            Method::from_bytes(request.method.as_bytes()).map_err(|_| ProxyError::BadRequest)?;
        if !matches!(
            method,
            Method::GET
                | Method::HEAD
                | Method::POST
                | Method::PUT
                | Method::PATCH
                | Method::DELETE
                | Method::OPTIONS
        ) {
            return Err(ProxyError::BadRequest);
        }
        let path = request
            .path
            .split('#')
            .next()
            .ok_or(ProxyError::BadRequest)?;
        if !is_solana_rpc_path(path) || path.starts_with("//") || path.contains('\\') {
            return Err(ProxyError::BadRequest);
        }
        let mut url = Url::parse(base).map_err(|_| ProxyError::BadRequest)?;
        // This URL is fixed in production; only tests pass a loopback base. The client-provided
        // path can never replace its authority or scheme.
        let (path_only, query) = path.split_once('?').unwrap_or((path, ""));
        url.set_path(path_only);
        url.set_query((!query.is_empty()).then_some(query));

        let mut builder = self.client.request(method.clone(), url);
        for line in &request.header_lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() || is_hop_header(name) || name.eq_ignore_ascii_case("host") {
                continue;
            }
            let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value.trim()),
            ) else {
                return Err(ProxyError::BadRequest);
            };
            builder = builder.header(name, value);
        }
        if method != Method::GET && method != Method::HEAD {
            builder = builder.body(request.body.clone());
        }
        let response = builder.send().await.map_err(|_| ProxyError::Upstream)?;
        let status = response.status();
        // A redirect response can otherwise send the caller to an unconfigured host. Refuse it
        // explicitly and do not expose Location to the client.
        if status.is_redirection() {
            return Err(ProxyError::Redirect);
        }
        let headers = response
            .headers()
            .iter()
            .filter(|(name, _)| {
                !is_hop_header(name.as_str())
                    && !name.as_str().starts_with("access-control-")
                    && !name.as_str().eq_ignore_ascii_case("date")
                    && !name.as_str().eq_ignore_ascii_case("allow")
            })
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ProxyError::Upstream)?;
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(ProxyError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(ProxyReply {
            status,
            headers,
            body,
        })
    }
}

pub fn is_solana_rpc_path(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    path.eq_ignore_ascii_case("/solana-rpc")
        || path.get("/solana-rpc".len()..).is_some_and(|tail| {
            path[.."/solana-rpc".len()].eq_ignore_ascii_case("/solana-rpc") && tail.starts_with('/')
        })
}

fn request_has_upgrade(request: &Request) -> bool {
    request.method.eq_ignore_ascii_case("upgrade")
        || request.header_lines.iter().any(|line| {
            let Some((name, value)) = line.split_once(':') else {
                return false;
            };
            name.trim().eq_ignore_ascii_case("upgrade")
                || (name.trim().eq_ignore_ascii_case("connection")
                    && value
                        .split(',')
                        .any(|v| v.trim().eq_ignore_ascii_case("upgrade")))
        })
}

fn is_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(CONNECTION.as_str())
        || name.eq_ignore_ascii_case(TRANSFER_ENCODING.as_str())
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str())
        || name.eq_ignore_ascii_case("expect")
        || name.eq_ignore_ascii_case("proxy-connection")
}

pub fn encode_reply(reply: ProxyReply) -> Vec<u8> {
    let reason = reply.status.canonical_reason().unwrap_or("Upstream");
    let mut out = format!("HTTP/1.1 {} {}\r\n", reply.status.as_u16(), reason);
    for (name, value) in reply.headers {
        out.push_str(&name);
        out.push_str(": ");
        out.push_str(&value);
        out.push_str("\r\n");
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        reply.body.len()
    ));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&reply.body);
    bytes
}

pub fn bad_gateway() -> Vec<u8> {
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn request(method: &str, path: &str, body: &[u8]) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            header_lines: vec![
                "Content-Type: application/json".into(),
                "Host: client.invalid".into(),
            ],
            body: body.into(),
            leftover: vec![],
        }
    }

    #[tokio::test]
    async fn forwards_http_method_path_query_body_and_upstream_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(request.starts_with("POST /solana-rpc?commitment=finalized HTTP/1.1\r\n"));
            assert!(request
                .to_ascii_lowercase()
                .contains("content-type: application/json"));
            assert!(request.ends_with("{\"jsonrpc\":\"2.0\"}"));
            socket.write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"error\":1}").await.unwrap();
        });
        let proxy = SolanaRpcProxy::new().unwrap();
        let req = request(
            "POST",
            "/solana-rpc?commitment=finalized",
            b"{\"jsonrpc\":\"2.0\"}",
        );
        let reply = proxy
            .forward_at(&req, &format!("http://{addr}"))
            .await
            .unwrap();
        assert_eq!(reply.status.as_u16(), 429);
        assert_eq!(reply.body, b"{\"error\":1}");
        upstream.await.unwrap();
    }

    #[tokio::test]
    async fn bad_or_non_rpc_paths_never_reach_upstream() {
        let proxy = SolanaRpcProxy::new().unwrap();
        for path in [
            "//evil.invalid/solana-rpc",
            "/not-rpc",
            "/solana-rpc\\evil",
            "/solana-rpc-suffix",
        ] {
            let req = request("POST", path, b"{}");
            assert!(matches!(
                proxy.forward_at(&req, "http://127.0.0.1:1").await,
                Err(ProxyError::BadRequest)
            ));
        }
    }

    #[tokio::test]
    async fn upgrade_is_rejected_before_opening_upstream_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let proxy = SolanaRpcProxy::new().unwrap();
        let mut req = request("GET", "/solana-rpc", b"");
        req.header_lines.extend([
            "Connection: keep-alive, Upgrade".into(),
            "Upgrade: websocket".into(),
        ]);
        assert!(matches!(
            proxy.forward_at(&req, &format!("http://{addr}")).await,
            Err(ProxyError::BadRequest)
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_millis(25), listener.accept()).await,
            Err(_)
        ));
    }

    #[tokio::test]
    async fn redirect_is_rejected_after_one_fixed_upstream_request() {
        for status in [301, 302] {
            let redirect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let redirect_addr = redirect_listener.local_addr().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let upstream = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await.unwrap();
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} Redirect\r\nLocation: http://{redirect_addr}/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            });
            let proxy = SolanaRpcProxy::new().unwrap();
            let req = request("POST", "/solana-rpc", b"{}");
            let error = proxy
                .forward_at(&req, &format!("http://{addr}"))
                .await
                .unwrap_err();
            assert!(matches!(error, ProxyError::Redirect));
            upstream.await.unwrap();
            assert!(matches!(
                tokio::time::timeout(Duration::from_millis(25), redirect_listener.accept()).await,
                Err(_)
            ));
            assert!(String::from_utf8(bad_gateway())
                .unwrap()
                .starts_with("HTTP/1.1 502"));
        }
    }

    #[tokio::test]
    async fn transport_and_timeout_fail_as_explicit_502() {
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let req = request("POST", "/solana-rpc", b"{}");
        let proxy = SolanaRpcProxy::new().unwrap();
        assert!(matches!(
            proxy.forward_at(&req, &format!("http://{addr}")).await,
            Err(ProxyError::Upstream)
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stalled = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let fast = SolanaRpcProxy::with_timeout(Duration::from_millis(10)).unwrap();
        assert!(matches!(
            fast.forward_at(&req, &format!("http://{addr}")).await,
            Err(ProxyError::Upstream)
        ));
        stalled.await.unwrap();
        assert!(String::from_utf8(bad_gateway())
            .unwrap()
            .starts_with("HTTP/1.1 502"));
    }
}
