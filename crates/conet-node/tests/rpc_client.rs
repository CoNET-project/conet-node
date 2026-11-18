//! The JSON-RPC client never follows a redirect and never reads a non-2xx answer as a result.
//! In-process loopback stubs only (127.0.0.1, ephemeral ports); no network.
use conet_node::chain::Rpc;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Stub {
    url: String,
    hits: Arc<AtomicUsize>,
}

/// Answers every request with `status`, an optional Location header and `body`.
async fn stub(status: u16, location: Option<String>, body: &'static str) -> Stub {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let (h, location) = (h.clone(), location.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let k = match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => k,
                    };
                    buf.extend_from_slice(&tmp[..k]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(p) = text.find("\r\n\r\n") {
                        let len: usize = text[..p]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        if buf.len() >= p + 4 + len {
                            break;
                        }
                    }
                }
                h.fetch_add(1, Ordering::SeqCst);
                let loc = location
                    .map(|l| format!("Location: {l}\r\n"))
                    .unwrap_or_default();
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{loc}Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    Stub { url, hits }
}

const OK_RESULT: &str = r#"{"jsonrpc":"2.0","id":1,"result":"0x2a"}"#;

#[tokio::test]
async fn a_redirect_is_an_error_and_the_target_is_never_contacted() {
    for status in [301u16, 302, 307, 308] {
        let landing = stub(200, None, OK_RESULT).await;
        let front = stub(status, Some(format!("{}/x", landing.url)), "").await;
        let rpc = Rpc::new(&front.url).unwrap();
        assert!(
            rpc.block_number().await.is_err(),
            "status {status} was followed"
        );
        assert_eq!(front.hits.load(Ordering::SeqCst), 1, "status {status}");
        assert_eq!(
            landing.hits.load(Ordering::SeqCst),
            0,
            "status {status}: target contacted"
        );
    }
}

#[tokio::test]
async fn a_non_2xx_answer_is_an_error_even_with_a_result_body() {
    for status in [400u16, 404, 500, 503] {
        let s = stub(status, None, OK_RESULT).await;
        let rpc = Rpc::new(&s.url).unwrap();
        assert!(
            rpc.block_number().await.is_err(),
            "status {status} read as a result"
        );
    }
}

#[tokio::test]
async fn a_200_with_a_result_is_read_and_a_200_with_an_error_is_an_error() {
    let ok = stub(200, None, OK_RESULT).await;
    let rpc = Rpc::new(&ok.url).unwrap();
    assert_eq!(rpc.block_number().await.unwrap(), 42);
    let err = stub(
        200,
        None,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}"#,
    )
    .await;
    let rpc = Rpc::new(&err.url).unwrap();
    assert!(rpc.block_number().await.is_err());
    let _: Value = json!(null);
}
