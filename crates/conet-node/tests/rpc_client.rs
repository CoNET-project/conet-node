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

/// A JSON-RPC revert answered with HTTP 500, as some nodes do. The message and `data` must survive.
const REVERT_500: &str = r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":"0x2c2e6b3c"}}"#;

#[tokio::test]
async fn a_500_with_a_json_rpc_revert_keeps_the_message_and_data() {
    let s = stub(500, None, REVERT_500).await;
    let rpc = Rpc::new(&s.url).unwrap();
    let err = rpc
        .block_number()
        .await
        .expect_err("a 500 must stay an error");
    assert!(
        err.0.contains("execution reverted"),
        "message lost: {}",
        err.0
    );
    // The revert data is read from this JSON text by service_order::revert_name.
    let v: Value = serde_json::from_str(&err.0).expect("error text is JSON");
    assert_eq!(v["data"], "0x2c2e6b3c");
}

#[tokio::test]
async fn a_500_json_rpc_error_without_revert_keeps_its_message() {
    let s = stub(
        500,
        None,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"header not found"}}"#,
    )
    .await;
    let rpc = Rpc::new(&s.url).unwrap();
    let err = rpc
        .block_number()
        .await
        .expect_err("a 500 must stay an error");
    assert!(
        err.0.contains("header not found"),
        "message lost: {}",
        err.0
    );
}

#[tokio::test]
async fn a_non_json_rpc_non_2xx_reports_only_the_http_code_and_not_the_body() {
    let s = stub(502, None, "<html>upstream-secret-body</html>").await;
    let rpc = Rpc::new(&s.url).unwrap();
    let err = rpc
        .block_number()
        .await
        .expect_err("a 502 must stay an error");
    assert_eq!(err.0, "rpc HTTP 502");
    assert!(!err.0.contains("upstream-secret-body"));
}

#[tokio::test]
async fn address_pgp_unknown_key_is_none_when_the_revert_arrives_as_a_500() {
    use conet_node::chain::{AddressPgp, UserRoutes};
    // Unknown key: AddressPGP reverts. The 500 answer must still read as "no route", not an error.
    let s = stub(500, None, REVERT_500).await;
    let pgp = AddressPgp::new(Rpc::new(&s.url).unwrap());
    assert_eq!(pgp.route_of_user_key("0x00").await.unwrap(), None);
    // A 500 that is not a revert stays an error.
    let other = stub(
        500,
        None,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"header not found"}}"#,
    )
    .await;
    let pgp = AddressPgp::new(Rpc::new(&other.url).unwrap());
    assert!(pgp.route_of_user_key("0x00").await.is_err());
}
