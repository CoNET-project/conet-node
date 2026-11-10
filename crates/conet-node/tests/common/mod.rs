//! A minimal local JSON-RPC over HTTP for read-layer tests: `answer(method, params)` gives the
//! `result` of each request; an answer `{"__rpc_error": {...}}` is sent as the JSON-RPC `error`
//! instead (e.g. a revert with its data). Test data only; binds 127.0.0.1 on a free port.
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// `answer(method, params) -> result`.
pub type Answer = Arc<dyn Fn(&str, &Value) -> Value + Send + Sync>;

pub async fn serve(answer: Answer) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let answer = answer.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let body = loop {
                    let k = s.read(&mut tmp).await.unwrap();
                    if k == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..k]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(h) = text.find("\r\n\r\n") {
                        let len = text[..h]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if buf.len() >= h + 4 + len {
                            break buf[h + 4..h + 4 + len].to_vec();
                        }
                    }
                };
                let req: Value = serde_json::from_slice(&body).unwrap();
                let result = answer(req["method"].as_str().unwrap(), &req["params"]);
                let out = match result.get("__rpc_error") {
                    Some(e) => json!({ "jsonrpc": "2.0", "id": 1, "error": e }),
                    None => json!({ "jsonrpc": "2.0", "id": 1, "result": result }),
                }
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}",
                    out.len()
                );
                s.write_all(resp.as_bytes()).await.unwrap();
            });
        }
    });
    url
}
