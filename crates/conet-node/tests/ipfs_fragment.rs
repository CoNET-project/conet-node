//! The CoNET IPFS API client with verified acceptance, and the node-local sealing layer, against a LOCAL fake of the API (loopback only; synthetic bytes). The fake can be told to
//! answer 200 {ok:true,hash} and store nothing, to return a wrong hash, to lose or change the object on read, and to refuse (402, 403,
//! 500). Expected semantics: an acceptance is confirmed only when the answer's hash equals the local keccak256 AND the object read back is byte-for-byte equal.
use conet_node::ipfs_fragment::{FragmentClient, GetError, LocalSeal, PutError, SealError};
use serde_json::{json, Value};
use si_crypto::eth::{eip191_hash, keccak_hex, recover_digest, EthKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Honest,
    /// A fake endpoint that answers 200 {ok:true,hash} and stores nothing.
    FalseSuccess,
    WrongHash,
    NotOk,
    ReadMissing,
    ReadMutated,
    Status(u16),
    /// The POST answers 307 to another path.
    PostRedirect,
    /// The read answers 302 to another path that holds the object.
    GetRedirect,
    /// The read answers with 5 MiB.
    BigBody,
    /// Reads the request and never answers.
    Stall,
}

#[derive(Default)]
struct Seen {
    posts: usize,
    gets: usize,
    redirect_target_hits: usize,
    last_post_body: String,
    signature_ok: Option<bool>,
}

struct Fake {
    addr: std::net::SocketAddr,
    mode: Arc<Mutex<Mode>>,
    store: Arc<Mutex<HashMap<String, String>>>,
    seen: Arc<Mutex<Seen>>,
}

async fn start(mode: Mode) -> Fake {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let mode = Arc::new(Mutex::new(mode));
    let store: Arc<Mutex<HashMap<String, String>>> = Default::default();
    let seen: Arc<Mutex<Seen>> = Default::default();
    let (m2, s2, n2) = (mode.clone(), store.clone(), seen.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = l.accept().await else {
                return;
            };
            let (mode, store, seen) = (m2.clone(), s2.clone(), n2.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                let (head_end, clen) = loop {
                    let n = c.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
                        let clen = head
                            .lines()
                            .find_map(|l| {
                                l.strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        break (p + 4, clen);
                    }
                };
                while buf.len() < head_end + clen {
                    let n = c.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                let line = head.lines().next().unwrap_or("").to_string();
                let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
                let mode = *mode.lock().unwrap();
                let respond = |status: u16, body: Vec<u8>| {
                    let mut out = format!("HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
                    out.extend(body);
                    out
                };
                if mode == Mode::Stall {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    return;
                }
                let reply = if line.starts_with("GET /elsewhere") {
                    seen.lock().unwrap().redirect_target_hits += 1;
                    let v = store
                        .lock()
                        .unwrap()
                        .values()
                        .next()
                        .cloned()
                        .unwrap_or_default();
                    respond(200, v.into_bytes())
                } else if line.starts_with("POST /storageFragment") && mode == Mode::PostRedirect {
                    seen.lock().unwrap().posts += 1;
                    let mut out = b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
                    out.shrink_to_fit();
                    out
                } else if line.starts_with("POST /storageFragment") {
                    seen.lock().unwrap().posts += 1;
                    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                    seen.lock().unwrap().last_post_body = body.clone();
                    let wallet = v["wallet"].as_str().unwrap_or("").to_string();
                    let sig = v["signMessage"].as_str().unwrap_or("").to_string();
                    let image = v["image"].as_str().unwrap_or("").to_string();
                    // the same check as the real handler: the signature is the wallet's EIP-191 signature of its own address text
                    let ok_sig = recover_digest(&eip191_hash(wallet.as_bytes()), &sig)
                        .map(|a| a.eq_ignore_ascii_case(&wallet))
                        .unwrap_or(false);
                    seen.lock().unwrap().signature_ok = Some(ok_sig);
                    let hash = keccak_hex(&image);
                    match mode {
                        Mode::Status(s) => respond(s, b"{}".to_vec()),
                        _ if !ok_sig => respond(403, vec![]),
                        Mode::Honest
                        | Mode::ReadMissing
                        | Mode::ReadMutated
                        | Mode::GetRedirect
                        | Mode::BigBody
                        | Mode::PostRedirect
                        | Mode::Stall => {
                            store.lock().unwrap().insert(
                                hash.clone(),
                                if mode == Mode::ReadMutated {
                                    format!("{image}x")
                                } else {
                                    image
                                },
                            );
                            respond(
                                200,
                                json!({ "ok": true, "hash": hash }).to_string().into_bytes(),
                            )
                        }
                        Mode::FalseSuccess => respond(
                            200,
                            json!({ "ok": true, "hash": hash }).to_string().into_bytes(),
                        ),
                        Mode::WrongHash => respond(
                            200,
                            json!({ "ok": true, "hash": keccak_hex("something else") })
                                .to_string()
                                .into_bytes(),
                        ),
                        Mode::NotOk => {
                            respond(200, json!({ "ok": false }).to_string().into_bytes())
                        }
                    }
                } else if line.starts_with("GET /getFragment") {
                    seen.lock().unwrap().gets += 1;
                    let hash = line
                        .split("hash=")
                        .nth(1)
                        .and_then(|r| r.split_whitespace().next())
                        .unwrap_or("")
                        .to_string();
                    match (mode, store.lock().unwrap().get(&hash).cloned()) {
                        (Mode::BigBody, _) => respond(200, vec![b'A'; 5 * 1024 * 1024]),
                        (Mode::GetRedirect, Some(_)) => b"HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                        (Mode::ReadMissing, _) | (_, None) => respond(404, vec![]),
                        (_, Some(v)) => respond(200, v.into_bytes()),
                    }
                } else {
                    respond(404, vec![])
                };
                let _ = c.write_all(&reply).await;
            });
        }
    });
    Fake {
        addr,
        mode,
        store,
        seen,
    }
}

fn qa_wallet() -> EthKey {
    // a throwaway key of this test run, never a real wallet
    EthKey::from_hex("0x1111111111111111111111111111111111111111111111111111111111111111").unwrap()
}

fn client(f: &Fake) -> FragmentClient {
    FragmentClient::new(&format!("http://{}", f.addr), qa_wallet()).unwrap()
}

fn synthetic(n: usize) -> String {
    format!("{}{}", "Zm9v", "A".repeat(n))
}

#[tokio::test(flavor = "multi_thread")]
async fn an_honest_api_gives_a_verified_acceptance_and_a_cold_read() {
    let f = start(Mode::Honest).await;
    let c = client(&f);
    for n in [1000usize, 3000, 65_000] {
        let img = synthetic(n);
        let h = c.put_verified(&img).await.unwrap();
        assert_eq!(
            h,
            keccak_hex(&img),
            "the content address is the keccak256 of the uploaded string"
        );
        // a second, independent client (no shared state) reads it back, and verifies the address
        let cold = client(&f).get_verified(&h).await.unwrap();
        assert_eq!(cold, img);
    }
    assert_eq!(
        f.seen.lock().unwrap().signature_ok,
        Some(true),
        "the signature the API checks is the wallet's signature of its own address"
    );
    // the same content twice: the same address, the same bytes
    let img = synthetic(500);
    let (a, b) = (
        c.put_verified(&img).await.unwrap(),
        c.put_verified(&img).await.unwrap(),
    );
    assert_eq!(a, b);
    assert_eq!(f.store.lock().unwrap().len(), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_false_success_200_without_storing_is_not_an_acceptance() {
    let f = start(Mode::FalseSuccess).await;
    let r = client(&f).put_verified(&synthetic(800)).await;
    println!("MEASURE false success (200, ok:true, correct hash, nothing stored): {r:?}");
    assert_eq!(r, Err(PutError::ReadBackMissing(404)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_hash_in_the_answer_is_not_an_acceptance() {
    let f = start(Mode::WrongHash).await;
    let r = client(&f).put_verified(&synthetic(800)).await;
    println!("MEASURE wrong hash: {r:?}");
    assert!(matches!(r, Err(PutError::HashMismatch { .. })));
    assert_eq!(
        f.seen.lock().unwrap().gets,
        0,
        "no read is attempted after a wrong hash"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_or_changed_read_back_is_not_an_acceptance() {
    let f = start(Mode::ReadMissing).await;
    assert_eq!(
        client(&f).put_verified(&synthetic(800)).await,
        Err(PutError::ReadBackMissing(404))
    );
    *f.mode.lock().unwrap() = Mode::ReadMutated;
    assert_eq!(
        client(&f).put_verified(&synthetic(800)).await,
        Err(PutError::ReadBackMismatch)
    );
    *f.mode.lock().unwrap() = Mode::NotOk;
    assert_eq!(
        client(&f).put_verified(&synthetic(800)).await,
        Err(PutError::NotOk)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals_and_payment_requests_are_errors_and_stop_conditions() {
    for (s, stop) in [
        (402u16, true),
        (403, true),
        (500, true),
        (503, true),
        (404, false),
    ] {
        let f = start(Mode::Status(s)).await;
        let e = client(&f).put_verified(&synthetic(100)).await.unwrap_err();
        assert_eq!(e, PutError::Status(s));
        assert_eq!(e.is_stop_condition(), stop, "status {s}");
    }
    // a transport failure (nothing listens)
    let c = FragmentClient::new("http://127.0.0.1:1", qa_wallet()).unwrap();
    assert!(matches!(
        c.put_verified(&synthetic(100)).await,
        Err(PutError::Transport(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_object_is_rejected_when_it_does_not_hash_to_its_address() {
    let f = start(Mode::Honest).await;
    let c = client(&f);
    let h = c.put_verified(&synthetic(300)).await.unwrap();
    f.store
        .lock()
        .unwrap()
        .insert(h.clone(), "tampered".to_string());
    assert_eq!(c.get_verified(&h).await, Err(GetError::HashMismatch));
    assert_eq!(
        c.get_verified(&keccak_hex("never stored")).await,
        Err(GetError::Status(404))
    );
}

/// The local layer: byte-exact restoration, the ACK hash of the original armor stays valid, a wrong key or a changed byte fails, and nothing identifying is in the uploaded string.
#[test]
fn the_local_layer_restores_the_armor_exactly_and_hides_the_key_id() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use si_crypto::opgp;
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    let g: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let user =
        opgp::PublicCert::from_armor(g["keys"]["user"]["armoredPublic"].as_str().unwrap()).unwrap();
    let armor = opgp::encrypt(
        ChaCha20Rng::from_seed([5; 32]),
        b"synthetic mail body",
        &user,
        opgp::EncryptOpts {
            text: true,
            zlib: true,
            sign_with: None,
        },
    )
    .unwrap();
    // the armor, as it is, carries the recipient's key ID in its packet header
    let key_id_hex = g["keys"]["user"]["encKeyId"]
        .as_str()
        .unwrap()
        .to_lowercase();
    let key_id = hex::decode(&key_id_hex).unwrap();
    let body: String = armor
        .lines()
        .filter(|l| {
            !l.starts_with("-----")
                && !l.starts_with('=')
                && !l.contains(':')
                && !l.trim().is_empty()
        })
        .collect();
    let raw = B64.decode(body.trim()).unwrap();
    assert!(
        raw.windows(8).any(|w| w == key_id.as_slice()),
        "the unsealed armor exposes the recipient's key ID (this is why the layer is mandatory)"
    );

    let key = [7u8; 32];
    let seal = LocalSeal::new(&key);
    let sealed = seal.seal(&armor);
    let up = B64.decode(&sealed).unwrap();
    assert!(
        !up.windows(8).any(|w| w == key_id.as_slice()),
        "the key ID bytes are not in the uploaded bytes"
    );
    let lower = sealed.to_lowercase();
    assert!(
        !lower.contains(&key_id_hex) && !sealed.contains("PGP") && !sealed.contains("BEGIN"),
        "no key ID text, no armor header in the uploaded string"
    );
    assert_eq!(
        up.len(),
        12 + armor.len() + 16,
        "nonce, ciphertext of the same length, tag: nothing else"
    );
    // exact restoration and the mailbox's ACK hash
    let back = seal.open(&sealed).unwrap();
    assert_eq!(back, armor);
    assert_eq!(
        keccak_hex(&back),
        keccak_hex(&armor),
        "the ACK hash of the original armor stays valid"
    );
    // a fresh nonce per message: the same armor gives different uploads
    assert_ne!(seal.seal(&armor), sealed);
    // wrong key, a changed byte, truncation, junk
    assert_eq!(
        LocalSeal::new(&[8u8; 32]).open(&sealed),
        Err(SealError::Open)
    );
    let mut bad = up.clone();
    bad[20] ^= 1;
    assert_eq!(seal.open(&B64.encode(bad)), Err(SealError::Open));
    assert_eq!(seal.open(&B64.encode(&up[..20])), Err(SealError::Open));
    assert_eq!(seal.open("not base64!"), Err(SealError::Open));
    // every size: empty, one byte, a multi-hundred-KB armor
    for n in [0usize, 1, 255, 256, 300_000] {
        let a = "a\r\n\0é".repeat(n / 6 + 1)[..]
            .chars()
            .take(n)
            .collect::<String>();
        assert_eq!(seal.open(&seal.seal(&a)).unwrap(), a);
    }
}

/// Redirects are never followed: a 307 on the write is an error (the redirect target is not called), and a 302 on the read is a failed read-back.
#[tokio::test(flavor = "multi_thread")]
async fn redirects_are_not_followed() {
    let f = start(Mode::PostRedirect).await;
    assert_eq!(
        client(&f).put_verified(&synthetic(200)).await,
        Err(PutError::Status(307))
    );
    assert_eq!(
        f.seen.lock().unwrap().redirect_target_hits,
        0,
        "the target of the redirect was not called"
    );
    let g = start(Mode::GetRedirect).await;
    assert_eq!(
        client(&g).put_verified(&synthetic(200)).await,
        Err(PutError::ReadBackMissing(302))
    );
    assert_eq!(
        g.seen.lock().unwrap().redirect_target_hits,
        0,
        "the target of the redirect was not called"
    );
}

/// A read larger than the cap is refused without being held in memory, and a service that never answers ends in an error within the budget.
#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_body_and_a_silent_service_are_bounded() {
    use conet_node::ipfs_fragment::MAX_OBJECT_BYTES;
    assert!(MAX_OBJECT_BYTES < 5 * 1024 * 1024);
    let f = start(Mode::BigBody).await;
    assert_eq!(
        client(&f).put_verified(&synthetic(200)).await,
        Err(PutError::TooLarge)
    );
    let h = keccak_hex(&synthetic(200));
    assert_eq!(client(&f).get_verified(&h).await, Err(GetError::TooLarge));
    let s = start(Mode::Stall).await;
    let t = std::time::Instant::now();
    let r = client(&s).put_verified(&synthetic(200)).await;
    let took = t.elapsed();
    println!(
        "MEASURE a service that never answers: {r:?} after {:.1} s",
        took.as_secs_f64()
    );
    assert!(matches!(
        r,
        Err(PutError::Transport(_)) | Err(PutError::Budget)
    ));
    assert!(
        took.as_secs() <= 21,
        "bounded by the 20 second budget, took {took:?}"
    );
}
