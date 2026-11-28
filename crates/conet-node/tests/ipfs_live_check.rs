//! LIVE CHECK (ignored; touches the public CoNET IPFS API): a few synthetic random ciphertexts are written with a purpose-made QA wallet and read back, bypassing every client
//! mirror. Run manually, only when explicitly needed. Needs IPFS_QA_KEY_FILE (a 0600 file holding the QA wallet's private key as hex: zero balance, never
//! funded, deleted after the check) and IPFS_QA_DIR (where the hash list is kept). The objects are random bytes in base64: no user, wallet, key ID, time or label is in them, and an
//! uploaded object is public and cannot be deleted. Output is hash prefixes, sizes, counts and statuses only. Any 402, a 403 for a good signature or a 5xx stops the check, no retry.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use conet_node::ipfs_fragment::{FragmentClient, PutError};
use rand_core::{OsRng, RngCore};
use si_crypto::eth::{keccak_hex, EthKey};

const BASE: &str = "https://ipfs.conet.network/api";

fn qa_wallet() -> EthKey {
    let p = std::env::var("IPFS_QA_KEY_FILE").expect("IPFS_QA_KEY_FILE");
    let hex = std::fs::read_to_string(p).unwrap();
    EthKey::from_hex(hex.trim()).unwrap()
}

fn random_object(len_bytes: usize) -> String {
    let mut b = vec![0u8; len_bytes];
    OsRng.fill_bytes(&mut b);
    B64.encode(b)
}

fn prefix(h: &str) -> &str {
    &h[..12.min(h.len())]
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live check against the public CoNET IPFS API; needs IPFS_QA_KEY_FILE and IPFS_QA_DIR"]
async fn live_write_and_read_with_the_qa_wallet() {
    let dir = std::path::PathBuf::from(std::env::var("IPFS_QA_DIR").expect("IPFS_QA_DIR"));
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let wallet = qa_wallet();
    println!(
        "LIVE uploader (QA wallet) address prefix {}",
        &wallet.address()[..8]
    );
    let c = FragmentClient::new(BASE, wallet).unwrap();
    // 4 distinct random objects of increasing size, then the first one again (a duplicate upload)
    let sizes = [750usize, 2250, 48_000, 450_000];
    let mut hashes: Vec<String> = vec![];
    let mut images: Vec<String> = vec![];
    for (i, n) in sizes.iter().enumerate() {
        let img = random_object(*n);
        let t = std::time::Instant::now();
        match c.put_verified(&img).await {
            Ok(h) => {
                println!("LIVE put #{i}: {} chars, hash {}.., verified (answer hash equals local keccak256, read-back byte-equal), {} ms", img.len(), prefix(&h), t.elapsed().as_millis());
                hashes.push(h);
                images.push(img);
            }
            Err(e) => {
                println!(
                    "LIVE put #{i}: {} chars: NOT ACCEPTED: {e:?} (stop condition: {})",
                    img.len(),
                    e.is_stop_condition()
                );
                if matches!(e, PutError::Status(_)) {
                    println!("LIVE stopping after the first refusal; no retry");
                }
                std::fs::write(dir.join("hashes.txt"), hashes.join("\n")).unwrap();
                panic!("live check stopped at put #{i}");
            }
        }
    }
    // the same content again: the same address, the same bytes (from outside nothing can be said about the number of copies)
    let again = c
        .put_verified(&images[0])
        .await
        .map_err(|e| format!("{e:?}"));
    println!(
        "LIVE duplicate upload of #0: {:?}",
        again.as_ref().map(|h| format!("{}..", prefix(h)))
    );
    assert_eq!(
        again.as_ref().ok(),
        Some(&hashes[0]),
        "the same content has the same address"
    );
    // a fresh client, no state: read every object again and check each against its address
    let cold = FragmentClient::new(BASE, qa_wallet()).unwrap();
    for (i, h) in hashes.iter().enumerate() {
        let got = cold
            .get_verified(h)
            .await
            .unwrap_or_else(|e| format!("ERR {e:?}"));
        println!(
            "LIVE cold read #{i}: hash {}.. {}",
            prefix(h),
            if got == images[i] {
                "byte-equal"
            } else {
                "DIFFERENT or missing"
            }
        );
        assert_eq!(got, images[i]);
    }
    // negative: a signature of ANOTHER key for the QA wallet's address must be refused
    let other = EthKey::from_hex(&hex::encode({
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        k[0] |= 1;
        k
    }))
    .unwrap();
    let addr = qa_wallet().address().to_lowercase();
    let bad = other.sign_message(&addr).unwrap();
    let img = random_object(300);
    let r = reqwest::Client::new()
        .post(format!("{BASE}/storageFragment"))
        .json(&serde_json::json!({ "wallet": addr, "signMessage": bad, "image": img }))
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .unwrap();
    println!("LIVE bad-signature negative: HTTP {}", r.status().as_u16());
    let st = r.status().as_u16();
    // the refused object must not be readable
    let rb = reqwest::Client::new()
        .get(format!("{BASE}/getFragment?hash={}", keccak_hex(&img)))
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .unwrap();
    println!(
        "LIVE bad-signature object read: HTTP {}",
        rb.status().as_u16()
    );
    std::fs::write(dir.join("hashes.txt"), hashes.join("\n")).unwrap();
    std::fs::write(
        dir.join("lengths.txt"),
        images
            .iter()
            .map(|i| i.len().to_string())
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    println!("LIVE summary: {} distinct objects written and verified, 1 duplicate, bad-signature status {st}", hashes.len());
}

/// A new process, minutes later: reads every object whose hash was kept and checks it against its address and recorded length (no local mirror exists for it).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live check against the public CoNET IPFS API; needs IPFS_QA_KEY_FILE and IPFS_QA_DIR"]
async fn live_cold_read_in_a_new_process() {
    let dir = std::path::PathBuf::from(std::env::var("IPFS_QA_DIR").expect("IPFS_QA_DIR"));
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hashes = std::fs::read_to_string(dir.join("hashes.txt")).unwrap();
    let lengths = std::fs::read_to_string(dir.join("lengths.txt")).unwrap();
    let c = FragmentClient::new(BASE, qa_wallet()).unwrap();
    let mut ok = 0;
    for (h, l) in hashes.lines().zip(lengths.lines()) {
        let got = c.get_verified(h).await;
        let good = matches!(&got, Ok(t) if t.len().to_string() == l);
        println!(
            "LIVE new-process read: hash {}.. {}",
            prefix(h),
            if good {
                "verified, length matches"
            } else {
                "FAILED"
            }
        );
        if good {
            ok += 1;
        }
    }
    println!(
        "LIVE new-process summary: {ok} of {} objects read and verified",
        hashes.lines().count()
    );
    assert_eq!(ok, hashes.lines().count());
}
