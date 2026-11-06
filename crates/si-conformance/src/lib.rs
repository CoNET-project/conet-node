//! Golden vector runner shared by the native binary and the wasm module.
//! Input: golden.json text. Output: JSON with per-vector results and Rust-made artifacts
//! for the reverse check in `vectors/verify-rust.mjs`.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde_json::{json, Value};
use si_core::{node::Node, LocalRoute, WriteKeys};
use si_crypto::{eth, opgp, sym};
use si_proto as proto;
use std::collections::HashMap;

struct Ctx {
    pubs: HashMap<String, opgp::PublicCert>,
    secs: HashMap<String, opgp::SecretCert>,
    wallets: HashMap<String, eth::EthKey>,
    node_a_id: String,
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn load(g: &Value) -> Result<Ctx, String> {
    let mut pubs = HashMap::new();
    let mut secs = HashMap::new();
    for (name, k) in g["keys"].as_object().ok_or("keys")? {
        pubs.insert(
            name.clone(),
            opgp::PublicCert::from_armor(s(k, "armoredPublic"))
                .map_err(|e| format!("{name} pub: {e}"))?,
        );
        secs.insert(
            name.clone(),
            opgp::SecretCert::from_armor(s(k, "armoredPrivate"), s(k, "passphrase"))
                .and_then(|k| k.unlock())
                .map_err(|e| format!("{name} sec: {e}"))?,
        );
    }
    let mut wallets = HashMap::new();
    for (name, w) in g["wallets"].as_object().ok_or("wallets")? {
        wallets.insert(
            name.clone(),
            eth::EthKey::from_hex(s(w, "privateKey")).map_err(|e| e.to_string())?,
        );
    }
    let node_a_id = pubs["nodeA"].enc_key_id().ok_or("nodeA subkey")?;
    Ok(Ctx {
        pubs,
        secs,
        wallets,
        node_a_id,
    })
}

fn write_keys(input: &Value) -> WriteKeys {
    input
        .get("writeKeys")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.clone(), B64.decode(v.as_str()?).ok()?)))
                .collect()
        })
        .unwrap_or_default()
}

fn run_one(c: &Ctx, v: &Value) -> Result<Value, String> {
    let input = &v["input"];
    let es = |e: si_crypto::Error| e.to_string();
    Ok(match s(v, "kind") {
        "pgp_key_ids" => {
            let p = &c.pubs[s(input, "key")];
            json!({ "keyIds": p.key_ids(), "encKeyId": p.enc_key_id(), "fingerprint": p.fingerprint() })
        }
        "eip191" | "raw_digest" => {
            let w = &c.wallets[s(input, "wallet")];
            let msg = s(input, "message");
            let (sig, addr) = if s(v, "kind") == "eip191" {
                let sig = w.sign_message(msg).map_err(es)?;
                let a = eth::recover_message(msg, &sig).map_err(es)?;
                (sig, a)
            } else {
                let d = eth::keccak256(msg.as_bytes());
                let sig = w.sign_digest(&d).map_err(es)?;
                let a = eth::recover_digest(&d, &sig).map_err(es)?;
                (sig, a)
            };
            json!({ "signature": sig, "address": addr })
        }
        "eip191_text" => {
            let a = input["args"].as_array().ok_or("args")?;
            let text = match s(input, "builder") {
                "voicePayText" => proto::voice_pay_text(
                    a[0].as_str().unwrap_or(""),
                    a[1].as_u64().unwrap_or(0),
                    a[2].as_u64().unwrap_or(0),
                    a[3].as_u64().unwrap_or(0),
                ),
                "voiceListenText" => proto::voice_listen_text(
                    a[0].as_str().unwrap_or(""),
                    a[1].as_str().unwrap_or(""),
                    a[2].as_str().unwrap_or(""),
                    a[3].as_u64().unwrap_or(0),
                ),
                b => return Err(format!("builder {b}")),
            };
            let w = &c.wallets[s(input, "wallet")];
            let sig = w.sign_message(&text).map_err(es)?;
            json!({ "text": text, "signature": sig, "address": eth::recover_message(&text, &sig).map_err(es)? })
        }
        "post_classify" => {
            let key = &c.secs[s(input, "localKey")];
            let route = LocalRoute {
                key,
                key_id: &c.node_a_id,
            };
            let d = si_core::classify_post(s(input, "armor"), &route, &write_keys(input));
            json!({ "decision": d })
        }
        "pgp_decrypt" => {
            let d = opgp::decrypt(s(input, "armor"), &c.secs[s(input, "key")], None).map_err(es)?;
            json!({ "textLf": proto::crlf_to_lf(&String::from_utf8_lossy(&d.data)) })
        }
        "pgp_decrypt_verify" => {
            let d = opgp::decrypt(
                s(input, "armor"),
                &c.secs[s(input, "key")],
                Some(&c.pubs[s(input, "signer")]),
            )
            .map_err(es)?;
            json!({ "textLf": proto::crlf_to_lf(&String::from_utf8_lossy(&d.data)), "verified": d.verified.unwrap_or(false) })
        }
        "pgp_detached_verify" => {
            json!({ "verified": opgp::verify_detached(s(input, "text"), s(input, "signature"), &c.pubs[s(input, "signer")]) })
        }
        "pgp_cleartext_verify" => {
            let (text, ok) = opgp::verify_cleartext(s(input, "armor"), &c.pubs[s(input, "signer")])
                .ok_or("cleartext parse")?;
            json!({ "text": proto::crlf_to_lf(&text), "verified": ok })
        }
        "mailbox_open" => {
            let key = B64.decode(s(input, "key")).map_err(|e| e.to_string())?;
            match si_core::open_mailbox(s(input, "sealed"), &key) {
                Some((j, n)) => json!({ "json": j, "paddedLen": n }),
                None => json!({ "json": null }),
            }
        }
        "udp_open" => {
            let key = B64.decode(s(input, "key")).map_err(|e| e.to_string())?;
            let packed = B64.decode(s(input, "payload")).map_err(|e| e.to_string())?;
            json!({ "plaintextB64": B64.encode(sym::gcm_open(&key, &packed).map_err(es)?) })
        }
        "hop_sigs" => {
            let header = s(input, "header");
            let now = input["now"].as_i64().unwrap_or(0);
            match proto::parse_hop_header(&[header]) {
                proto::HopHeader::Rows(rows) => json!({
                    "payloads": rows.iter().map(|h| proto::hop_sig_payload(&h.w, h.t, h.n, &h.h, &h.k)).collect::<Vec<_>>(),
                    "valid": rows.iter().map(|h| si_core::verify_hop(h, now)).collect::<Vec<_>>(),
                    "count": rows.len(),
                    "armorHashMatches": rows.iter().all(|h| h.h == eth::keccak_hex(s(input, "armor"))),
                }),
                other => json!({ "error": format!("{other:?}") }),
            }
        }
        "hop_sign" => {
            let h = si_core::sign_hop(
                &c.wallets[s(input, "wallet")],
                s(input, "armor"),
                s(input, "nextKeyId"),
                input["t"].as_i64().unwrap_or(0),
            )
            .map_err(es)?;
            json!({ "payload": proto::hop_sig_payload(&h.w, h.t, h.n, &h.h, &h.k), "signature": h.s })
        }
        "eip712" => {
            use si_core::statement::{BindNode, Domain, NodeStatement};
            use si_crypto::eip712 as e7;
            let d = &input["domain"];
            if s(d, "name") != proto::node_registry::DOMAIN_NAME
                || s(d, "version") != proto::node_registry::DOMAIN_VERSION
                || d["chainId"].as_u64() != Some(proto::node_registry::CHAIN_ID)
            {
                return Err("domain differs from si-proto constants".into());
            }
            let domain = Domain::new(s(d, "verifyingContract")).map_err(es)?;
            let v = &input["value"];
            let (type_str, sh, dg) = match s(input, "primaryType") {
                "NodeStatement" => {
                    let st = NodeStatement {
                        node_id: e7::u256_dec(s(v, "nodeId")).map_err(es)?,
                        epoch: s(v, "epoch").parse().map_err(|_| "epoch")?,
                        kind: v["kind"].as_u64().ok_or("kind")? as u8,
                        payload_hash: e7::bytes32(s(v, "payloadHash")).map_err(es)?,
                    };
                    (
                        proto::node_registry::NODE_STATEMENT_TYPE,
                        st.struct_hash(),
                        st.digest(&domain),
                    )
                }
                "BindNode" => {
                    let b = BindNode {
                        operator: e7::address_word(s(v, "operator")).map_err(es)?,
                        node_id: e7::u256_dec(s(v, "nodeId")).map_err(es)?,
                        ip_hash: e7::bytes32(s(v, "ipHash")).map_err(es)?,
                        key_id: e7::fixed_bytes_word(s(v, "keyId"), 8).map_err(es)?,
                        pgp_hash: e7::bytes32(s(v, "pgpHash")).map_err(es)?,
                        nonce: e7::u256_dec(s(v, "nonce")).map_err(es)?,
                        deadline: e7::u256_dec(s(v, "deadline")).map_err(es)?,
                    };
                    (
                        proto::node_registry::BIND_NODE_TYPE,
                        b.struct_hash(),
                        b.digest(&domain),
                    )
                }
                t => return Err(format!("primaryType {t}")),
            };
            let w = &c.wallets[s(input, "wallet")];
            let sig = w.sign_digest(&dg).map_err(es)?;
            json!({
                "typeHash": e7::to_hex(&e7::type_hash(type_str)),
                "domainSeparator": e7::to_hex(&domain.separator),
                "structHash": e7::to_hex(&sh),
                "digest": e7::to_hex(&dg),
                "signature": sig,
                "address": eth::recover_digest(&dg, &sig).map_err(es)?,
            })
        }
        k => return Err(format!("unknown kind {k}")),
    })
}

/// Every key in `expect` must equal the same key in `actual`.
fn matches(expect: &Value, actual: &Value) -> bool {
    match (expect, actual) {
        (Value::Object(e), Value::Object(a)) => e.iter().all(|(k, ev)| {
            if k == "packetTags" {
                true
            } else {
                a.get(k).map(|av| matches(ev, av)).unwrap_or(false)
            }
        }),
        (e, a) => e == a,
    }
}

pub fn run_vectors(golden: &str) -> String {
    let g: Value = match serde_json::from_str(golden) {
        Ok(v) => v,
        Err(e) => return json!({ "fatal": e.to_string() }).to_string(),
    };
    let c = match load(&g) {
        Ok(c) => c,
        Err(e) => return json!({ "fatal": e }).to_string(),
    };
    let mut results = vec![];
    let (mut pass, mut fail) = (0, 0);
    for v in g["vectors"].as_array().cloned().unwrap_or_default() {
        let r = run_one(&c, &v);
        let ok = matches(&v["expect"], r.as_ref().unwrap_or(&Value::Null));
        if ok {
            pass += 1
        } else {
            fail += 1
        }
        results.push(match r {
            Ok(_) if ok => json!({ "id": v["id"], "pass": true }),
            Ok(a) => json!({ "id": v["id"], "pass": false, "actual": a, "expect": v["expect"] }),
            Err(e) => json!({ "id": v["id"], "pass": false, "error": e }),
        });
    }
    json!({ "summary": { "pass": pass, "fail": fail }, "results": results }).to_string()
}

/// Rust-made artifacts for the reverse check. `seed_hex` fixes every random byte we control.
pub fn make_artifacts(golden: &str, seed_hex: &str) -> String {
    let g: Value = serde_json::from_str(golden).expect("golden json");
    let c = load(&g).expect("golden keys");
    let mut seed = [0u8; 32];
    hex::decode_to_slice(seed_hex, &mut seed).expect("seed hex");
    let mut rng = ChaCha20Rng::from_seed(seed);
    let client = &c.wallets["client"];
    let node_a = &c.pubs["nodeA"];
    let text = |t: bool| opgp::EncryptOpts {
        text: t,
        zlib: true,
        sign_with: None,
    };
    let now = g["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "hop-two")
        .map(|v| v["input"]["now"].as_i64().unwrap())
        .unwrap();

    let mut stream_key = [0u8; 32];
    rng.fill_bytes(&mut stream_key);
    let cmd = json!({ "command": "mailbox_listen", "walletAddress": client.address().to_lowercase(), "streamKey": B64.encode(stream_key), "timestamp": now });
    let message = cmd.to_string();
    let sign_message = client.sign_message(&message).unwrap();
    let route_cmd_plain =
        B64.encode(json!({ "message": message, "signMessage": sign_message }).to_string());
    let route_cmd =
        opgp::encrypt(&mut rng, route_cmd_plain.as_bytes(), node_a, text(true)).unwrap();

    let business = opgp::encrypt(
        &mut rng,
        "{\"v\":1,\"text\":\"from rust\"}".as_bytes(),
        &c.pubs["user"],
        text(true),
    )
    .unwrap();
    let work = opgp::encrypt(
        &mut rng,
        json!({ "data": business, "NoPush": true })
            .to_string()
            .as_bytes(),
        node_a,
        text(true),
    )
    .unwrap();
    let inner_b = opgp::encrypt(
        &mut rng,
        B64.encode("{\"command\":\"x\"}").as_bytes(),
        &c.pubs["nodeB"],
        text(true),
    )
    .unwrap();
    let onion = opgp::encrypt(&mut rng, inner_b.as_bytes(), node_a, text(true)).unwrap();

    let mut locator = [0u8; 16];
    let mut write_key = [0u8; 32];
    let mut blob = vec![0u8; 512];
    rng.fill_bytes(&mut locator);
    rng.fill_bytes(&mut write_key);
    rng.fill_bytes(&mut blob);
    let mut chunk = proto::VOICE_CHUNK_MAGIC.to_vec();
    chunk.extend_from_slice(&locator);
    chunk.extend_from_slice(&sym::chunk_mac(&write_key, &locator, &blob));
    chunk.extend_from_slice(&blob);
    let voice = opgp::encrypt(&mut rng, &chunk, node_a, text(false)).unwrap();

    let signed_text = "signed by rust\nline 2";
    let signed_enc = opgp::encrypt(
        &mut rng,
        signed_text.as_bytes(),
        node_a,
        opgp::EncryptOpts {
            text: true,
            zlib: true,
            sign_with: Some(&c.secs["user"]),
        },
    )
    .unwrap();
    let detached = opgp::sign_detached_text(&mut rng, signed_text, &c.secs["user"]).unwrap();
    let cleartext = opgp::sign_cleartext(&mut rng, signed_text, &c.secs["user"]).unwrap();
    let multiline = "a\nb\r\nc\n你好";
    let multiline_enc = opgp::encrypt(&mut rng, multiline.as_bytes(), node_a, text(true)).unwrap();

    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);
    let frame_json = json!({ "type": "message", "data": business }).to_string();
    let sealed = si_core::seal_mailbox(&frame_json, &stream_key, &iv).unwrap();
    let mut udp_key = [0u8; 32];
    rng.fill_bytes(&mut udp_key);
    rng.fill_bytes(&mut iv);
    let udp = B64.encode(sym::gcm_seal(&udp_key, &iv, b"udp from rust").unwrap());

    // hop header produced by the sans-IO node acting as entry for a foreign key
    let foreign = g["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "post-not-local")
        .unwrap()["input"]["armor"]
        .as_str()
        .unwrap()
        .to_string();
    let node = Node {
        route: LocalRoute {
            key: &c.secs["nodeA"],
            key_id: &c.node_a_id,
        },
        wallet: &c.wallets["nodeA"],
        write_keys: WriteKeys::new(),
    };
    let actions = node.on_post(&[], &json!({ "data": foreign }).to_string(), now);

    json!({
        "now": now,
        "routeCommand": { "armor": route_cmd, "expectSigner": client.address(), "expectCommand": cmd },
        "mailboxWork": { "armor": work, "innerKey": "user", "noPush": true },
        "onion": { "armor": onion, "innerKey": "nodeB" },
        "voiceChunk": { "armor": voice, "chunkB64": B64.encode(&chunk), "writeKeyB64": B64.encode(write_key) },
        "signedEncrypted": { "armor": signed_enc, "text": signed_text, "signer": "user" },
        "detached": { "signature": detached, "text": signed_text, "signer": "user" },
        "cleartext": { "armor": cleartext, "text": signed_text, "signer": "user" },
        "multiline": { "armor": multiline_enc, "textLf": proto::crlf_to_lf(multiline) },
        "sealed": { "sealed": sealed, "keyB64": B64.encode(stream_key), "json": frame_json },
        "udp": { "payload": udp, "keyB64": B64.encode(udp_key), "plaintext": "udp from rust" },
        "eip191": { "message": message, "signature": sign_message, "address": client.address() },
        "entryForward": { "armor": foreign, "actions": actions },
        "nodeStatement": node_statement_artifact(&c, now),
    })
    .to_string()
}

/// Repeat one operation `n` times for host-side timing (wasm has no clock of its own).
pub fn bench(golden: &str, op: &str, n: u32) -> String {
    let g: Value = serde_json::from_str(golden).expect("golden json");
    let c = load(&g).expect("keys");
    let vec_of = |id: &str| {
        g["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == id)
            .unwrap()["input"]
            .clone()
    };
    let cmd = vec_of("post-cmd-mailbox-listen");
    let fwd = vec_of("post-not-local");
    let route = LocalRoute {
        key: &c.secs["nodeA"],
        key_id: &c.node_a_id,
    };
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let key = [1u8; 32];
    let sig_in = vec_of("eip191-ascii");
    let sig_sig = g["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "eip191-ascii")
        .unwrap()["expect"]["signature"]
        .as_str()
        .unwrap()
        .to_string();
    let mut last = String::new();
    for _ in 0..n {
        last = match op {
            "classify_command" => format!(
                "{:?}",
                si_core::classify_post(s(&cmd, "armor"), &route, &WriteKeys::new())
            )
            .len()
            .to_string(),
            "classify_forward" => format!(
                "{:?}",
                si_core::classify_post(s(&fwd, "armor"), &route, &WriteKeys::new())
            )
            .len()
            .to_string(),
            "eip191_sign" => c.wallets["client"].sign_message("bench message").unwrap(),
            "eip191_recover" => eth::recover_message(s(&sig_in, "message"), &sig_sig).unwrap(),
            "encrypt_1k" => opgp::encrypt(
                &mut rng,
                &[b'x'; 1024],
                &c.pubs["nodeA"],
                opgp::EncryptOpts {
                    text: true,
                    zlib: true,
                    sign_with: None,
                },
            )
            .unwrap()
            .len()
            .to_string(),
            "seal_frame" => {
                si_core::seal_mailbox("{\"type\":\"keepalive\"}", &key, &[0u8; 12]).unwrap()
            }
            o => return format!("unknown op {o}"),
        };
    }
    last
}

fn node_statement_artifact(c: &Ctx, now: i64) -> Value {
    use si_core::statement::{Domain, NodeStatement};
    let verifying = "0x00000000000000000000000000000000c0de0001";
    let domain = Domain::new(verifying).unwrap();
    let st = NodeStatement::online(si_crypto::eip712::u64_word(7), now as u64);
    let sig = c.wallets["nodeA"].sign_digest(&st.digest(&domain)).unwrap();
    json!({
        "domain": { "name": proto::node_registry::DOMAIN_NAME, "version": proto::node_registry::DOMAIN_VERSION, "chainId": proto::node_registry::CHAIN_ID, "verifyingContract": verifying },
        "value": { "nodeId": "7", "epoch": now.to_string(), "kind": 1, "payloadHash": si_crypto::eip712::to_hex(&st.payload_hash) },
        "signature": sig,
        "address": c.wallets["nodeA"].address(),
    })
}
