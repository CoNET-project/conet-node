//! `conet-register`: NodeRegistryV2 registration data for operators (F7). Prints JSON; never
//! sends a transaction. The operator's own wallet signs typed data and sends the calldata.
//!
//! ```text
//! conet-register request  --registry A --operator A --beneficiary A --node-wallet A --ip IP
//!                         --tcp-port N [--udp-port N] --pgp-public FILE --services N
//!                         --sponsor ID [--node-type 1] [--nonce N] [--deadline UNIX]
//! conet-register register-for --request FILE --operator-sig HEX --node-sig HEX
//! conet-register reserved-bind --legacy-id N --operator A --ip IP [--udp-port N] --node-wallet A
//!                         --pgp-public FILE --services N --bind-nonce N [--deadline UNIX]
//! conet-register reserved --(same as reserved-bind) --bind-sig HEX
//! conet-register egress-policy --node-id N (--policy FILE | --clear)
//! ```
//! `bindNonceOf` can be read with `--rpc URL --registry A` instead of `--bind-nonce`.
//! The node wallet signs a printed `bind` object with its signer (`conet-signer --allow-bind`).
use alloy_primitives::{Address, U256};
use conet_node::register::{self as reg, RegisterInput, ReservedInput};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
}

fn need(name: &str) -> Res<String> {
    arg(name).ok_or_else(|| format!("missing {name}").into())
}

fn address(name: &str) -> Res<Address> {
    Ok(need(name)?.parse()?)
}

fn num<T: std::str::FromStr>(name: &str, default: Option<T>) -> Res<T> {
    match arg(name) {
        Some(v) => {
            let v = v.trim();
            // Accept 0x… for the service bits.
            if let Some(h) = v.strip_prefix("0x") {
                let n = u64::from_str_radix(h, 16)?;
                return n
                    .to_string()
                    .parse()
                    .map_err(|_| format!("bad {name}").into());
            }
            v.parse().map_err(|_| format!("bad {name}").into())
        }
        None => default.ok_or_else(|| format!("missing {name}").into()),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

async fn bind_nonce(wallet: Address) -> Res<U256> {
    if let Some(n) = arg("--bind-nonce") {
        return Ok(n.parse()?);
    }
    let (Some(url), Some(registry)) = (arg("--rpc"), arg("--registry")) else {
        return Err("--bind-nonce N, or --rpc URL with --registry A".into());
    };
    let r = conet_node::nr2::Nr2Reader {
        rpc: conet_node::chain::Rpc::new(&url)?,
        registry,
    };
    Ok(r.call(
        &r.registry,
        conet_node::nr2::NodeRegistryV2::bindNonceOfCall { w: wallet },
        None,
    )
    .await?)
}

async fn reserved_input() -> Res<ReservedInput> {
    let node_wallet = address("--node-wallet")?;
    Ok(ReservedInput {
        legacy_id: num("--legacy-id", None)?,
        operator: address("--operator")?,
        ip: need("--ip")?,
        udp_port: num("--udp-port", Some(0))?,
        node_wallet,
        deadline: num("--deadline", Some(U256::from(now() + 3600)))?,
        armored_public: std::fs::read_to_string(need("--pgp-public")?)?,
        services: num("--services", None)?,
        bind_nonce: bind_nonce(node_wallet).await?,
    })
}

async fn run() -> Res<Value> {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    Ok(match cmd.as_str() {
        "request" => {
            let registry = need("--registry")?;
            let inp = RegisterInput {
                operator: address("--operator")?,
                beneficiary: address("--beneficiary")?,
                node_wallet: address("--node-wallet")?,
                node_type: num("--node-type", Some(1u8))?,
                ip: arg("--ip").unwrap_or_default(),
                tcp_port: num("--tcp-port", Some(0))?,
                udp_port: num("--udp-port", Some(0))?,
                armored_public: std::fs::read_to_string(need("--pgp-public")?)?,
                services: num("--services", None)?,
                sponsor_node_id: num("--sponsor", None)?,
                nonce: num("--nonce", Some(U256::from(now())))?,
                deadline: num("--deadline", Some(U256::from(now() + 3600)))?,
            };
            let p = reg::prepare_register(&inp, &registry)?;
            let r = &p.request;
            json!({
                "registry": registry,
                "ip": inp.ip,
                "pgp": p.pgp,
                "typedData": reg::typed_data(r, &registry),
                "requestHash": format!("{:#x}", p.request_hash),
                "prestakeCalldata": hex0x(&reg::prestake_calldata(p.request_hash)),
                "bind": reg::bind_request(r.operator, U256::ZERO, r.ipHash, r.keyId, r.pgpHash, r.nonce, r.deadline),
                "warnings": reg::warnings(r.nodeType, r.services),
                "steps": [
                    "operator wallet: eth_signTypedData_v4(typedData) -> operator signature",
                    "operator wallet: send prestakeCalldata to the registry with the stake as value",
                    "node: sign the bind object with conet-signer (--allow-bind) -> node signature",
                    "conet-register register-for --request <this file> --operator-sig .. --node-sig ..",
                    "sponsor node wallet: send that calldata (sponsored registration)"
                ],
            })
        }
        "register-for" => {
            let saved: Value = serde_json::from_str(&std::fs::read_to_string(need("--request")?)?)?;
            let m = &saved["typedData"]["message"];
            let s = |k: &str| m[k].as_str().map(str::to_string).unwrap_or_else(|| m[k].to_string());
            let registry = saved["registry"].as_str().ok_or("request file: registry")?;
            let pgp_b64 = saved["pgp"].as_str().ok_or("request file: pgp")?;
            let armored = String::from_utf8(
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pgp_b64)?,
            )?;
            let inp = RegisterInput {
                operator: s("operator").parse()?,
                beneficiary: s("beneficiary").parse()?,
                node_wallet: s("nodeWallet").parse()?,
                node_type: s("nodeType").parse()?,
                ip: saved["ip"].as_str().unwrap_or("").to_string(),
                tcp_port: s("tcpPort").parse()?,
                udp_port: s("udpPort").parse()?,
                armored_public: armored,
                services: s("services").parse()?,
                sponsor_node_id: s("sponsorNodeId").parse()?,
                nonce: s("nonce").parse()?,
                deadline: s("deadline").parse()?,
            };
            let p = reg::prepare_register(&inp, registry)?;
            if format!("{:#x}", p.request_hash) != saved["requestHash"].as_str().unwrap_or("") {
                return Err("request file does not match its requestHash".into());
            }
            let data = reg::register_for_calldata(
                &p,
                &inp.ip,
                &need("--operator-sig")?,
                &need("--node-sig")?,
            )?;
            json!({ "to": registry, "calldata": hex0x(&data), "sender": "sponsor node wallet" })
        }
        "reserved-bind" => {
            let inp = reserved_input().await?;
            json!({ "bind": reg::reserved_bind(&inp)?, "warnings": reg::warnings(1, inp.services) })
        }
        "reserved" => {
            let inp = reserved_input().await?;
            let data = reg::register_reserved_calldata(&inp, &need("--bind-sig")?)?;
            json!({
                "calldata": hex0x(&data),
                "sender": "the reserved operator",
                "value": "at least minStakeNow()",
            })
        }
        "egress-policy" => {
            let node_id: U256 = num("--node-id", None)?;
            if arg("--clear").is_some() || std::env::args().any(|a| a == "--clear") {
                json!({ "calldata": hex0x(&reg::set_egress_policy_calldata(node_id, None)), "sender": "operator" })
            } else {
                let file = std::fs::read(need("--policy")?)?;
                conet_node::egress::PolicyFile::parse(&file)?;
                let cid = reg::policy_cid(&file)?;
                json!({
                    "cid": hex0x(&cid),
                    "cidText": reg::cid_text(&cid),
                    "bytes": file.len(),
                    "calldata": hex0x(&reg::set_egress_policy_calldata(node_id, Some(&cid))),
                    "sender": "operator (not the node wallet)",
                    "note": "publish the same file on IPFS (ipfs add --cid-version 1 --raw-leaves) and load it on the node with --egress-policy",
                })
            }
        }
        _ => return Err("usage: conet-register request|register-for|reserved-bind|reserved|egress-policy ... (see the source header)".into()),
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match run().await {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default()),
        Err(e) => {
            eprintln!("conet-register: {e}");
            std::process::exit(2);
        }
    }
}
