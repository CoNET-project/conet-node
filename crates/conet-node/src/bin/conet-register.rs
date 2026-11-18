//! `conet-register`: NodeRegistryV2 registration data for operators (F7). Prints JSON; never
//! sends a transaction. The operator's own wallet signs typed data and sends the calldata.
//!
//! ```text
//! conet-register request  --registry A --operator A --beneficiary A --node-wallet A --ip IP
//!                         --tcp-port N --udp-port N --pgp-public FILE --services N
//!                         --sponsor ID --node-type N [--nonce N] [--deadline UNIX]
//! conet-register register-for --request FILE --operator-sig HEX --node-sig HEX
//! conet-register reserved-bind --legacy-id N --operator A --ip IP --udp-port N --node-wallet A
//!                         --pgp-public FILE --services N --bind-nonce N [--deadline UNIX]
//! Required, no defaults: --ip, --tcp-port, --udp-port and --node-type (--node-type no longer
//! defaults to 1). Old scripts that omit them fail on purpose. --nonce and --deadline keep their
//! bounded defaults (current time; now+3600).
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

/// The value of flag `name`: the token after it. A flag with no value never takes the next flag
/// (`--…`) as its value; that is what an empty `${VAR}` expanded by the shell looks like.
fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    arg_in(&a, name)
}

/// The value flags of this binary. `--clear` is a switch and is not in this list.
const VALUE_FLAGS: [&str; 22] = [
    "--beneficiary",
    "--bind-nonce",
    "--bind-sig",
    "--deadline",
    "--ip",
    "--legacy-id",
    "--node-id",
    "--node-sig",
    "--node-type",
    "--node-wallet",
    "--nonce",
    "--operator",
    "--operator-sig",
    "--pgp-public",
    "--policy",
    "--registry",
    "--request",
    "--rpc",
    "--services",
    "--sponsor",
    "--tcp-port",
    "--udp-port",
];

/// True when a value is present and usable: not missing, not another flag, not blank.
fn has_value(v: Option<&String>) -> bool {
    v.is_some_and(|v| !v.starts_with("--") && !v.trim().is_empty())
}

/// The first value flag that appears without a usable value. Returns the flag name only.
fn valueless_flag(args: &[String]) -> Option<&'static str> {
    VALUE_FLAGS.iter().copied().find(|f| {
        args.iter()
            .enumerate()
            .any(|(i, a)| a == f && !has_value(args.get(i + 1)))
    })
}

fn arg_in(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|x| x == name)?;
    let v = args.get(i + 1)?;
    (!v.starts_with("--")).then(|| v.clone())
}

fn need(name: &str) -> Res<String> {
    arg(name).ok_or_else(|| format!("missing {name}").into())
}

fn address(name: &str) -> Res<Address> {
    Ok(need(name)?.parse()?)
}

fn num<T: std::str::FromStr>(name: &str, default: Option<T>) -> Res<T> {
    let a: Vec<String> = std::env::args().collect();
    num_in(&a, name, default)
}

/// `num` over an argument list. With no default, a missing value is an error.
fn num_in<T: std::str::FromStr>(args: &[String], name: &str, default: Option<T>) -> Res<T> {
    match arg_in(args, name) {
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
        udp_port: num("--udp-port", None)?,
        node_wallet,
        deadline: num("--deadline", Some(U256::from(now() + 3600)))?,
        armored_public: std::fs::read_to_string(need("--pgp-public")?)?,
        services: num("--services", None)?,
        bind_nonce: bind_nonce(node_wallet).await?,
    })
}

async fn run() -> Res<Value> {
    // Fail closed: a value flag given without a usable value stops the run. Nothing falls back to
    // a default. Only the flag name is printed, never a value.
    let argv: Vec<String> = std::env::args().collect();
    if let Some(flag) = valueless_flag(&argv) {
        return Err(format!("{flag} is given without a value; refusing to run").into());
    }
    let cmd = std::env::args().nth(1).unwrap_or_default();
    Ok(match cmd.as_str() {
        "request" => {
            let registry = need("--registry")?;
            let inp = RegisterInput {
                operator: address("--operator")?,
                beneficiary: address("--beneficiary")?,
                node_wallet: address("--node-wallet")?,
                node_type: num("--node-type", None)?,
                ip: need("--ip")?,
                tcp_port: num("--tcp-port", None)?,
                udp_port: num("--udp-port", None)?,
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

#[cfg(test)]
mod arg_tests {
    use super::arg_in;

    /// Every flag this binary reads (`--clear` is a switch; its own check also uses `any`).
    const FLAGS: [&str; 23] = [
        "--beneficiary",
        "--bind-nonce",
        "--bind-sig",
        "--clear",
        "--deadline",
        "--ip",
        "--legacy-id",
        "--node-id",
        "--node-sig",
        "--node-type",
        "--node-wallet",
        "--nonce",
        "--operator",
        "--operator-sig",
        "--pgp-public",
        "--policy",
        "--registry",
        "--request",
        "--rpc",
        "--services",
        "--sponsor",
        "--tcp-port",
        "--udp-port",
    ];

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn every_flag_takes_a_normal_value() {
        for f in FLAGS {
            assert_eq!(
                arg_in(&argv(&["bin", f, "v1"]), f),
                Some("v1".into()),
                "{f}"
            );
        }
    }

    #[test]
    fn every_flag_missing_from_argv_is_none() {
        for f in FLAGS {
            assert_eq!(arg_in(&argv(&["bin", "--other", "x"]), f), None, "{f}");
        }
    }

    #[test]
    fn every_flag_at_the_end_has_no_value() {
        for f in FLAGS {
            assert_eq!(arg_in(&argv(&["bin", "--other", "x", f]), f), None, "{f}");
        }
    }

    #[test]
    fn every_flag_followed_by_a_flag_takes_no_value_and_the_next_flag_still_parses() {
        for f in FLAGS {
            let next = if f == "--rpc" { "--registry" } else { "--rpc" };
            let a = argv(&["bin", f, next, "http://127.0.0.1:8545"]);
            assert_eq!(arg_in(&a, f), None, "{f} took the next flag");
            assert_eq!(
                arg_in(&a, next),
                Some("http://127.0.0.1:8545".into()),
                "{next} after {f}"
            );
        }
    }

    #[test]
    fn a_single_dash_value_is_kept() {
        assert_eq!(
            arg_in(&argv(&["bin", "--node-type", "-1"]), "--node-type"),
            Some("-1".into())
        );
    }

    #[test]
    fn an_empty_value_is_kept_for_the_caller_to_judge() {
        assert_eq!(
            arg_in(&argv(&["bin", "--ip", ""]), "--ip"),
            Some(String::new())
        );
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::{valueless_flag, VALUE_FLAGS};

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn every_value_flag_without_a_value_refuses_to_run() {
        for f in VALUE_FLAGS {
            assert_eq!(
                valueless_flag(&argv(&["bin", "egress-policy", f])),
                Some(f),
                "{f} at end"
            );
            assert_eq!(
                valueless_flag(&argv(&["bin", "egress-policy", f, "--rpc", "http://x"])),
                Some(f),
                "{f} then flag"
            );
            assert_eq!(
                valueless_flag(&argv(&["bin", "egress-policy", f, ""])),
                Some(f),
                "{f} empty"
            );
            assert_eq!(
                valueless_flag(&argv(&["bin", "egress-policy", f, " \t"])),
                Some(f),
                "{f} blank"
            );
        }
    }

    #[test]
    fn every_value_flag_with_a_usable_value_runs() {
        for f in VALUE_FLAGS {
            assert_eq!(
                valueless_flag(&argv(&["bin", "egress-policy", f, "v1"])),
                None,
                "{f}"
            );
            assert_eq!(
                valueless_flag(&argv(&["bin", "egress-policy", f, "-1"])),
                None,
                "{f} -1"
            );
        }
    }

    #[test]
    fn clear_is_a_switch_and_an_absent_flag_still_runs() {
        assert_eq!(
            valueless_flag(&argv(&["bin", "egress-policy", "--clear"])),
            None
        );
        assert_eq!(
            valueless_flag(&argv(&["bin", "egress-policy", "--clear", "--rpc", "u"])),
            None
        );
        for f in VALUE_FLAGS {
            assert_eq!(
                valueless_flag(&argv(&["bin", "egress-policy", "--other", "x"])),
                None,
                "{f}"
            );
        }
    }

    #[test]
    fn the_refusal_names_the_flag_and_no_value() {
        let secret = "0xSECRETaddress";
        let got = valueless_flag(&argv(&["bin", "x", "--operator", secret, "--sponsor"]));
        assert_eq!(got, Some("--sponsor"));
        assert!(!got.unwrap().contains(secret));
    }
}

#[cfg(test)]
mod required_field_tests {
    use super::{arg_in, num_in};

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn node_type_ports_and_ip_are_required() {
        let a = argv(&["bin", "request"]);
        assert!(num_in::<u8>(&a, "--node-type", None).is_err());
        assert!(num_in::<u16>(&a, "--tcp-port", None).is_err());
        assert!(num_in::<u16>(&a, "--udp-port", None).is_err());
        assert!(arg_in(&a, "--ip").is_none());
        // Given, they parse.
        let b = argv(&[
            "bin",
            "request",
            "--node-type",
            "1",
            "--tcp-port",
            "0",
            "--udp-port",
            "0",
        ]);
        assert_eq!(num_in::<u8>(&b, "--node-type", None).unwrap(), 1);
        assert_eq!(num_in::<u16>(&b, "--tcp-port", None).unwrap(), 0);
        assert_eq!(num_in::<u16>(&b, "--udp-port", None).unwrap(), 0);
    }

    #[test]
    fn deadline_and_nonce_keep_their_bounded_defaults() {
        let a = argv(&["bin", "request"]);
        assert_eq!(num_in::<u64>(&a, "--nonce", Some(42)).unwrap(), 42);
        assert_eq!(num_in::<u64>(&a, "--deadline", Some(7)).unwrap(), 7);
    }

    #[test]
    fn a_non_numeric_value_is_an_error_not_the_default() {
        let a = argv(&["bin", "request", "--tcp-port", "abc"]);
        assert!(num_in::<u16>(&a, "--tcp-port", Some(0)).is_err());
    }
}
