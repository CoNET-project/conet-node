//! Node-provided settings (`--init-config /etc/conet-node/init.json`, plus the legacy `node.env`
//! variables) merged into the one argument vector `main` already parses.
//!
//! Priority per setting, highest first:
//! 1. an explicit command-line flag (it is in argv, so nothing is synthesized for it);
//! 2. `init.json` (validated by `si_signer::init_config`; a damaged file refuses to start);
//! 3. the environment variables of `node.env` (`CONET_RPC`, `BEAMIO_API_BASE`, `CONET_PUBLIC_IP`),
//!    kept so a node that only has `node.env` behaves as it did with the old unit;
//! 4. auto-detection (`public_ip: "auto"` only: global IPv4 addresses of the local interfaces);
//! 5. built-in defaults, applied only when `--init-config` was given: HTTP `[::]:80`, HTTPS
//!    `[::]:443` (the TypeScript node's ports). Without `--init-config` nothing here runs and the
//!    process behaves exactly as before (`--listen` defaults to `127.0.0.1:8080`, no TLS).
//!
//! The merged values are ordinary flags, so every existing check (`FAIL_CLOSED_FLAGS`,
//! `public_ips_from`, `Rpc::new`, `choose_mode`) applies to them unchanged. A blank environment
//! variable counts as unset (the old unit would have passed an empty flag and refused to start).
use si_signer::init_config::{InitConfig, PublicIp};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EnvSettings {
    pub rpc: Option<String>,
    pub api_base: Option<String>,
    pub public_ip: Option<String>,
    /// Names of variables that are set but blank. The old unit would have passed an empty flag and
    /// refused to start; here they count as unset, and `merge` says so (name only).
    pub blank: Vec<&'static str>,
}

impl EnvSettings {
    pub fn from_env() -> Self {
        let mut blank = Vec::new();
        let mut get = |n: &'static str| match std::env::var(n) {
            Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
            Ok(_) => {
                blank.push(n);
                None
            }
            Err(_) => None,
        };
        let rpc = get("CONET_RPC");
        let api_base = get("BEAMIO_API_BASE");
        let public_ip = get("CONET_PUBLIC_IP");
        EnvSettings {
            rpc,
            api_base,
            public_ip,
            blank,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Merged {
    pub argv: Vec<String>,
    /// One line per setting that was synthesized, naming its source; never a URL or key.
    pub notes: Vec<String>,
}

fn has_flag(argv: &[String], name: &str) -> bool {
    argv.iter().any(|a| a == name)
}

/// `None`: `--init-config` not given. `Some(path)`: given with a usable value. A valueless
/// `--init-config` is an error, never "not given".
pub fn config_path(argv: &[String]) -> Result<Option<String>, String> {
    let Some(i) = argv.iter().position(|a| a == "--init-config") else {
        return Ok(None);
    };
    match argv.get(i + 1) {
        Some(v) if !v.starts_with("--") && !v.trim().is_empty() => Ok(Some(v.clone())),
        _ => Err("--init-config is given without a value; refusing to start".into()),
    }
}

/// The TypeScript node's `rfc1918` exclusion set (`localNodeCommand.ts:36`) as address tests:
/// 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24,
/// 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24 and everything from 224.0.0.0 up.
pub fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || (a == 100 && (64..=127).contains(&b))
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

/// Global IPv4 addresses of the local interfaces (what TS `getServerIPV4Address(false)` listed).
pub fn probe_global_ipv4() -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = if_addrs::get_if_addrs()
        .map(|ifs| {
            ifs.into_iter()
                .filter(|i| !i.is_loopback())
                .filter_map(|i| match i.ip() {
                    IpAddr::V4(a) if is_global_ipv4(a) => Some(IpAddr::V4(a)),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v.dedup();
    v
}

/// Merge. `cfg` is the loaded `init.json` (`None` when the file does not exist).
pub fn merge(
    argv: &[String],
    cfg: Option<&InitConfig>,
    env: &EnvSettings,
    probe: &dyn Fn() -> Vec<IpAddr>,
) -> Result<Merged, String> {
    if config_path(argv)?.is_none() {
        return Ok(Merged {
            argv: argv.to_vec(),
            notes: vec![],
        });
    }
    let default = InitConfig::default();
    let c = cfg.unwrap_or(&default);
    let from_file = |present: bool| if present { "init.json" } else { "default" };
    let mut out = argv.to_vec();
    let mut notes = vec![];
    fn add(
        out: &mut Vec<String>,
        notes: &mut Vec<String>,
        flag: &str,
        value: String,
        note: String,
    ) {
        out.push(flag.to_string());
        out.push(value);
        notes.push(note);
    }
    if !has_flag(argv, "--listen") {
        let p = c.http_port.unwrap_or(80);
        add(
            &mut out,
            &mut notes,
            "--listen",
            format!("[::]:{p}"),
            format!(
                "init-config: --listen [::]:{p} ({})",
                from_file(c.http_port.is_some())
            ),
        );
    }
    if !has_flag(argv, "--tls-listen") {
        let p = c.https_port.unwrap_or(443);
        if p != 0 {
            add(
                &mut out,
                &mut notes,
                "--tls-listen",
                format!("[::]:{p}"),
                format!(
                    "init-config: --tls-listen [::]:{p} ({})",
                    from_file(c.https_port.is_some())
                ),
            );
        } else {
            notes.push("init-config: https off (https_port 0)".into());
        }
    }
    if !has_flag(argv, "--rpc") {
        match (&c.rpc, &env.rpc) {
            (Some(v), _) => add(
                &mut out,
                &mut notes,
                "--rpc",
                v.clone(),
                "init-config: --rpc set (init.json)".into(),
            ),
            (None, Some(v)) => add(
                &mut out,
                &mut notes,
                "--rpc",
                v.clone(),
                "init-config: --rpc set (node.env)".into(),
            ),
            _ => {}
        }
    }
    if !has_flag(argv, "--api-base") {
        match (&c.api_base, &env.api_base) {
            (Some(v), _) => add(
                &mut out,
                &mut notes,
                "--api-base",
                v.clone(),
                "init-config: --api-base set (init.json)".into(),
            ),
            (None, Some(v)) => add(
                &mut out,
                &mut notes,
                "--api-base",
                v.clone(),
                "init-config: --api-base set (node.env)".into(),
            ),
            _ => {}
        }
    }
    if !has_flag(argv, "--public-ip") {
        let join = |ips: &[IpAddr]| {
            ips.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        match (&c.public_ip, &env.public_ip) {
            (Some(PublicIp::List(ips)), _) => add(
                &mut out,
                &mut notes,
                "--public-ip",
                join(ips),
                format!(
                    "init-config: --public-ip {} address(es) (init.json)",
                    ips.len()
                ),
            ),
            (Some(PublicIp::Auto), _) => {
                let found = probe();
                if found.is_empty() {
                    notes.push(
                        "init-config: public_ip auto found no global IPv4; --public-ip unset"
                            .into(),
                    );
                } else {
                    add(
                        &mut out,
                        &mut notes,
                        "--public-ip",
                        join(&found),
                        format!(
                            "init-config: --public-ip {} address(es) (auto-detected)",
                            found.len()
                        ),
                    );
                }
            }
            (None, Some(v)) => add(
                &mut out,
                &mut notes,
                "--public-ip",
                v.clone(),
                "init-config: --public-ip set (node.env)".into(),
            ),
            _ => {}
        }
    }
    for name in &env.blank {
        notes.push(format!(
            "init-config: environment variable {name} is set but empty; treated as unset"
        ));
    }
    for f in &c.legacy_ignored {
        notes.push(format!("init-config: ignored {f} (no Rust consumer)"));
    }
    for f in &c.ts_consumed {
        notes.push(format!("init-config: TS field {f} consumed"));
    }
    Ok(Merged { argv: out, notes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use si_signer::init_config;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }
    fn none() -> Vec<IpAddr> {
        vec![]
    }
    fn pairs(argv: &[String]) -> std::collections::BTreeMap<String, String> {
        let mut m = std::collections::BTreeMap::new();
        let mut i = 1;
        while i < argv.len() {
            if argv[i].starts_with("--") {
                let val = argv
                    .get(i + 1)
                    .filter(|x| !x.starts_with("--"))
                    .cloned()
                    .unwrap_or_default();
                m.insert(argv[i].clone(), val);
            }
            i += 1;
        }
        m
    }

    #[test]
    fn without_init_config_nothing_changes() {
        let a = v(&["conet-node", "--signer-socket", "/s", "--rpc", "https://x"]);
        let env = EnvSettings {
            rpc: Some("https://other".into()),
            ..Default::default()
        };
        let m = merge(&a, None, &env, &none).unwrap();
        assert_eq!(m.argv, a);
        assert!(m.notes.is_empty());
    }

    #[test]
    fn a_valueless_init_config_refuses() {
        for a in [
            v(&["bin", "--init-config"]),
            v(&["bin", "--init-config", "--listen", "x"]),
            v(&["bin", "--init-config", " "]),
        ] {
            assert!(merge(&a, None, &EnvSettings::default(), &none).is_err());
        }
    }

    #[test]
    fn defaults_are_the_ts_ports() {
        let a = v(&["bin", "--init-config", "/etc/conet-node/init.json"]);
        let m = merge(&a, None, &EnvSettings::default(), &none).unwrap();
        let p = pairs(&m.argv);
        assert_eq!(p["--listen"], "[::]:80");
        assert_eq!(p["--tls-listen"], "[::]:443");
        assert!(
            !p.contains_key("--rpc")
                && !p.contains_key("--api-base")
                && !p.contains_key("--public-ip")
        );
    }

    #[test]
    fn priority_is_flag_then_init_json_then_env_then_default() {
        let cfg = init_config::parse_value(&serde_json::json!({
            "version":1,"http_port":8081,"https_port":0,"rpc":"https://from-init","public_ip":["203.0.113.7"]
        }))
        .unwrap();
        let env = EnvSettings {
            rpc: Some("https://from-env".into()),
            api_base: Some("https://api-env".into()),
            public_ip: Some("198.51.100.1".into()),
            blank: vec![],
        };
        // init.json beats env and default; env fills what init.json does not say.
        let m = merge(&v(&["bin", "--init-config", "/c"]), Some(&cfg), &env, &none).unwrap();
        let p = pairs(&m.argv);
        assert_eq!(p["--listen"], "[::]:8081");
        assert!(
            !p.contains_key("--tls-listen"),
            "https_port 0 turns TLS off"
        );
        assert_eq!(p["--rpc"], "https://from-init");
        assert_eq!(p["--api-base"], "https://api-env");
        assert_eq!(p["--public-ip"], "203.0.113.7");
        // An explicit flag beats everything, and nothing is synthesized for it.
        let a = v(&[
            "bin",
            "--init-config",
            "/c",
            "--listen",
            "127.0.0.1:9",
            "--rpc",
            "https://flag",
            "--public-ip",
            "192.0.2.1",
        ]);
        let m = merge(&a, Some(&cfg), &env, &none).unwrap();
        let p = pairs(&m.argv);
        assert_eq!(p["--listen"], "127.0.0.1:9");
        assert_eq!(p["--rpc"], "https://flag");
        assert_eq!(p["--public-ip"], "192.0.2.1");
        assert_eq!(m.argv.iter().filter(|x| *x == "--listen").count(), 1);
        // The notes never carry a URL or an address.
        for n in &m.notes {
            assert!(!n.contains("https://") && !n.contains("203.0.113"), "{n}");
        }
    }

    #[test]
    fn auto_uses_the_probe_and_loses_to_explicit_values() {
        let cfg =
            init_config::parse_value(&serde_json::json!({"version":1,"public_ip":"auto"})).unwrap();
        let probe = || {
            vec![
                "203.0.113.9".parse::<IpAddr>().unwrap(),
                "198.51.100.4".parse().unwrap(),
            ]
        };
        let m = merge(
            &v(&["bin", "--init-config", "/c"]),
            Some(&cfg),
            &EnvSettings::default(),
            &probe,
        )
        .unwrap();
        assert_eq!(pairs(&m.argv)["--public-ip"], "203.0.113.9,198.51.100.4");
        let m = merge(
            &v(&["bin", "--init-config", "/c"]),
            Some(&cfg),
            &EnvSettings::default(),
            &none,
        )
        .unwrap();
        assert!(!pairs(&m.argv).contains_key("--public-ip"));
        assert!(m.notes.iter().any(|n| n.contains("found no global IPv4")));
    }

    #[test]
    fn blank_environment_values_count_as_unset() {
        // The old unit would pass `--rpc` with nothing and refuse to start; here it is just unset.
        std::env::set_var("CONET_RPC", "  ");
        std::env::set_var("BEAMIO_API_BASE", "");
        let e = EnvSettings::from_env();
        assert_eq!((e.rpc.clone(), e.api_base.clone()), (None, None));
        assert_eq!(e.blank, vec!["CONET_RPC", "BEAMIO_API_BASE"]);
        // merge names them, never a value.
        let m = merge(&v(&["bin", "--init-config", "/c"]), None, &e, &none).unwrap();
        assert!(m.notes.iter().any(|n| n
            == "init-config: environment variable CONET_RPC is set but empty; treated as unset"));
        assert!(m
            .notes
            .iter()
            .any(|n| n.contains("BEAMIO_API_BASE is set but empty")));
        assert!(
            !m.argv.contains(&"--rpc".to_string()),
            "a blank variable must not become a flag"
        );
        std::env::remove_var("CONET_RPC");
        std::env::remove_var("BEAMIO_API_BASE");
    }

    #[test]
    fn the_ts_exclusion_set_is_reproduced() {
        let g = |s: &str| is_global_ipv4(s.parse().unwrap());
        for local in [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.9.9",
            "192.0.0.5",
            "192.0.2.5",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.9.9",
            "198.51.100.7",
            "203.0.113.7",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                !g(local),
                "{local} must be excluded like the TS rfc1918 pattern"
            );
        }
        for global in [
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "198.17.0.1",
            "198.20.0.1",
            "223.255.255.255",
            "192.0.1.1",
        ] {
            assert!(g(global), "{global}");
        }
    }

    #[test]
    fn the_ts_ipv4_field_becomes_the_public_ip_flag_and_is_reported_consumed() {
        let cfg = init_config::parse_value(
            &serde_json::json!({"version":1,"ipV4":"203.0.113.9","ipV4Port":8088}),
        )
        .unwrap();
        let m = merge(
            &v(&["bin", "--init-config", "/c"]),
            Some(&cfg),
            &EnvSettings::default(),
            &none,
        )
        .unwrap();
        let p = pairs(&m.argv);
        assert_eq!(p["--public-ip"], "203.0.113.9");
        assert_eq!(p["--listen"], "[::]:8088");
        assert!(m.notes.iter().any(|n| n.contains("TS field ipV4 consumed")));
        assert!(m
            .notes
            .iter()
            .any(|n| n.contains("TS field ipV4Port consumed")));
    }
}
