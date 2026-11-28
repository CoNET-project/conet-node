//! `--init-config` on the real start path: the `conet-node` binary is started as a process, and
//! the unit file that ships in the package is parsed, not copied.
//!
//! Keys here are made on this machine by this test (a throw-away route key and wallet key for the
//! binary's `--insecure-dev-keys` test mode); nothing real is read or printed.
use rand_core::{OsRng, RngCore};
use std::collections::BTreeMap;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Node {
    dir: tempfile::TempDir,
}

impl Node {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut sk = [0u8; 32];
        let (wallet_hex, wallet) = loop {
            OsRng.fill_bytes(&mut sk);
            let h = format!("0x{}", hex::encode(sk));
            if let Ok(k) = si_crypto::eth::EthKey::from_hex(&h) {
                break (h, k.address());
            }
        };
        let (armor, _public, key_id) = si_crypto::opgp::generate_route_key(OsRng, &wallet).unwrap();
        std::fs::write(dir.path().join("route.asc"), armor).unwrap();
        std::fs::write(dir.path().join("wallet.hex"), wallet_hex).unwrap();
        std::fs::write(
            dir.path().join("routes.json"),
            format!(r#"{{"nodes":[{{"keyId":"{key_id}","addr":"127.0.0.1:9"}}]}}"#),
        )
        .unwrap();
        Node { dir }
    }
    fn p(&self, n: &str) -> PathBuf {
        self.dir.path().join(n)
    }
    fn init(&self, text: &str) -> PathBuf {
        let p = self.p("init.json");
        std::fs::write(&p, text).unwrap();
        p
    }
    fn command(&self, extra: &[&str], health: u16) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_conet-node"));
        c.args(["--insecure-dev-keys", "--dev-route-key"])
            .arg(self.p("route.asc"))
            .arg("--routes")
            .arg(self.p("routes.json"))
            .args(["--health-listen", &format!("127.0.0.1:{health}")])
            .args(extra)
            .env(
                "CONET_DEV_WALLET_KEY",
                std::fs::read_to_string(self.p("wallet.hex")).unwrap(),
            )
            .env_remove("CONET_RPC")
            .env_remove("BEAMIO_API_BASE")
            .env_remove("CONET_PUBLIC_IP")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }
}

fn reachable(port: u16) -> bool {
    ["127.0.0.1", "::1"].iter().any(|h| {
        let addr = format!("[{h}]:{port}").replace("[127.0.0.1]", "127.0.0.1");
        addr.parse::<std::net::SocketAddr>()
            .ok()
            .is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_millis(200)).is_ok())
    })
}

fn wait_reachable(child: &mut Child, port: u16) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        if child.try_wait().unwrap().is_some() {
            return false;
        }
        if reachable(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn stop(mut child: Child) -> String {
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn the_port_in_init_json_decides_the_port_the_process_listens_on() {
    let n = Node::new();
    let (http, health) = (free_port(), free_port());
    let init = n.init(&format!(
        r#"{{"version":1,"http_port":{http},"https_port":0}}"#
    ));
    let mut child = n
        .command(&["--init-config", init.to_str().unwrap()], health)
        .spawn()
        .unwrap();
    let up = wait_reachable(&mut child, http);
    let log = stop(child);
    assert!(
        up,
        "nothing listens on the init.json port {http}; log:\n{log}"
    );
    assert!(
        log.contains(&format!("--listen [::]:{http} (init.json)")),
        "{log}"
    );
    assert!(log.contains("https off"), "{log}");
}

#[test]
fn the_ts_field_name_ipv4port_in_init_json_is_consumed_as_the_listen_port() {
    let n = Node::new();
    let (http, health) = (free_port(), free_port());
    let init = n.init(&format!(
        r#"{{"version":1,"ipV4Port":{http},"https_port":0,"storage_price":0.01,"cpus":2}}"#
    ));
    let mut child = n
        .command(&["--init-config", init.to_str().unwrap()], health)
        .spawn()
        .unwrap();
    let up = wait_reachable(&mut child, http);
    let log = stop(child);
    assert!(up, "ipV4Port was not consumed; log:\n{log}");
    assert!(log.contains("TS field ipV4Port consumed"), "{log}");
    assert!(
        log.contains("ignored storage_price (no Rust consumer)"),
        "{log}"
    );
    assert!(log.contains("ignored cpus (no Rust consumer)"), "{log}");
}

#[test]
fn an_explicit_flag_beats_init_json() {
    let n = Node::new();
    let (in_init, explicit, health) = (free_port(), free_port(), free_port());
    let init = n.init(&format!(
        r#"{{"version":1,"http_port":{in_init},"https_port":0}}"#
    ));
    let listen = format!("127.0.0.1:{explicit}");
    let mut child = n
        .command(
            &["--init-config", init.to_str().unwrap(), "--listen", &listen],
            health,
        )
        .spawn()
        .unwrap();
    let up = wait_reachable(&mut child, explicit);
    let init_port_open = reachable(in_init);
    let log = stop(child);
    assert!(up, "{log}");
    assert!(
        !init_port_open,
        "init.json's port was bound although --listen was given"
    );
    assert!(!log.contains("--listen [::]"), "{log}");
}

#[test]
fn a_damaged_init_json_stops_the_start_and_nothing_listens() {
    let n = Node::new();
    let (http, health) = (free_port(), free_port());
    for (bytes, want) in [
        (
            format!(r#"{{"version":1,"http_port":{http},"http_"#),
            "not_json",
        ),
        (
            format!(r#"{{"version":1,"http_port":{http},"passwd":"x"}}"#),
            "secret_field_not_allowed:passwd",
        ),
        (
            format!(r#"{{"version":1,"http_port":{http},"https_port":99999}}"#),
            "bad_value:https_port",
        ),
    ] {
        let init = n.init(&bytes);
        let out = n
            .command(&["--init-config", init.to_str().unwrap()], health)
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{want}: started");
        assert!(
            err.contains("init config refused") && err.contains(want),
            "{want}: {err}"
        );
        assert!(
            !reachable(http),
            "{want}: a port is open after a refused start"
        );
    }
    // Not "absent": a directory or an unreadable path also refuses.
    let out = n
        .command(
            &[
                "--init-config",
                n.p("route.asc").parent().unwrap().to_str().unwrap(),
            ],
            health,
        )
        .output()
        .unwrap();
    assert!(!out.status.success());
    // A flag with no value is refused, not read as "no config".
    let out = n.command(&["--init-config"], health).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn node_env_values_reach_the_real_validation_when_there_is_no_init_json() {
    let n = Node::new();
    let (http, health) = (free_port(), free_port());
    // No init.json at all: the missing file is "no node-provided config"; ports are set by flags
    // here so the test never binds 80 or 443; the legacy variables still apply.
    let missing = n.p("absent-init.json");
    let out = n
        .command(
            &[
                "--init-config",
                missing.to_str().unwrap(),
                "--listen",
                &format!("127.0.0.1:{http}"),
                "--tls-listen",
                "0.0.0.0:0",
            ],
            health,
        )
        .env("CONET_PUBLIC_IP", "this-is-not-an-ip")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        err.contains("--public-ip: every entry must be an IP address"),
        "CONET_PUBLIC_IP did not reach --public-ip validation: {err}"
    );
}

// -------- upgrade parity: old unit + node.env versus new unit + node.env ---------------------

/// `deploy/apt/systemd/conet-node.service` as shipped in fc0939af (the unit being replaced).
const OLD_UNIT_EXEC: &str = r#"ExecStart=/usr/lib/conet-node/conet-node \
  --listen [::]:80 \
  --tls-listen [::]:443 \
  --acme-cache /var/lib/conet-node/acme \
  --signer-socket /run/conet-signer/signer.sock \
  --rpc ${CONET_RPC} \
  --api-base ${BEAMIO_API_BASE} \
  --public-ip ${CONET_PUBLIC_IP} \
  --mailbox-db /var/lib/conet-node/mailbox.redb \
  --health-listen 127.0.0.1:9180 \
  --evidence-log /var/lib/conet-node/evidence/evidence.jsonl
"#;

fn exec_tokens(unit: &str) -> Vec<String> {
    let start = unit.find("ExecStart=").expect("ExecStart");
    let body = &unit[start + "ExecStart=".len()..];
    let mut text = String::new();
    for line in body.lines() {
        let l = line.trim_end();
        if let Some(stripped) = l.strip_suffix('\\') {
            text.push_str(stripped);
            text.push(' ');
        } else {
            text.push_str(l);
            break;
        }
    }
    text.split_whitespace().map(str::to_string).collect()
}

fn flag_pairs(tokens: &[String]) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut i = 1;
    while i < tokens.len() {
        if tokens[i].starts_with("--") {
            let v = tokens
                .get(i + 1)
                .filter(|t| !t.starts_with("--"))
                .cloned()
                .unwrap_or_default();
            m.insert(tokens[i].clone(), v);
        }
        i += 1;
    }
    m
}

fn substitute(tokens: &[String], env: &BTreeMap<&str, &str>) -> Vec<String> {
    tokens
        .iter()
        .map(|t| {
            let mut t = t.clone();
            for (k, v) in env {
                t = t.replace(&format!("${{{k}}}"), v);
            }
            t
        })
        .collect()
}

#[test]
fn without_init_json_the_new_unit_and_node_env_give_the_flags_of_the_old_unit() {
    let new_unit = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/apt/systemd/conet-node.service"),
    )
    .unwrap();
    let env: BTreeMap<&str, &str> = BTreeMap::from([
        ("CONET_RPC", "https://rpc1.conet.network"),
        ("BEAMIO_API_BASE", "https://beamio.ca"),
        ("CONET_PUBLIC_IP", "203.0.113.10"),
    ]);
    // What the old unit started the process with (systemd expands ${VAR} from node.env).
    let old = flag_pairs(&substitute(&exec_tokens(OLD_UNIT_EXEC), &env));
    // What the new unit starts it with, then what the process makes of it with the same node.env
    // and no init.json (the file is absent).
    let new_argv = exec_tokens(&new_unit);
    let settings = conet_node::init_args::EnvSettings {
        rpc: Some(env["CONET_RPC"].into()),
        api_base: Some(env["BEAMIO_API_BASE"].into()),
        public_ip: Some(env["CONET_PUBLIC_IP"].into()),
    };
    let merged = conet_node::init_args::merge(&new_argv, None, &settings, &|| vec![]).unwrap();
    let new = flag_pairs(&merged.argv);
    let mut old = old;
    // The only difference in the file itself is the added --init-config flag.
    assert_eq!(
        new.get("--init-config").map(String::as_str),
        Some("/etc/conet-node/init.json")
    );
    let mut new = new;
    new.remove("--init-config");
    old.remove("--init-config");
    assert_eq!(
        new, old,
        "an upgraded node would start differently with only node.env"
    );
    // And the values really are the old literal ones.
    assert_eq!(new["--listen"], "[::]:80");
    assert_eq!(new["--tls-listen"], "[::]:443");
    assert_eq!(new["--public-ip"], "203.0.113.10");
}

#[test]
fn the_shipped_example_init_json_is_valid_and_what_it_says_is_what_the_process_gets() {
    let text = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/apt/examples/init.json"),
    )
    .unwrap();
    let cfg = si_signer::init_config::parse_bytes(&text).unwrap();
    let argv: Vec<String> = ["conet-node", "--init-config", "/etc/conet-node/init.json"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let m =
        conet_node::init_args::merge(&argv, Some(&cfg), &Default::default(), &|| vec![]).unwrap();
    let p = flag_pairs(&m.argv);
    assert_eq!(p["--listen"], "[::]:80");
    assert_eq!(p["--tls-listen"], "[::]:443");
    assert_eq!(p["--public-ip"], "203.0.113.10");
    assert_eq!(p["--rpc"], "https://rpc1.conet.network");
}
