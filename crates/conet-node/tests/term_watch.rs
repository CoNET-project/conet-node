//! Term watch (read-only task in the running node): mapping of the contract's read-time term
//! state, once-only log lines, the recorded renewals of node line 45e9c5d0
//! (`data/precheck-fixture.json`), and the read layer against a local mock JSON-RPC (every read
//! of one round pinned to the same block).
use alloy_primitives::keccak256;
use conet_node::nr2::Nr2Reader;
use conet_node::stake_term::{Advice, Reminders, Renewal};
use conet_node::term_watch::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const C: u128 = 1_000_000_000_000_000_000;
const DAY: u64 = 86_400;
const END: u64 = 1_900_000_000;
const LEN: u64 = 15_768_000;

fn base() -> TermReads {
    TermReads {
        now: END - 40 * DAY,
        term_end: END,
        term_base: 5 * C,
        term_length: LEN,
        stake_stop: false,
        in_term: true,
        read_base: 5 * C,
        stake: 5 * C,
        need_at_end: 5 * C,
        min_stake_now: 5 * C,
    }
}

#[test]
fn read_time_state_maps_like_the_contract() {
    // Running term: pending, renewal compares with minStakeAt(termEnd).
    let v = term_view_from(&TermReads {
        need_at_end: 10 * C,
        min_stake_now: 12 * C,
        ..base()
    });
    assert_eq!((v.renewal, v.current_threshold), (Renewal::Pending, 10 * C));
    // Stored end passed, read-time still in term: renewed, next end after now (k terms).
    let v = term_view_from(&TermReads {
        now: END + LEN + 5,
        ..base()
    });
    assert_eq!(
        v.renewal,
        Renewal::Renewed {
            next_term_ends_at: END + 2 * LEN
        }
    );
    let v = term_view_from(&TermReads { now: END, ..base() });
    assert_eq!(
        v.renewal,
        Renewal::Renewed {
            next_term_ends_at: END + LEN
        }
    );
    // Stored end passed, read-time not in term: failed even before anyone writes it; the next
    // step needs the latest full amount.
    let v = term_view_from(&TermReads {
        now: END + 1,
        in_term: false,
        min_stake_now: 10 * C,
        ..base()
    });
    assert_eq!((v.renewal, v.current_threshold), (Renewal::Failed, 10 * C));
    // stakeStop (slashed below the floor inside the term): failed at any time.
    let v = term_view_from(&TermReads {
        stake_stop: true,
        in_term: false,
        ..base()
    });
    assert_eq!(v.renewal, Renewal::Failed);
}

#[test]
fn each_fact_is_logged_once() {
    let r = Reminders::default();
    let mut w = TermWatch::default();
    let short = TermReads {
        stake: 4 * C,
        need_at_end: 5 * C,
        ..base()
    };
    // 40 days before: nothing.
    let at = |now| TermReads {
        now,
        ..short.clone()
    };
    assert_eq!(
        w.step(&term_view_from(&at(END - 40 * DAY)), END - 40 * DAY, &r),
        None
    );
    // 30-day reminder once, then silence until 7 days, then 1 day.
    let mut said = vec![];
    for now in [
        END - 30 * DAY,
        END - 29 * DAY,
        END - 7 * DAY,
        END - 6 * DAY,
        END - DAY,
        END - 60,
    ] {
        if let Some(l) = w.step(&term_view_from(&at(now)), now, &r) {
            said.push((now, l));
        }
    }
    assert_eq!(
        said.iter().map(|s| s.0).collect::<Vec<_>>(),
        vec![END - 30 * DAY, END - 7 * DAY, END - DAY]
    );
    assert!(
        said[0].1.contains("missing 1000000000000000000"),
        "{}",
        said[0].1
    );
    assert!(said[0].1.contains("path_after_fines=true"), "{}", said[0].1);
    // Topped up after a reminder: said once.
    let mut w2 = TermWatch::default();
    w2.step(&term_view_from(&at(END - 7 * DAY)), END - 7 * DAY, &r)
        .unwrap();
    let funded = TermReads {
        now: END - 6 * DAY,
        stake: 5 * C,
        ..short.clone()
    };
    let l = w2.step(&term_view_from(&funded), funded.now, &r).unwrap();
    assert!(l.contains("meets the renewal threshold"), "{l}");
    assert_eq!(w2.step(&term_view_from(&funded), funded.now + 60, &r), None);
    // Ended short: the stop is logged once.
    let failed = TermReads {
        now: END + 10,
        in_term: false,
        stake_stop: true,
        ..short.clone()
    };
    let l = w.step(&term_view_from(&failed), END + 10, &r).unwrap();
    assert!(l.contains("renewal failed"), "{l}");
    assert_eq!(w.step(&term_view_from(&failed), END + 70, &r), None);

    // A node that meets the threshold: silent at start, renewal logged once.
    let mut w = TermWatch::default();
    assert_eq!(w.step(&term_view_from(&base()), base().now, &r), None);
    let renewed = TermReads {
        now: END + 5,
        ..base()
    };
    let l = w.step(&term_view_from(&renewed), END + 5, &r).unwrap();
    assert!(l.contains(&format!("next end {}", END + LEN)), "{l}");
    assert_eq!(w.step(&term_view_from(&renewed), END + 65, &r), None);
}

fn n(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

/// The two renewals recorded from the real contract (45e9c5d0): the short node is reminded
/// before and reported stopped after; the funded node (stake == minStakeAt(termEnd)) is never
/// reminded and, once settled, runs its next term.
#[test]
fn recorded_renewals() {
    let f: Value = serde_json::from_str(include_str!("data/precheck-fixture.json")).unwrap();
    let r = Reminders::default();
    for row in f["renewal"].as_array().unwrap() {
        let reads = TermReads {
            now: n(&row["termEnd"]) as u64 - DAY,
            term_end: n(&row["termEnd"]) as u64,
            term_base: n(&row["termBase"]),
            term_length: n(&row["termLength"]) as u64,
            stake_stop: false,
            in_term: true,
            read_base: n(&row["termBase"]),
            stake: n(&row["stake"]),
            need_at_end: n(&row["needAtEnd"]),
            min_stake_now: n(&row["needAtEnd"]),
        };
        let mut w = TermWatch::default();
        let before = w.step(&term_view_from(&reads), reads.now, &r);
        let after = if row["event"] == "TermStarted" {
            TermReads {
                now: n(&row["termEnd"]) as u64 + 1,
                term_end: n(&row["termEndAfter"]) as u64,
                ..reads.clone()
            }
        } else {
            TermReads {
                now: n(&row["termEnd"]) as u64 + 1,
                stake_stop: row["stakeStopAfter"].as_bool().unwrap(),
                in_term: false,
                ..reads.clone()
            }
        };
        let v = term_view_from(&after);
        match row["event"].as_str().unwrap() {
            "TermStarted" => {
                assert_eq!(before, None);
                assert_eq!(v.renewal, Renewal::Pending);
                assert_eq!(
                    conet_node::stake_term::advise(&v, after.now, &r),
                    Advice::Fine
                );
            }
            "TermRenewalFailed" => {
                assert!(before.unwrap().contains("will fail"));
                assert_eq!(v.renewal, Renewal::Failed);
                assert!(w
                    .step(&v, after.now, &r)
                    .unwrap()
                    .contains("renewal failed"));
            }
            e => panic!("{e}"),
        }
    }
}

// ---- read layer against a mock JSON-RPC ----

fn sel(sig: &str) -> String {
    hex::encode(&keccak256(sig.as_bytes())[..4])
}
fn word(v: u128) -> String {
    format!("{v:064x}")
}

async fn serve(answers: HashMap<String, String>, seen: Arc<Mutex<Vec<String>>>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let answers = answers.clone();
            let seen = seen.clone();
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
                let result = match req["method"].as_str().unwrap() {
                    "eth_getBlockByNumber" => {
                        json!({ "number": "0x2a", "timestamp": format!("0x{:x}", END - 7 * DAY) })
                    }
                    "eth_call" => {
                        let data = req["params"][0]["data"].as_str().unwrap();
                        seen.lock()
                            .unwrap()
                            .push(req["params"][1].as_str().unwrap().to_string());
                        json!(format!("0x{}", answers[&data[2..10]]))
                    }
                    m => panic!("unexpected {m}"),
                };
                let out = json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string();
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

#[tokio::test]
async fn read_pins_one_block_and_decodes() {
    let mut a = HashMap::new();
    // termOf(uint256) -> (uint64 termEnd, uint128 termBase, uint32 termLength, bool stakeStop)
    a.insert(
        sel("termOf(uint256)"),
        [word(END as u128), word(5 * C), word(LEN as u128), word(0)].concat(),
    );
    a.insert(sel("termStateOf(uint256)"), [word(1), word(5 * C)].concat());
    a.insert(sel("stakeOf(uint256)"), word(4 * C));
    a.insert(sel("minStakeAt(uint64)"), word(10 * C));
    a.insert(sel("minStakeNow()"), word(12 * C));
    let seen = Arc::new(Mutex::new(vec![]));
    let url = serve(a, seen.clone()).await;
    let reader = Nr2Reader {
        rpc: conet_node::chain::Rpc::new(&url).unwrap(),
        registry: "0x00000000000000000000000000000000c0de0001".into(),
    };
    let r = read(&reader, 101).await.unwrap();
    assert_eq!(
        r,
        TermReads {
            now: END - 7 * DAY,
            term_end: END,
            term_base: 5 * C,
            term_length: LEN,
            stake_stop: false,
            in_term: true,
            read_base: 5 * C,
            stake: 4 * C,
            need_at_end: 10 * C,
            min_stake_now: 12 * C,
        }
    );
    let tags = seen.lock().unwrap().clone();
    assert_eq!(tags.len(), 5);
    assert!(tags.iter().all(|t| t == "0x2a"), "{tags:?}");
    // And the operator is told to reach minStakeAt(termEnd), not minStakeNow.
    let mut w = TermWatch::default();
    let l = w
        .step(&term_view_from(&r), r.now, &Reminders::default())
        .unwrap();
    assert!(
        l.contains("reaches 10000000000000000000 (missing 6000000000000000000)"),
        "{l}"
    );
}
