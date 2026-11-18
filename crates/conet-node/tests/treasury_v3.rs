//! Treasury V3 read path against the TypeScript reference (CoNET-SI 215afb1). The fixture holds
//! logs and the output of the TS `parseBridgeOperation` on them; the Rust decoder must match it
//! field by field. Also: cursor planning, restart resume and the state file. No network, no ports.
use alloy_primitives::{hex, B256};
use conet_node::treasury_v3::{
    advance, chunk_ranges, decode, load_cursor, next_window, save_cursor, start_cursor, Cursor,
    CursorError, RawLog, Window,
};
use serde_json::Value;
use std::path::PathBuf;

fn fixture() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/treasury_v3_bridge_operation.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn raw_log(v: &Value) -> RawLog {
    let topics = v["topics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().parse::<B256>().unwrap())
        .collect();
    RawLog {
        topics,
        data: hex::decode(v["data"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
        transaction_hash: v["transactionHash"].as_str().unwrap().parse().unwrap(),
        block_number: v["blockNumber"].as_u64().unwrap(),
    }
}

#[test]
fn decoder_matches_the_ts_parser_field_by_field_on_every_fixture_case() {
    let f = fixture();
    let cases = f["cases"].as_array().unwrap();
    assert!(cases.len() >= 9, "fixture shrank");
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let log = raw_log(&case["log"]);
        let got = decode(&log);
        let expect = &case["expect"];
        if expect.get("error").is_some() {
            assert!(got.is_err(), "{name}: TS throws, Rust returned {got:?}");
        } else if expect.get("null").is_some() {
            assert_eq!(got.as_ref().unwrap(), &None, "{name}: TS returns null");
        } else {
            let op = got
                .unwrap()
                .unwrap_or_else(|| panic!("{name}: TS returns an operation"));
            let rust = op.to_json();
            let ts = &expect["ok"];
            // Same key set, then each field, so a mismatch names the field.
            let keys = |v: &Value| {
                v.as_object()
                    .unwrap()
                    .keys()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>()
            };
            assert_eq!(keys(&rust), keys(ts), "{name}: key set");
            for (k, want) in ts.as_object().unwrap() {
                assert_eq!(&rust[k], want, "{name}: field {k}");
            }
        }
    }
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("conet-treasury-v3-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_fresh_start_begins_just_before_the_deploy_block_and_scans_to_the_head() {
    assert_eq!(
        start_cursor(None, 100, 1000),
        Cursor {
            last_processed: 99,
            scan_target: 1000
        }
    );
    // No deploy block: start at the head.
    assert_eq!(
        start_cursor(None, 0, 1000),
        Cursor {
            last_processed: 1000,
            scan_target: 1000
        }
    );
}

#[test]
fn a_saved_cursor_resumes_where_it_stopped_and_is_clamped_to_the_deploy_block() {
    let saved = Cursor {
        last_processed: 500,
        scan_target: 900,
    };
    assert_eq!(start_cursor(Some(saved), 100, 1000), saved);
    // Saved below the deploy block: clamped up.
    let low = Cursor {
        last_processed: 10,
        scan_target: 20,
    };
    assert_eq!(
        start_cursor(Some(low), 100, 1000),
        Cursor {
            last_processed: 99,
            scan_target: 99
        }
    );
}

#[test]
fn a_tick_plans_at_most_chunk_times_chunks_per_tick_blocks_and_refreshes_the_head_when_caught_up() {
    let mut c = Cursor {
        last_processed: 500,
        scan_target: 900,
    };
    // 400 * 4 = 1600 blocks at most, capped at the scan target.
    assert_eq!(
        next_window(&mut c, 1000, 400, 4),
        Some(Window { from: 501, to: 900 })
    );
    // Caught up: the head is refreshed, then the window runs to the new head.
    let mut c = Cursor {
        last_processed: 900,
        scan_target: 900,
    };
    assert_eq!(
        next_window(&mut c, 1200, 400, 4),
        Some(Window {
            from: 901,
            to: 1200
        })
    );
    // Nothing to do at the head.
    let mut c = Cursor {
        last_processed: 1200,
        scan_target: 1200,
    };
    assert_eq!(next_window(&mut c, 1200, 400, 4), None);
}

#[test]
fn a_window_is_split_into_chunks_that_cover_it_exactly_once() {
    let chunks = chunk_ranges(Window { from: 1, to: 1000 }, 400);
    assert_eq!(
        chunks,
        vec![
            Window { from: 1, to: 400 },
            Window { from: 401, to: 800 },
            Window {
                from: 801,
                to: 1000
            }
        ]
    );
    let total: u64 = chunks.iter().map(|w| w.to - w.from + 1).sum();
    assert_eq!(total, 1000);
}

#[test]
fn the_cursor_moves_only_when_no_log_failed() {
    let mut c = Cursor {
        last_processed: 500,
        scan_target: 900,
    };
    advance(&mut c, 900, 1);
    assert_eq!(
        c.last_processed, 500,
        "a failed window must be fetched again"
    );
    advance(&mut c, 900, 0);
    assert_eq!(c.last_processed, 900);
}

/// Run `heads.len()` ticks. When `restart_after` is set, save the cursor, load it back and start
/// again from the saved state after that many ticks. Returns the windows fetched, in order.
fn run_ticks(heads: &[u64], restart_after: Option<usize>, dir: &std::path::Path) -> Vec<Window> {
    let deploy = 100;
    let file = dir.join("cursor.json");
    let mut c = start_cursor(None, deploy, heads[0]);
    let mut out = Vec::new();
    for (i, head) in heads.iter().enumerate() {
        if restart_after == Some(i) {
            save_cursor(&file, &c, 1).unwrap();
            c = start_cursor(load_cursor(&file).unwrap(), deploy, *head);
        }
        if let Some(w) = next_window(&mut c, *head, 400, 4) {
            for chunk in chunk_ranges(w, 400) {
                out.push(chunk);
            }
            advance(&mut c, w.to, 0);
        }
    }
    out
}

#[test]
fn a_restart_in_the_middle_neither_skips_nor_repeats_a_block() {
    // Heads grow in jumps, so some ticks are full windows and some are partial.
    let heads = [
        1000u64, 1000, 1800, 1801, 2600, 2600, 4000, 4001, 4001, 9000, 9000, 9000, 9000,
    ];
    let dir = scratch("restart");
    let straight = run_ticks(&heads, None, &dir);
    for at in 1..heads.len() {
        let restarted = run_ticks(&heads, Some(at), &dir);
        assert_eq!(
            restarted, straight,
            "restart before tick {at} changed the windows"
        );
    }
    // Every block from the deploy block up to the last head is covered exactly once.
    let mut covered = 0u64;
    let mut next = 100u64;
    for w in &straight {
        assert_eq!(w.from, next, "gap or overlap at {w:?}");
        covered += w.to - w.from + 1;
        next = w.to + 1;
    }
    assert_eq!(covered, 9000 - 99);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_state_file_round_trips_and_keeps_the_ts_keys() {
    let dir = scratch("state");
    let file = dir.join("state.json");
    assert_eq!(
        load_cursor(&file).unwrap(),
        None,
        "missing file is a first start"
    );
    let c = Cursor {
        last_processed: 123,
        scan_target: 456,
    };
    save_cursor(&file, &c, 1_700_000_000).unwrap();
    assert_eq!(load_cursor(&file).unwrap(), Some(c));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(v["version"], 1);
    assert_eq!(v["lastProcessedBlock"], "123");
    assert_eq!(v["scanTargetBlock"], "456");
    // The temporary file is renamed away.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(leftovers.len(), 1, "leftover temp file: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_corrupt_or_foreign_state_file_is_refused_not_rescanned() {
    let dir = scratch("corrupt");
    let file = dir.join("state.json");
    for bad in [
        "not json",
        r#"{"version":2,"lastProcessedBlock":"1","scanTargetBlock":"2"}"#,
        r#"{"version":1,"lastProcessedBlock":"x","scanTargetBlock":"2"}"#,
        r#"{"version":1,"lastProcessedBlock":"1"}"#,
    ] {
        std::fs::write(&file, bad).unwrap();
        assert!(
            matches!(load_cursor(&file), Err(CursorError::Format(_))),
            "{bad} was accepted"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
