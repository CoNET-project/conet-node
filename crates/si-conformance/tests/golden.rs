//! Every golden vector must pass. The vectors come from live CoNET-SI code and openpgp.js.
#[test]
fn golden_vectors_pass() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/golden.json"
    );
    let golden = std::fs::read_to_string(path).expect("golden.json");
    let out: serde_json::Value =
        serde_json::from_str(&si_conformance::run_vectors(&golden)).unwrap();
    let failed: Vec<_> = out["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["pass"] != true)
        .collect();
    assert!(failed.is_empty(), "failed vectors: {failed:#?}");
    assert!(out["summary"]["pass"].as_u64().unwrap() >= 54);
}
