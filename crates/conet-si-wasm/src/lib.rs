//! wasm host: same runner, exported to JS through wasm-bindgen.
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn run_vectors(golden: &str) -> String {
    si_conformance::run_vectors(golden)
}

#[wasm_bindgen]
pub fn make_artifacts(golden: &str, seed_hex: &str) -> String {
    si_conformance::make_artifacts(golden, seed_hex)
}

#[wasm_bindgen]
pub fn bench(golden: &str, op: &str, n: u32) -> String {
    si_conformance::bench(golden, op, n)
}
