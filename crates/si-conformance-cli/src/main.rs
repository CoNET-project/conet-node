//! Native host for the conformance runner: `si-conformance-cli run|artifacts|bench <golden.json> [arg] [n]`.
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let golden = std::fs::read_to_string(a.get(2).expect("golden.json path")).expect("read golden");
    match a.get(1).map(String::as_str) {
        Some("run") => println!("{}", si_conformance::run_vectors(&golden)),
        Some("artifacts") => println!(
            "{}",
            si_conformance::make_artifacts(&golden, a.get(3).expect("seed hex"))
        ),
        Some("bench") => {
            let op = a.get(3).expect("op");
            let n: u32 = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(100);
            let t = Instant::now();
            si_conformance::bench(&golden, op, n);
            println!(
                "{op} n={n} total_ms={:.1} per_op_ms={:.3}",
                t.elapsed().as_secs_f64() * 1e3,
                t.elapsed().as_secs_f64() * 1e3 / n as f64
            );
        }
        _ => eprintln!("usage: si-conformance-cli run|artifacts|bench <golden.json> [seed|op] [n]"),
    }
}
