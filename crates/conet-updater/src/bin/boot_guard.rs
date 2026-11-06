//! `conet-boot-guard --root <dir>`: run as `ExecStartPre=+` of conet-node.service.
//! Counts starts of the current version until the updater marks it healthy; after
//! MAX_UNHEALTHY_BOOTS it switches back to `previous` and blacklists the version.
//! Offline, small, and never part of the binary it guards. Always exits 0 so the node starts.
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let Some(root) = a
        .windows(2)
        .find(|w| w[0] == "--root")
        .map(|w| std::path::PathBuf::from(&w[1]))
    else {
        eprintln!("usage: conet-boot-guard --root <dir>");
        return;
    };
    match conet_updater::agent::boot_guard(&root) {
        Ok(o) => eprintln!("boot guard: {o:?}"),
        Err(e) => eprintln!("boot guard error (start continues): {e}"),
    }
}
