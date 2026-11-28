#!/usr/bin/env python3
"""Build the `conet-node` APT package from this checkout (Linux, needs dpkg-deb unless --stage-only).

The package carries the two binaries, their systemd units, sysusers and tmpfiles snippets, one
maintainer script (creates the accounts; never starts, stops, enables, restarts or reloads anything),
the example environment files and the docs. Under /etc the package only creates the empty directory /etc/credstore.encrypted (tmpfiles).

Version: `<workspace version>+git<UTC commit date YYYYMMDD>.<8-char commit>-1`, for example
`0.0.1+git20261127.1a2b3c4d-1`. It must sort above the version it replaces. Same-day rule: a second commit on one date may have a smaller hash and then needs `--timestamp-version`
(date and time of the commit, `YYYYMMDDHHMMSS`), because the short hash alone does not sort by time.
The build refuses any version that does not sort above `--replaces`.

Usage:
  scripts/build_deb.py --out DIR [--bin-dir DIR] [--revision N] [--replaces VERSION] [--timestamp-version] [--stage-only]
  --bin-dir   directory holding `conet-node` and `conet-signer` (release ELFs). Without it the script
              runs `cargo build --release --locked -p conet-node -p si-signer` and uses target/release.
  --stage-only  write the package tree and metadata, skip dpkg-deb (tests, macOS).
The checkout must be clean and HEAD must be the commit to package; the build refuses otherwise.
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = "conet-node"
ARCH = "amd64"
MAINTAINER = "CoNET Project <info@conet.network>"
HOMEPAGE = "https://conet.network/"
# Same floors as the previous package (built on the same toolchain); the glibc symbol check below
# keeps the binaries inside them.
DEPENDS = "libc6 (>= 2.43-2ubuntu2.3), libgcc-s1 (>= 16-20260322-1ubuntu1), systemd (>= 255)"
MAX_GLIBC = (2, 43)
BINARIES = ("conet-node", "conet-signer")
PREVIOUS = "0.0.1+git20261126.ca64f794-1"


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw).stdout


def workspace_version():
    text = (ROOT / "Cargo.toml").read_text()
    sect = text.split("[workspace.package]", 1)[1].split("\n[", 1)[0]
    return re.search(r'^version = "([0-9][0-9A-Za-z.]*)"', sect, re.M).group(1)


def commit_info(git_dir=ROOT, fmt="%Y%m%d"):
    env = dict(os.environ, TZ="UTC", GIT_OPTIONAL_LOCKS="0")
    out = subprocess.run(["git", "-C", str(git_dir), "show", "-s", "--format=%H %ct", "HEAD"], check=True, text=True, capture_output=True, env=env).stdout.split()
    full, ts = out[0], int(out[1])
    import datetime
    date = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(fmt)
    return full, ts, date


def make_version(upstream, date, full, revision=1):
    return f"{upstream}+git{date}.{full[:8]}-{revision}"


def _order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first:
                first = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return first
    return 0


def version_compare(a, b):
    """dpkg version order (no epoch): negative, zero, positive."""
    def split(v):
        if "-" in v:
            up, rev = v.rsplit("-", 1)
        else:
            up, rev = v, ""
        return up, rev
    ua, ra = split(a)
    ub, rb = split(b)
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def max_glibc(data):
    best = (0, 0)
    for m in re.finditer(rb"GLIBC_(\d+)\.(\d+)", data):
        best = max(best, (int(m.group(1)), int(m.group(2))))
    return best


def check_binary(path):
    data = Path(path).read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[18:20] != b"\x3e\x00":
        raise SystemExit(f"{path}: not a 64-bit x86-64 ELF")
    if max_glibc(data) > MAX_GLIBC:
        raise SystemExit(f"{path}: needs glibc above {MAX_GLIBC}, the Depends floor")
    return hashlib.sha256(data).hexdigest(), len(data)


def sha256_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


FILES = [
    # (source relative to repo, destination in the package, mode)
    ("deploy/apt/systemd/conet-node.service", "usr/lib/systemd/system/conet-node.service", 0o644),
    ("deploy/apt/systemd/conet-signer.service", "usr/lib/systemd/system/conet-signer.service", 0o644),
    ("deploy/apt/systemd/conet-node-first-start.service", "usr/lib/systemd/system/conet-node-first-start.service", 0o644),
    ("deploy/apt/sysusers.d/conet-node.conf", "usr/lib/sysusers.d/conet-node.conf", 0o644),
    ("deploy/apt/tmpfiles.d/conet-node.conf", "usr/lib/tmpfiles.d/conet-node.conf", 0o644),
    ("deploy/apt/examples/node.env", "usr/share/doc/conet-node/examples/node.env", 0o644),
    ("deploy/apt/examples/signer.env", "usr/share/doc/conet-node/examples/signer.env", 0o644),
    ("deploy/apt/examples/init.json", "usr/share/doc/conet-node/examples/init.json", 0o644),
    ("deploy/apt/README.md", "usr/share/doc/conet-node/README.md", 0o644),
    ("LICENSE", "usr/share/doc/conet-node/copyright", 0o644),
]


def stage(out, bin_dir, version, epoch, git_dir=ROOT):
    tree = Path(out) / "tree"
    if tree.exists():
        shutil.rmtree(tree)
    entries = []  # (relative path, mode) of every file, for md5sums and timestamps
    for name in BINARIES:
        dst = tree / "usr/lib/conet-node" / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(bin_dir) / name, dst)
        dst.chmod(0o755)
        entries.append((dst.relative_to(tree).as_posix(), 0o755))
    for src, rel, mode in FILES:
        dst = tree / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(git_dir / src, dst)
        dst.chmod(mode)
        entries.append((rel, mode))
    entries.sort()
    size_kib = sum((tree / r).stat().st_size for r, _ in entries) // 1024 + 1
    deb = tree / "DEBIAN"
    deb.mkdir()
    control = (
        f"Package: {PKG}\nVersion: {version}\nArchitecture: {ARCH}\nSection: net\nPriority: optional\n"
        f"Maintainer: {MAINTAINER}\nInstalled-Size: {size_kib}\nDepends: {DEPENDS}\nHomepage: {HOMEPAGE}\n"
        "Description: CoNET node (Rust)\n"
        " Entry, forwarding and mailbox node for CoNET chat, with its key-holding signer process.\n"
        " Ships the binaries, three systemd units (not enabled), sysusers and tmpfiles snippets and\n"
        " example environment files. The maintainer script creates two accounts and two directories;\n"
        " it never starts or restarts a service.\n"
    )
    (deb / "control").write_text(control)
    (deb / "md5sums").write_text("".join(f"{hashlib.md5((tree / r).read_bytes()).hexdigest()}  {r}\n" for r, _ in entries))
    shutil.copyfile(git_dir / "deploy/apt/debian/postinst", deb / "postinst")
    (deb / "postinst").chmod(0o755)
    for p in sorted(tree.rglob("*")):
        os.utime(p, (epoch, epoch), follow_symlinks=False)
    os.utime(tree, (epoch, epoch))
    return tree, entries


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--bin-dir")
    ap.add_argument("--revision", type=int, default=1)
    ap.add_argument("--replaces", default=PREVIOUS)
    ap.add_argument("--timestamp-version", action="store_true", help="use YYYYMMDDHHMMSS instead of the date")
    ap.add_argument("--stage-only", action="store_true")
    ap.add_argument("--allow-dirty", action="store_true", help="tests only")
    a = ap.parse_args(argv)
    if not a.allow_dirty and run(["git", "-C", str(ROOT), "status", "--porcelain"]).strip():
        raise SystemExit("the checkout is not clean; commit first (the package must name a commit)")
    full, ts, date = commit_info(fmt="%Y%m%d%H%M%S" if a.timestamp_version else "%Y%m%d")
    version = make_version(workspace_version(), date, full, a.revision)
    if version_compare(version, a.replaces) <= 0:
        raise SystemExit(f"{version} does not sort above {a.replaces}")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    bin_dir = a.bin_dir
    if bin_dir is None:
        subprocess.run(["cargo", "build", "--release", "--locked", "-p", "conet-node", "-p", "si-signer"], check=True, cwd=ROOT)
        bin_dir = ROOT / "target/release"
    sums = {n: check_binary(Path(bin_dir) / n) for n in BINARIES}
    tree, entries = stage(out, bin_dir, version, ts)
    lines = [f"version {version}", f"commit {full}", f"source_date_epoch {ts}"]
    lines += [f"elf {n} sha256 {h} bytes {b}" for n, (h, b) in sums.items()]
    if not a.stage_only:
        deb = out / f"{PKG}_{version}_{ARCH}.deb"
        env = dict(os.environ, SOURCE_DATE_EPOCH=str(ts))
        subprocess.run(["dpkg-deb", "--root-owner-group", "-Zxz", "--threads-max=1", "--build", str(tree), str(deb)], check=True, env=env)
        lines += [f"deb {deb.name} sha256 {sha256_file(deb)} bytes {deb.stat().st_size}"]
    (out / "BUILD-RECORD.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
