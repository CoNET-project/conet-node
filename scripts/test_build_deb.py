import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_deb as b


def fake_elf(glibc="GLIBC_2.34"):
    h = bytearray(64)
    h[:4] = b"\x7fELF"
    h[4] = 2
    h[18:20] = b"\x3e\x00"
    return bytes(h) + glibc.encode()


class Version(unittest.TestCase):
    def test_new_sorts_above_the_old_one_and_qa_below(self):
        old = "0.0.1+git20261126.ca64f794-1"
        for new in ("0.0.1+git20261127.00000000-1", "0.0.1+git20261127.ffffffff-1", "0.0.1+git20261126.ca64f794-2", "0.0.2+git20260101.aaaaaaaa-1"):
            self.assertGreater(b.version_compare(new, old), 0, new)
        self.assertLess(b.version_compare("0.0.1+git20261126.ca64f794-1~qa1", old), 0)
        self.assertEqual(b.version_compare(old, old), 0)

    def test_same_day_hash_order_is_not_monotonic_so_a_revision_is_needed(self):
        # Two commits of one day: the later one may have the smaller hash.
        a, c = "0.0.1+git20261127.ffffffff-1", "0.0.1+git20261127.00000000-1"
        self.assertLess(b.version_compare(c, a), 0)
        # The timestamp form fixes it: later time sorts higher whatever the hash, and it still beats the date form.
        early, late = "0.0.1+git20261127100000.ffffffff-1", "0.0.1+git20261127110000.00000000-1"
        self.assertGreater(b.version_compare(late, early), 0)
        self.assertGreater(b.version_compare(early, "0.0.1+git20261127.ffffffff-1"), 0)
        self.assertGreater(b.version_compare(early, "0.0.1+git20261126.ca64f794-1"), 0)

    def test_make_version(self):
        self.assertEqual(b.make_version("0.0.1", "20261127", "1a2b3c4d" + "0" * 32, 1), "0.0.1+git20261127.1a2b3c4d-1")


class Binary(unittest.TestCase):
    def test_glibc_floor_and_elf_shape(self):
        with tempfile.TemporaryDirectory() as t:
            ok = Path(t, "ok")
            ok.write_bytes(fake_elf("GLIBC_2.34 GLIBC_2.43"))
            digest, size = b.check_binary(ok)
            self.assertEqual((digest, size), (hashlib.sha256(ok.read_bytes()).hexdigest(), ok.stat().st_size))
            for name, data in (("new", fake_elf("GLIBC_2.44")), ("text", b"#!/bin/sh\n"), ("arm", fake_elf().replace(b"\x3e\x00", b"\xb7\x00", 1))):
                p = Path(t, name)
                p.write_bytes(data)
                with self.assertRaises(SystemExit):
                    b.check_binary(p)


class Stage(unittest.TestCase):
    def test_tree_has_exactly_the_planned_files_and_no_etc(self):
        with tempfile.TemporaryDirectory() as t:
            bins = Path(t, "bin")
            bins.mkdir()
            for n in b.BINARIES:
                (bins / n).write_bytes(fake_elf() + n.encode())
            tree, entries = b.stage(Path(t, "out"), bins, "0.0.1+git20261127.1a2b3c4d-1", 1_795_801_524)
            files = sorted(p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file())
            want = sorted([r for r, _ in entries] + ["DEBIAN/control", "DEBIAN/md5sums", "DEBIAN/postinst"])
            self.assertEqual(files, want)
            self.assertFalse(any(f.startswith("etc/") for f in files))
            self.assertEqual(set(r for r, _ in entries if r.startswith("usr/lib/conet-node/")), {"usr/lib/conet-node/conet-node", "usr/lib/conet-node/conet-signer"})
            control = (tree / "DEBIAN/control").read_text()
            self.assertIn("Version: 0.0.1+git20261127.1a2b3c4d-1\n", control)
            self.assertIn("Depends: libc6 (>= 2.43-2ubuntu2.3), libgcc-s1 (>= 16-20260322-1ubuntu1), systemd (>= 255)\n", control)
            for line in (tree / "DEBIAN/md5sums").read_text().splitlines():
                digest, rel = line.split("  ", 1)
                self.assertEqual(hashlib.md5((tree / rel).read_bytes()).hexdigest(), digest)
            self.assertEqual(os.stat(tree / "DEBIAN/postinst").st_mode & 0o777, 0o755)
            self.assertEqual(int((tree / "usr/lib/conet-node/conet-node").stat().st_mtime), 1_795_801_524)

    def test_units_users_and_maintainer_script_say_what_the_docs_promise(self):
        root = b.ROOT / "deploy/apt"
        node = (root / "systemd/conet-node.service").read_text()
        signer = (root / "systemd/conet-signer.service").read_text()
        users = (root / "sysusers.d/conet-node.conf").read_text()
        post = (root / "debian/postinst").read_text()
        self.assertIn("--allow-uid 61051", signer)
        self.assertIn("conet-node 61051", users)
        self.assertIn("conet-signer 61050", users)
        self.assertNotIn("--insecure", node + signer)
        self.assertNotIn("EnvironmentFile=-", node + signer)         # a missing env file must stop the start
        self.assertIn("--evidence-log /var/lib/conet-node/evidence/evidence.jsonl", node)
        self.assertIn("\nAssertPathExists=/var/lib/conet-signer/keystore.json", signer)
        self.assertNotIn("ConditionPathExists", signer)
        for word in ("systemctl", "enable", "restart", "start ", "stop ", "reload"):
            self.assertNotIn(word, "\n".join(l for l in post.splitlines() if not l.lstrip().startswith("#")), word)
        self.assertIn("[Install]", node)

    def test_first_start_units_are_non_interactive_and_chained(self):
        root = b.ROOT / "deploy/apt"
        first = (root / "systemd/conet-node-first-start.service").read_text()
        signer = (root / "systemd/conet-signer.service").read_text()
        node = (root / "systemd/conet-node.service").read_text()
        tmp = (root / "tmpfiles.d/conet-node.conf").read_text()
        self.assertIn("\nType=oneshot\n", first)
        self.assertIn("\nStandardInput=null\n", first)
        self.assertIn("\nTimeoutStartSec=", first)
        self.assertNotIn("--insecure", first)
        self.assertIn("ExecStart=/usr/lib/conet-node/conet-signer first-start", first)
        self.assertIn("\nRequires=conet-node-first-start.service\n", signer)
        self.assertIn("conet-node-first-start.service", [w for l in signer.splitlines() if l.startswith("After=") for w in l[6:].split()])
        # The node unit hands settings to the process through init.json / node.env, never as
        # ${VAR} flags that an empty value would turn into a valueless flag.
        self.assertNotIn("${", node)
        self.assertIn("--init-config /etc/conet-node/init.json", node)
        for hard in ("--listen", "--tls-listen", "--rpc ", "--api-base", "--public-ip"):
            self.assertNotIn(hard, node.split("ExecStart=", 1)[1].split("Restart=", 1)[0], hard)
        self.assertIn("d /etc/credstore.encrypted 0700 root root", tmp)
        files = [src for src, _, _ in b.FILES]
        self.assertIn("deploy/apt/systemd/conet-node-first-start.service", files)
        self.assertIn("deploy/apt/examples/init.json", files)


if __name__ == "__main__":
    unittest.main()
