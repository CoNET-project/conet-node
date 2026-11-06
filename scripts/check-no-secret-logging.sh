#!/usr/bin/env bash
# Requirement R3: no key material or whole config objects in logs.
# Fails when a log/print macro mentions a secret-looking name, or Debug-prints a config/secret type.
set -euo pipefail
cd "$(dirname "$0")/.."
names='private_?key|privateKey|passwd|passphrase|pgp_pass|pgp_armored|wallet_hex|armoredPrivate|secrets?|kek|seed'
# a secret-looking variable interpolated ({name}, {name:?}) or passed as an argument (, name) or field (name = / %name / ?name)
pattern="(trace|debug|info|warn|error|println|eprintln|print|eprint)!\\([^;]*(\\{|, *&?|[%?])(self\\.|c\\.|cfg\\.)?($names)\\b|BEGIN PGP PRIVATE"
hits=$(grep -rnE --include='*.rs' "$pattern" crates/*/src || true)
# whole-object debug dumps of config/secret holders
dumps=$(grep -rnE --include='*.rs' '\{:\?\}.*\b(cfg|config|secrets|keystore|initData|setup)\b|\?(cfg|config|secrets|keystore)\b' crates/*/src || true)
derive=$(grep -rnB2 --include='*.rs' -E 'pub struct (Secrets|SignerConfig|SecretCert)\\b' crates/*/src | grep -E 'derive\(.*Debug' || true)
if [[ -n "$hits$dumps$derive" ]]; then
  echo "possible secret logging:"
  printf '%s\n' "$hits" "$dumps" "$derive" | sed '/^$/d'
  exit 1
fi
echo "no secret logging found"
