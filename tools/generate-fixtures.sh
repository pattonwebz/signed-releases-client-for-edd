#!/usr/bin/env bash
#
# Regenerates the test fixtures in tests/fixtures using the real
# minisign binary, so the PHP verifier is tested against authentic signatures.
#
# Usage: MINISIGN=/path/to/minisign tools/generate-fixtures.sh
#
# The keypairs generated here are TEST KEYS ONLY. They are committed to the
# repository on purpose and must never be used to sign a real release.
set -euo pipefail

MINISIGN="${MINISIGN:-minisign}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES="$REPO_ROOT/tests/fixtures"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

command -v "$MINISIGN" >/dev/null || { echo "minisign not found (set MINISIGN=...)" >&2; exit 1; }
mkdir -p "$FIXTURES"

echo "== Generating TEST keypairs (unencrypted, -W) =="
"$MINISIGN" -G -f -W -p "$FIXTURES/testkey.pub" -s "$FIXTURES/testkey.sec"
"$MINISIGN" -G -f -W -p "$FIXTURES/otherkey.pub" -s "$FIXTURES/otherkey.sec"

echo "== Building sample plugin zip =="
mkdir -p "$WORK/sample-plugin"
cat > "$WORK/sample-plugin/sample-plugin.php" <<'PHP'
<?php
/**
 * Plugin Name: Sample Plugin
 * Version: 1.2.3
 */
PHP
(cd "$WORK" && zip -q -X -r sample-plugin-1.2.3.zip sample-plugin)
cp "$WORK/sample-plugin-1.2.3.zip" "$FIXTURES/sample-plugin-1.2.3.zip"

TRUSTED_COMMENT="slug:sample-plugin version:1.2.3 signed:2026-07-15T00:00:00Z"

echo "== Signing fixtures =="
# Valid signature with the trusted comment contract used by the release pipeline.
"$MINISIGN" -S -s "$FIXTURES/testkey.sec" \
    -m "$FIXTURES/sample-plugin-1.2.3.zip" \
    -t "$TRUSTED_COMMENT" \
    -c "signature for sample-plugin 1.2.3" \
    -x "$FIXTURES/sample-plugin-1.2.3.zip.minisig"

# Signature by a different (untrusted) key over the same file.
"$MINISIGN" -S -s "$FIXTURES/otherkey.sec" \
    -m "$FIXTURES/sample-plugin-1.2.3.zip" \
    -t "$TRUSTED_COMMENT" \
    -x "$FIXTURES/wrong-key.minisig"

# Valid signature whose trusted comment claims a different version.
"$MINISIGN" -S -s "$FIXTURES/testkey.sec" \
    -m "$FIXTURES/sample-plugin-1.2.3.zip" \
    -t "slug:sample-plugin version:9.9.9 signed:2026-07-15T00:00:00Z" \
    -x "$FIXTURES/version-mismatch.minisig"

# Valid signature whose trusted comment claims a different plugin slug.
"$MINISIGN" -S -s "$FIXTURES/testkey.sec" \
    -m "$FIXTURES/sample-plugin-1.2.3.zip" \
    -t "slug:evil-plugin version:1.2.3 signed:2026-07-15T00:00:00Z" \
    -x "$FIXTURES/slug-mismatch.minisig"

# Valid signature whose trusted comment carries no version token at all.
"$MINISIGN" -S -s "$FIXTURES/testkey.sec" \
    -m "$FIXTURES/sample-plugin-1.2.3.zip" \
    -t "slug:sample-plugin signed:2026-07-15T00:00:00Z" \
    -x "$FIXTURES/no-version.minisig"

echo "== Tampered zip (one byte flipped) =="
php -r '
$f = $argv[1];
$data = file_get_contents($f . "/sample-plugin-1.2.3.zip");
$data[100] = chr(ord($data[100]) ^ 0xFF);
file_put_contents($f . "/sample-plugin-1.2.3.tampered.zip", $data);
' "$FIXTURES"

echo "== Cross-checking every valid fixture with minisign -Vm =="
"$MINISIGN" -Vm "$FIXTURES/sample-plugin-1.2.3.zip" \
    -x "$FIXTURES/sample-plugin-1.2.3.zip.minisig" -p "$FIXTURES/testkey.pub"
"$MINISIGN" -Vm "$FIXTURES/sample-plugin-1.2.3.zip" \
    -x "$FIXTURES/wrong-key.minisig" -p "$FIXTURES/otherkey.pub"
"$MINISIGN" -Vm "$FIXTURES/sample-plugin-1.2.3.zip" \
    -x "$FIXTURES/version-mismatch.minisig" -p "$FIXTURES/testkey.pub"
"$MINISIGN" -Vm "$FIXTURES/sample-plugin-1.2.3.zip" \
    -x "$FIXTURES/slug-mismatch.minisig" -p "$FIXTURES/testkey.pub"
"$MINISIGN" -Vm "$FIXTURES/sample-plugin-1.2.3.zip" \
    -x "$FIXTURES/no-version.minisig" -p "$FIXTURES/testkey.pub"

echo "Done. Fixtures written to $FIXTURES"
