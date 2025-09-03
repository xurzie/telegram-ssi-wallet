*** /dev/null
--- b/scripts/dl_circuits.sh
@@ -0,0 +1,26 @@
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/sdk/circuits"
TMP="$ROOT/tmp"
mkdir -p "$DEST" "$TMP"

ZIP="$TMP/latest.zip"
echo "→ downloading circuits to $ZIP ..."
curl -L -o "$ZIP" https://circuits.privado.id/latest.zip || \
curl -L -o "$ZIP" https://iden3-circuits-bucket.s3.eu-west-1.amazonaws.com/latest.zip

echo "→ unpacking into $DEST ..."
unzip -o "$ZIP" -d "$DEST" > /dev/null
echo "✓ circuits ready in $DEST"