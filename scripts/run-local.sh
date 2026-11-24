#!/usr/bin/env bash
# Local dry-run of the scanner pipeline (no GHA / no Supabase submit).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE=""
IPA=""
EXPECTED=""
PUBLISHED=""
JOB_ID="00000000-0000-0000-0000-000000000001"
OWNER="local"
REPO="fixture"
TAG="local"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE="$2"; shift 2 ;;
    --ipa) IPA="$2"; shift 2 ;;
    --expected-sha256) EXPECTED="$2"; shift 2 ;;
    --published-at) PUBLISHED="$2"; shift 2 ;;
    --job-id) JOB_ID="$2"; shift 2 ;;
    --owner) OWNER="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 2 ;;
  esac
done

[[ -n "$SOURCE" && -n "$IPA" && -n "$EXPECTED" ]] || {
  echo "Usage: $0 --source DIR --ipa FILE --expected-sha256 HEX [--published-at ISO]"
  exit 2
}

WORK="$(mktemp -d)"
ADAPTERS="$WORK/adapters"
mkdir -p "$ADAPTERS"

python3 "$ROOT/adapters/identity.py" "$IPA" "$EXPECTED" "$ADAPTERS/identity.json"
python3 "$ROOT/adapters/age_policy.py" "${PUBLISHED:-}" "$ADAPTERS/age_policy.json"
bash "$ROOT/adapters/gitleaks.sh" "$SOURCE" "$ADAPTERS/gitleaks.json" || true
bash "$ROOT/adapters/semgrep.sh" "$SOURCE" "$ADAPTERS/semgrep.json" || true
python3 "$ROOT/adapters/osv_custom_spm.py" "$SOURCE" "$ADAPTERS/osv_custom_spm.json"
bash "$ROOT/adapters/osv_scanner.sh" "$SOURCE" "$ADAPTERS/osv_scanner.json" || true
python3 "$ROOT/adapters/ipa_light.py" "$IPA" "$ADAPTERS/ipa_light.json"

ACTUAL="$(python3 -c "import json; print(json.load(open('$ADAPTERS/identity.json')).get('ipa_sha256') or '')")"
cat > "$WORK/artifact.json" <<EOF
{
  "ipa_sha256": "$ACTUAL",
  "github_owner": "$OWNER",
  "github_repo": "$REPO",
  "release_tag": "$TAG",
  "source_commit": null,
  "asset_id": null,
  "asset_name": "$(basename "$IPA")",
  "published_at": ${PUBLISHED:+\"$PUBLISHED\"}${PUBLISHED:-null}
}
EOF

python3 "$ROOT/normalize/normalize_report.py" \
  --job-id "$JOB_ID" \
  --policy "$ROOT/policy/v1.json" \
  --artifact-json "$WORK/artifact.json" \
  --adapter-dir "$ADAPTERS" \
  --out "$WORK/report.json"

echo "Report: $WORK/report.json"
cat "$WORK/report.json" | python3 -m json.tool | head -80
