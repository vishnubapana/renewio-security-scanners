#!/usr/bin/env bash
# Stage B: Semgrep Community Edition (best-effort Swift/JS/TS).
set -euo pipefail
SOURCE_DIR="${1:?source dir}"
OUT_JSON="${2:?out json}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! command -v semgrep >/dev/null 2>&1; then
  python3 -m pip install --quiet semgrep==1.97.0
fi

set +e
semgrep scan --config p/default --config p/secrets --json --output "$TMP/sg.json" "$SOURCE_DIR" >/dev/null 2>"$TMP/sg.err"
RC=$?
set -e

python3 - "$TMP/sg.json" "$TMP/sg.err" "$OUT_JSON" "$RC" <<'PY'
import json, sys
from pathlib import Path
path, err, out, rc = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4])
findings = []
limitations = ["semgrep_ce_swift_limited_to_single_function"]
ok = True
if path.exists() and path.stat().st_size:
    data = json.loads(path.read_text())
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        sev = (extra.get("severity") or "WARNING").upper()
        mapped = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(sev, "medium")
        check = r.get("check_id") or "semgrep"
        path_s = r.get("path") or ""
        start = (r.get("start") or {}).get("line") or 0
        findings.append({
            "id": f"semgrep-{check}-{path_s}-{start}",
            "scanner": "semgrep",
            "severity": mapped,
            "title": check.split(".")[-1],
            "summary": (extra.get("message") or check)[:500],
            "override_eligible": mapped in ("low", "medium", "unknown"),
            "evidence": {"file": path_s, "line": start, "check_id": check},
        })
else:
    msg = err.read_text(errors="replace") if err.exists() else ""
    if rc not in (0, 1):
        ok = False
        findings.append({
            "id": "semgrep-failed",
            "scanner": "semgrep",
            "severity": "high",
            "title": "Semgrep failed",
            "summary": msg[:500] or f"exit {rc}",
            "override_eligible": False,
            "evidence": {"exit_code": rc},
        })
    else:
        limitations.append("semgrep_no_results")
out.write_text(json.dumps({"scanner": "semgrep", "ok": ok, "findings": findings, "limitations": limitations}, indent=2))
PY
