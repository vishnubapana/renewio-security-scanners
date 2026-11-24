#!/usr/bin/env bash
# Stage B: secret detection via Gitleaks.
set -euo pipefail
SOURCE_DIR="${1:?source dir}"
OUT_JSON="${2:?out json}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! command -v gitleaks >/dev/null 2>&1; then
  curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz | tar -xz -C "$TMP" gitleaks
  GL="$TMP/gitleaks"
else
  GL="$(command -v gitleaks)"
fi

set +e
"$GL" detect --source "$SOURCE_DIR" --no-git --report-format json --report-path "$TMP/gl.json" --exit-code 0 >/dev/null 2>"$TMP/gl.err"
RC=$?
set -e

python3 - "$TMP/gl.json" "$TMP/gl.err" "$OUT_JSON" "$RC" <<'PY'
import json, sys
from pathlib import Path
path, err, out, rc = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4])
findings = []
ok = True
if path.exists() and path.stat().st_size:
    data = json.loads(path.read_text() or "[]")
    if isinstance(data, dict):
        data = data.get("Findings") or data.get("findings") or []
    for item in data:
        rule = item.get("RuleID") or item.get("Description") or "secret"
        file = item.get("File") or item.get("file") or ""
        line = item.get("StartLine") or item.get("line") or 0
        findings.append({
            "id": f"gitleaks-{rule}-{file}-{line}",
            "scanner": "gitleaks",
            "severity": "high",
            "title": f"Possible secret: {rule}",
            "summary": f"Gitleaks matched {rule} in {file}:{line}",
            "override_eligible": True,
            "evidence": {"file": file, "line": line, "rule": rule},
        })
elif rc not in (0, 1):
    ok = False
    findings.append({
        "id": "gitleaks-failed",
        "scanner": "gitleaks",
        "severity": "high",
        "title": "Gitleaks failed",
        "summary": (err.read_text(errors="replace") if err.exists() else "")[:500] or f"exit {rc}",
        "override_eligible": False,
        "evidence": {"exit_code": rc},
    })
out.write_text(json.dumps({"scanner": "gitleaks", "ok": ok, "findings": findings, "limitations": []}, indent=2))
PY
