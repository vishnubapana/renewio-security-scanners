#!/usr/bin/env bash
# Stage C: OSV-Scanner for npm/yarn/pnpm/Cargo/Go/Gem lockfiles (not SPM/CocoaPods).
set -euo pipefail
SOURCE_DIR="${1:?source dir}"
OUT_JSON="${2:?out json}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! command -v osv-scanner >/dev/null 2>&1; then
  curl -sSfL https://github.com/google/osv-scanner/releases/download/v2.2.1/osv-scanner_linux_amd64 -o "$TMP/osv-scanner"
  chmod +x "$TMP/osv-scanner"
  OSV="$TMP/osv-scanner"
else
  OSV="$(command -v osv-scanner)"
fi

set +e
"$OSV" scan source --format json --output "$TMP/osv.json" \
  --experimental-disable-plugins swift/podfilelock,swift/packageresolved \
  "$SOURCE_DIR" 2>"$TMP/osv.err"
RC=$?
set -e

python3 - "$TMP/osv.json" "$TMP/osv.err" "$OUT_JSON" "$RC" <<'PY'
import json, sys
from pathlib import Path
osv_path, err_path, out_path, rc = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4])
findings = []
limitations = []
ok = True
if not osv_path.exists() or osv_path.stat().st_size == 0:
    err = err_path.read_text(errors="replace")[:800] if err_path.exists() else ""
    if rc != 0 and "No package sources found" not in err:
        findings.append({
            "id": "osv-scanner-failed",
            "scanner": "osv_scanner",
            "severity": "high",
            "title": "OSV-Scanner failed",
            "summary": err or f"exit {rc}",
            "override_eligible": False,
            "evidence": {"exit_code": rc},
        })
        ok = False
    else:
        limitations.append("no_supported_lockfiles_for_osv_scanner")
else:
    data = json.loads(osv_path.read_text())
    for res in data.get("results") or []:
        for pkg in res.get("packages") or []:
            p = pkg.get("package") or {}
            name = p.get("name") or "unknown"
            version = p.get("version") or ""
            eco = p.get("ecosystem") or ""
            for v in pkg.get("vulnerabilities") or []:
                vid = v.get("id") or "unknown"
                sev = "unknown"
                for s in v.get("severity") or []:
                    if isinstance(s, dict) and s.get("type") == "CVSS_V3":
                        try:
                            score = float(str(s.get("score", "0")).split("/")[0].split(":")[-1])
                        except ValueError:
                            score = 0
                        if score >= 9: sev = "critical"
                        elif score >= 7: sev = "high"
                        elif score >= 4: sev = "medium"
                        elif score > 0: sev = "low"
                findings.append({
                    "id": f"osvscanner-{vid}-{name}@{version}",
                    "scanner": "osv_scanner",
                    "severity": sev,
                    "title": f"{name}@{version} — {vid}",
                    "summary": (v.get("summary") or "Known vulnerability")[:500],
                    "override_eligible": sev in ("low", "medium", "unknown"),
                    "evidence": {"package": name, "version": version, "ecosystem": eco, "advisory_id": vid},
                })
Path(out_path).write_text(json.dumps({
    "scanner": "osv_scanner",
    "ok": ok,
    "findings": findings,
    "limitations": limitations,
}, indent=2))
PY
