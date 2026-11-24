#!/usr/bin/env python3
"""Stage C: parse Package.resolved / Podfile.lock and query api.osv.dev (SwiftURL / CocoaPods-ish)."""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

OSV_URL = "https://api.osv.dev/v1/querybatch"
CHUNK = 80


def severity_from_osv(vuln: dict) -> str:
    sev = (vuln.get("severity") or [])
    if isinstance(sev, list) and sev:
        first = sev[0]
        if isinstance(first, dict):
            score = first.get("score")
            if isinstance(score, str) and score.upper().startswith("CVSS"):
                # fall through to database_specific
                pass
            try:
                s = float(score)
                if s >= 9:
                    return "critical"
                if s >= 7:
                    return "high"
                if s >= 4:
                    return "medium"
                if s > 0:
                    return "low"
            except (TypeError, ValueError):
                pass
    db = vuln.get("database_specific") or {}
    raw = (db.get("severity") or "").lower()
    if raw in ("critical", "high", "medium", "moderate", "low"):
        return "medium" if raw == "moderate" else raw
    return "unknown"


def parse_package_resolved(text: str) -> list[tuple[str, str, str]]:
    data = json.loads(text)
    pins = data.get("pins") or []
    out: list[tuple[str, str, str]] = []
    for pin in pins:
        ident = pin.get("identity") or (pin.get("package") or {}).get("identity") or pin.get("location") or ""
        state = pin.get("state") or {}
        version = state.get("version") or pin.get("version") or ""
        if not ident or not version:
            continue
        name = ident.rsplit("/", 1)[-1]
        out.append((name, version, "SwiftURL"))
    return out


def parse_podfile_lock(text: str) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    in_pods = False
    for line in text.splitlines():
        if line.startswith("PODS:"):
            in_pods = True
            continue
        if in_pods and line and not line.startswith(" "):
            break
        if not in_pods:
            continue
        m = re.match(r"\s+-\s+([^\s(]+)\s+\(([^)]+)\)", line)
        if not m:
            continue
        name = m.group(1).split("/")[0]
        version = m.group(2).strip()
        out.append((name, version, "SwiftURL"))
    return out


def query_osv(packages: list[tuple[str, str, str]]) -> list[dict]:
    findings: list[dict] = []
    for i in range(0, len(packages), CHUNK):
        chunk = packages[i : i + CHUNK]
        queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for n, v, e in chunk]
        body = json.dumps({"queries": queries}).encode()
        req = urllib.request.Request(
            OSV_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            return [
                {
                    "id": "osv-spm-query-failed",
                    "scanner": "osv_custom_spm",
                    "severity": "high",
                    "title": "OSV query failed",
                    "summary": f"Dependency scan incomplete: {exc}",
                    "override_eligible": False,
                    "evidence": {"error": str(exc)},
                }
            ]
        results = data.get("results") or []
        for pkg, res in zip(chunk, results):
            name, version, eco = pkg
            for vuln in res.get("vulns") or []:
                vid = vuln.get("id") or "unknown"
                sev = severity_from_osv(vuln)
                findings.append(
                    {
                        "id": f"osv-{vid}-{name}@{version}",
                        "scanner": "osv_custom_spm",
                        "severity": sev,
                        "title": f"{name}@{version} — {vid}",
                        "summary": (vuln.get("summary") or vuln.get("details") or "Known vulnerability")[:500],
                        "override_eligible": sev in ("low", "medium", "unknown"),
                        "evidence": {
                            "package": name,
                            "version": version,
                            "ecosystem": eco,
                            "advisory_id": vid,
                        },
                    }
                )
    return findings


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: osv_custom_spm.py <source_dir> <out_json>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    out = Path(sys.argv[2])
    packages: list[tuple[str, str, str]] = []
    lockfiles: list[str] = []
    limitations: list[str] = []

    for path in root.rglob("Package.resolved"):
        lockfiles.append(str(path.relative_to(root)))
        packages.extend(parse_package_resolved(path.read_text(errors="replace")))
    for path in root.rglob("Podfile.lock"):
        lockfiles.append(str(path.relative_to(root)))
        packages.extend(parse_podfile_lock(path.read_text(errors="replace")))

    # dedupe
    seen: set[tuple[str, str, str]] = set()
    uniq: list[tuple[str, str, str]] = []
    for p in packages:
        if p not in seen:
            seen.add(p)
            uniq.append(p)

    findings: list[dict] = []
    if not uniq:
        limitations.append("no_spm_or_cocoapods_lockfiles")
    else:
        findings = query_osv(uniq)

    result = {
        "scanner": "osv_custom_spm",
        "ok": not any(f.get("id") == "osv-spm-query-failed" for f in findings),
        "findings": findings,
        "limitations": limitations,
        "lockfiles": lockfiles,
        "packages_scanned": len(uniq),
    }
    out.write_text(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
