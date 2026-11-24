#!/usr/bin/env python3
"""Merge adapter JSON outputs into SecurityReport schema v1 and derive assessment_status."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
NON_OVERRIDE_SCANNERS = {"identity", "malware"}


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def derive_assessment(findings: list[dict], identity_ok: bool, incomplete: bool) -> str:
    if not identity_ok:
        return "blocked"
    if incomplete:
        return "incomplete"
    elevated = [f for f in findings if SEVERITY_RANK.get(f.get("severity", "unknown"), 0) >= 2]
    blocking = [
        f
        for f in findings
        if (not f.get("override_eligible", True))
        or f.get("scanner") in NON_OVERRIDE_SCANNERS
        and SEVERITY_RANK.get(f.get("severity", "unknown"), 0) >= 3
    ]
    if any(f.get("scanner") == "identity" and not f.get("override_eligible", True) for f in findings):
        return "blocked"
    if blocking and any(SEVERITY_RANK.get(f.get("severity", "unknown"), 0) >= 3 for f in blocking):
        # critical non-override
        if any(f.get("scanner") == "identity" for f in blocking):
            return "blocked"
    if elevated:
        return "review_required"
    return "checks_passed"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--artifact-json", required=True)
    ap.add_argument("--adapter-dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    policy = load_json(Path(args.policy))
    artifact = load_json(Path(args.artifact_json))
    adapter_dir = Path(args.adapter_dir)

    findings: list[dict] = []
    limitations: list[str] = []
    scanners_ran: list[str] = []
    age = None
    identity_ok = True
    incomplete = False

    for path in sorted(adapter_dir.glob("*.json")):
        data = load_json(path)
        if not data:
            continue
        scanner = data.get("scanner") or path.stem
        scanners_ran.append(scanner)
        if data.get("ok") is False and scanner == "identity":
            identity_ok = False
        if data.get("ok") is False and scanner != "identity":
            incomplete = True
        findings.extend(data.get("findings") or [])
        limitations.extend(data.get("limitations") or [])
        if data.get("age"):
            age = data["age"]

    # Deduplicate findings by id
    by_id = {}
    for f in findings:
        by_id[f.get("id") or json.dumps(f, sort_keys=True)] = f
    findings = list(by_id.values())

    assessment = derive_assessment(findings, identity_ok=identity_ok, incomplete=incomplete)
    report = {
        "schema_version": "1",
        "job_id": args.job_id,
        "artifact": artifact,
        "policy_version": policy.get("policy_version", "v1"),
        "scanner_bundle_version": policy.get("scanner_bundle_version", "1.0.0"),
        "scanners_ran": scanners_ran,
        "assessment_status": assessment,
        "findings": findings,
        "limitations": sorted(set(limitations)),
        "age": age,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    out = Path(args.out)
    raw = json.dumps(report, indent=2, sort_keys=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    digest = hashlib.sha256(raw.encode()).hexdigest()
    out.with_suffix(".sha256").write_text(digest + "\n")
    print(f"assessment_status={assessment}")
    print(f"report_sha256={digest}")


if __name__ == "__main__":
    main()
