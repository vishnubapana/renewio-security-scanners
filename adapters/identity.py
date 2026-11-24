#!/usr/bin/env python3
"""Stage A: verify IPA SHA-256 matches expected hash; record asset metadata."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: identity.py <ipa_path> <expected_sha256> <out_json>", file=sys.stderr)
        return 2
    ipa = Path(sys.argv[1])
    expected = sys.argv[2].strip().lower()
    out = Path(sys.argv[3])
    if not ipa.is_file():
        result = {
            "scanner": "identity",
            "ok": False,
            "findings": [
                {
                    "id": "identity-missing-ipa",
                    "scanner": "identity",
                    "severity": "critical",
                    "title": "IPA file missing",
                    "summary": f"Expected IPA at {ipa}",
                    "override_eligible": False,
                    "evidence": {"path": str(ipa)},
                }
            ],
            "limitations": [],
            "ipa_sha256": None,
        }
        out.write_text(json.dumps(result, indent=2))
        return 1

    actual = sha256_file(ipa)
    findings = []
    ok = actual == expected
    if not ok:
        findings.append(
            {
                "id": "identity-hash-mismatch",
                "scanner": "identity",
                "severity": "critical",
                "title": "IPA SHA-256 mismatch",
                "summary": "Downloaded IPA does not match the hash the client requested to scan.",
                "override_eligible": False,
                "evidence": {"expected": expected, "actual": actual},
            }
        )
    result = {
        "scanner": "identity",
        "ok": ok,
        "findings": findings,
        "limitations": [],
        "ipa_sha256": actual,
    }
    out.write_text(json.dumps(result, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
