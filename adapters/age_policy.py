#!/usr/bin/env python3
"""Stage A soft signal: 14-day release age floor."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

MINIMUM_AGE_DAYS = 14


def parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    raw = raw.strip()
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw).astimezone(timezone.utc)
    except ValueError:
        return None


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: age_policy.py <published_at_iso_or_empty> <out_json>", file=sys.stderr)
        return 2
    published_raw = sys.argv[1] if sys.argv[1] not in ("", "-", "null") else None
    out = Path(sys.argv[2])
    now = datetime.now(timezone.utc)
    published = parse_ts(published_raw)
    findings = []
    limitations = []
    if published is None:
        status = "unknown"
        age_days = None
        findings.append(
            {
                "id": "age-unknown",
                "scanner": "age_policy",
                "severity": "medium",
                "title": "Release publish date unknown",
                "summary": "Cannot verify the 14-day age floor; manual review recommended.",
                "override_eligible": True,
                "evidence": {"published_at": published_raw},
            }
        )
    else:
        age_days = max(0, int((now - published).total_seconds() // 86400))
        if age_days >= MINIMUM_AGE_DAYS:
            status = "eligible"
        else:
            status = "too_new"
            findings.append(
                {
                    "id": "age-too-new",
                    "scanner": "age_policy",
                    "severity": "medium",
                    "title": f"Release is only {age_days} day(s) old",
                    "summary": f"Auto/latest installs wait {MINIMUM_AGE_DAYS}+ days; pinned tags may Proceed after review.",
                    "override_eligible": True,
                    "evidence": {
                        "age_days": age_days,
                        "required_days": MINIMUM_AGE_DAYS,
                        "published_at": published.isoformat(),
                    },
                }
            )

    result = {
        "scanner": "age_policy",
        "ok": True,
        "findings": findings,
        "limitations": limitations,
        "age": {
            "status": status,
            "age_days": age_days,
            "required_days": MINIMUM_AGE_DAYS,
        },
    }
    out.write_text(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
