#!/usr/bin/env python3
"""Phase 5 stub: VirusTotal hash lookup only (disabled; ToS / rate limits)."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    out = Path(sys.argv[-1]) if len(sys.argv) > 1 else Path("virustotal.json")
    out.write_text(
        json.dumps(
            {
                "scanner": "virustotal",
                "ok": True,
                "findings": [],
                "limitations": [
                    "virustotal_disabled",
                    "unknown_or_zero_detections_is_not_safe",
                    "public_api_non_commercial_rate_limited",
                ],
                "enabled": False,
                "reputation": "not_queried",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
