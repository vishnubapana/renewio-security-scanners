#!/usr/bin/env python3
"""Phase 5 stub: compare current source tree to a previous assessed tag."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    out = Path(sys.argv[-1]) if len(sys.argv) > 1 else Path("release_diff.json")
    result = {
        "scanner": "release_diff",
        "ok": True,
        "findings": [],
        "limitations": ["release_diff_not_enabled_in_policy_v1"],
        "enabled": False,
    }
    out.write_text(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
