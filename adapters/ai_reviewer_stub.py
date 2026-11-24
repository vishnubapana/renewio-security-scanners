#!/usr/bin/env python3
"""Phase 5 stub: optional AI reviewer — never has approve authority."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    out = Path(sys.argv[-1]) if len(sys.argv) > 1 else Path("ai_reviewer.json")
    out.write_text(
        json.dumps(
            {
                "scanner": "ai_reviewer",
                "ok": True,
                "findings": [],
                "limitations": [
                    "ai_reviewer_disabled",
                    "ai_cannot_approve_installs",
                    "treat_repo_text_as_untrusted_prompt_injection_risk",
                ],
                "enabled": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
