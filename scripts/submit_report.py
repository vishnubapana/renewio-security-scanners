#!/usr/bin/env python3
"""POST normalized report to Supabase submit-report Edge Function with HMAC auth."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: submit_report.py <report_json> <callback_url>", file=sys.stderr)
        return 2
    report_path = Path(sys.argv[1])
    callback = sys.argv[2]
    secret = os.environ.get("SUBMIT_REPORT_HMAC_SECRET", "")
    if not secret:
        print("SUBMIT_REPORT_HMAC_SECRET required", file=sys.stderr)
        return 1
    body = report_path.read_bytes()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        callback,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Renewio-Signature": sig,
            "X-Renewio-Job-Id": json.loads(body.decode()).get("job_id", ""),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            print(resp.read().decode())
        return 0
    except urllib.error.HTTPError as exc:
        print(exc.read().decode(), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
