#!/usr/bin/env python3
"""Stage D (light): unzip IPA, inspect Info.plist, entitlements, URLs, embedded binaries."""
from __future__ import annotations

import json
import plistlib
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

URL_RE = re.compile(rb"https?://[^\s\"'<>\\]{4,200}", re.I)
SUSPICIOUS_ATS = ("NSAllowsArbitraryLoads", "NSExceptionAllowsInsecureHTTPLoads")


def find_info_plists(root: Path) -> list[Path]:
    return [p for p in root.rglob("Info.plist") if "Watch" not in p.parts]


def load_plist(path: Path) -> dict:
    try:
        with path.open("rb") as f:
            data = plistlib.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def extract_urls(root: Path, limit: int = 50) -> list[str]:
    found: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file() or path.stat().st_size > 8_000_000:
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".car", ".nib"}:
            continue
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        for m in URL_RE.findall(blob):
            try:
                s = m.decode("utf-8", errors="ignore").rstrip(".,);]")
            except Exception:
                continue
            if "apple.com" in s or "itunes" in s:
                continue
            found.add(s)
            if len(found) >= limit:
                return sorted(found)
    return sorted(found)


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: ipa_light.py <ipa_path> <out_json>", file=sys.stderr)
        return 2
    ipa = Path(sys.argv[1])
    out = Path(sys.argv[2])
    findings: list[dict] = []
    limitations: list[str] = [
        "ipa_light_not_mobsf",
        "no_dynamic_analysis",
        "tvos_rules_best_effort",
    ]
    meta: dict = {"bundle_id": None, "urls": [], "executables": []}

    if not ipa.is_file():
        findings.append(
            {
                "id": "ipa-missing",
                "scanner": "ipa_light",
                "severity": "critical",
                "title": "IPA missing for binary inspection",
                "summary": str(ipa),
                "override_eligible": False,
                "evidence": {},
            }
        )
        out.write_text(json.dumps({"scanner": "ipa_light", "ok": False, "findings": findings, "limitations": limitations, "meta": meta}, indent=2))
        return 1

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        try:
            with zipfile.ZipFile(ipa) as zf:
                # Guard against zip bombs: cap uncompressed listing size
                total = sum(i.file_size for i in zf.infolist())
                if total > 800_000_000:
                    findings.append(
                        {
                            "id": "ipa-too-large",
                            "scanner": "ipa_light",
                            "severity": "high",
                            "title": "IPA uncompressed size exceeds limit",
                            "summary": f"Uncompressed size {total} bytes",
                            "override_eligible": False,
                            "evidence": {"uncompressed_bytes": total},
                        }
                    )
                    out.write_text(json.dumps({"scanner": "ipa_light", "ok": False, "findings": findings, "limitations": limitations, "meta": meta}, indent=2))
                    return 1
                zf.extractall(td_path)
        except zipfile.BadZipFile as exc:
            findings.append(
                {
                    "id": "ipa-bad-zip",
                    "scanner": "ipa_light",
                    "severity": "critical",
                    "title": "IPA is not a valid zip",
                    "summary": str(exc),
                    "override_eligible": False,
                    "evidence": {},
                }
            )
            out.write_text(json.dumps({"scanner": "ipa_light", "ok": False, "findings": findings, "limitations": limitations, "meta": meta}, indent=2))
            return 1

        plists = find_info_plists(td_path)
        if not plists:
            limitations.append("no_info_plist")
        for plist_path in plists[:3]:
            data = load_plist(plist_path)
            bid = data.get("CFBundleIdentifier")
            if bid and not meta["bundle_id"]:
                meta["bundle_id"] = bid
            ats = data.get("NSAppTransportSecurity") or {}
            if isinstance(ats, dict):
                for key in SUSPICIOUS_ATS:
                    if ats.get(key) is True:
                        findings.append(
                            {
                                "id": f"ats-{key}-{bid}",
                                "scanner": "ipa_light",
                                "severity": "medium",
                                "title": f"Insecure ATS setting: {key}",
                                "summary": "App Transport Security allows insecure loads.",
                                "override_eligible": True,
                                "evidence": {"bundle_id": bid, "key": key, "plist": str(plist_path.relative_to(td_path))},
                            }
                        )

        # entitlements from embedded.mobileprovision is binary; look for .xcent / entitlements plists
        for ent in list(td_path.rglob("*.entitlements")) + list(td_path.rglob("archived-expanded-entitlements.xcent")):
            ent_data = load_plist(ent)
            if ent_data.get("get-task-allow") is True:
                findings.append(
                    {
                        "id": f"ent-get-task-allow-{ent.name}",
                        "scanner": "ipa_light",
                        "severity": "medium",
                        "title": "get-task-allow entitlement present",
                        "summary": "Debuggable entitlement found in package.",
                        "override_eligible": True,
                        "evidence": {"path": str(ent.relative_to(td_path))},
                    }
                )

        urls = extract_urls(td_path)
        meta["urls"] = urls
        if len(urls) > 40:
            findings.append(
                {
                    "id": "ipa-many-urls",
                    "scanner": "ipa_light",
                    "severity": "low",
                    "title": "Many embedded network URLs",
                    "summary": f"Extracted {len(urls)} non-Apple URLs from the IPA.",
                    "override_eligible": True,
                    "evidence": {"sample": urls[:15]},
                }
            )

        # list Mach-O-ish executables under Payload
        for app in td_path.glob("Payload/*.app"):
            for exe in app.iterdir():
                if exe.is_file() and not exe.suffix:
                    meta["executables"].append(str(exe.relative_to(td_path)))
                    # try readelf/file
                    try:
                        desc = subprocess.check_output(["file", str(exe)], text=True, timeout=10)
                        if "Mach-O" not in desc and "aarch64" not in desc.lower():
                            limitations.append(f"unexpected_binary_type:{exe.name}")
                    except (subprocess.SubprocessError, FileNotFoundError):
                        limitations.append("file_cmd_unavailable")

    out.write_text(
        json.dumps(
            {
                "scanner": "ipa_light",
                "ok": not any(f["severity"] == "critical" for f in findings),
                "findings": findings,
                "limitations": sorted(set(limitations)),
                "meta": meta,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
