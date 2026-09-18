#!/usr/bin/env python3
"""Synchronize the canonical cipher engine with every Python/browser copy."""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "encripter.py"
PYTHON_MIRRORS = (
    ROOT / "ars_occultandarum_litterarum" / "core.py",
    ROOT / "apk" / "v1" / "encripter.py",
)
WEB_APP = ROOT / "index.html"
MANIFEST = ROOT / "ciphers_manifest.json"
WEB_ENGINE_PATTERN = re.compile(
    rb'(?P<prefix>const PY_B64 = ")(?P<payload>[A-Za-z0-9+/=]+)(?P<suffix>";)'
)


def expected_web_app(current: bytes, source: bytes) -> bytes:
    """Return the web app with its embedded Python engine replaced."""
    encoded = base64.b64encode(source)
    updated, replacements = WEB_ENGINE_PATTERN.subn(
        lambda match: match.group("prefix") + encoded + match.group("suffix"),
        current,
        count=1,
    )
    if replacements != 1:
        raise RuntimeError("index.html must contain exactly one PY_B64 engine payload")
    return updated


def expected_manifest() -> bytes:
    """Build a language-neutral catalogue from the canonical registry."""
    module_name = "_cipher_sync_source"
    spec = importlib.util.spec_from_file_location(module_name, SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SOURCE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        entries = [
            {
                "name": entry.name,
                "parameters": [
                    {
                        "name": parameter.name,
                        "label": parameter.label,
                        "default": str(parameter.default),
                        "tip": parameter.tip,
                    }
                    for parameter in entry.params
                ],
            }
            for entry in module.get_registry()
        ]
    finally:
        sys.modules.pop(module_name, None)
    return (json.dumps(entries, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def synchronize(check: bool) -> list[str]:
    source = SOURCE.read_bytes()
    changed: list[str] = []

    for mirror in PYTHON_MIRRORS:
        if mirror.read_bytes() != source:
            changed.append(str(mirror.relative_to(ROOT)))
            if not check:
                mirror.write_bytes(source)

    web_current = WEB_APP.read_bytes()
    web_expected = expected_web_app(web_current, source)
    if web_current != web_expected:
        changed.append(str(WEB_APP.relative_to(ROOT)))
        if not check:
            WEB_APP.write_bytes(web_expected)

    manifest_expected = expected_manifest()
    manifest_current = MANIFEST.read_bytes() if MANIFEST.exists() else b""
    if manifest_current != manifest_expected:
        changed.append(str(MANIFEST.relative_to(ROOT)))
        if not check:
            MANIFEST.write_bytes(manifest_expected)

    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report stale copies without modifying files",
    )
    args = parser.parse_args(argv)

    try:
        changed = synchronize(args.check)
    except (OSError, RuntimeError) as error:
        print(f"sync error: {error}", file=sys.stderr)
        return 2

    if args.check and changed:
        print("Cipher engine copies are out of sync:", file=sys.stderr)
        for path in changed:
            print(f"  - {path}", file=sys.stderr)
        print("Run: python scripts/sync_cipher_engines.py", file=sys.stderr)
        return 1

    if changed:
        print("Synchronized: " + ", ".join(changed))
    else:
        print("All cipher engine copies are synchronized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
