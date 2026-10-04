#!/usr/bin/env python3
"""Build a dependency notice bundle from `go list -deps -json ./cmd/vojeto` on stdin.

Exit nonzero when any module has no discoverable license. This is a mechanical
inventory gate, not a replacement for reviewing license compatibility or notices.
"""
import argparse
import json
from pathlib import Path
import sys


def documents(raw):
    decoder = json.JSONDecoder()
    while raw.strip():
        raw = raw.lstrip()
        value, end = decoder.raw_decode(raw)
        yield value
        raw = raw[end:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--goroot", required=True, type=Path)
    args = parser.parse_args()
    entries = []
    missing = []
    seen = set()
    for package in documents(sys.stdin.read()):
        module = package.get("Module")
        if module is None or module.get("Main") or module["Path"] in seen:
            continue
        seen.add(module["Path"])
        source = module.get("Replace", module)
        directory = Path(source["Dir"])
        names = sorted(p for p in directory.iterdir() if p.is_file() and p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS")))
        licensed = any(p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING")) for p in names)
        if not licensed:
            missing.append(f'{module["Path"]}@{module.get("Version", "local")}')
        entries.append((module["Path"], module.get("Version", "local"), names))
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = []
    for index, (module, version, names) in enumerate(entries):
        for name in names:
            target = f"{index:03d}-{name.name}"
            (args.output / target).write_bytes(name.read_bytes())
            manifest.append({"module": module, "version": version, "notice": target})
    (args.output / "GO_LICENSE").write_bytes((args.goroot / "LICENSE").read_bytes())
    (args.output / "inventory.json").write_text(json.dumps({"notices": manifest, "missing_license": missing}, indent=2) + "\n")
    if missing:
        print("Missing dependency license: " + ", ".join(missing), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
