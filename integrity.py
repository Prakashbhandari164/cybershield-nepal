import argparse
import hashlib
import json
from pathlib import Path

def digest(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def collect(root: Path):
    paths = [root] if root.is_file() else (p for p in root.rglob("*") if p.is_file() and not any(x in p.parts for x in {".git", ".venv", "__pycache__"}))
    out = {}
    for p in paths:
        if p.is_file():
            out[str(p.relative_to(root.parent if root.is_file() else root))] = digest(p)
    return dict(sorted(out.items()))

def main():
    parser = argparse.ArgumentParser(description="Create or verify SHA-256 file-integrity baselines.")
    subs = parser.add_subparsers(dest="command", required=True)
    a = subs.add_parser("baseline"); a.add_argument("path", type=Path); a.add_argument("--output", type=Path, default=Path("integrity-baseline.json"))
    b = subs.add_parser("verify"); b.add_argument("path", type=Path); b.add_argument("--baseline", type=Path, required=True)
    args = parser.parse_args()
    if not args.path.exists(): parser.error("path does not exist")
    current = collect(args.path)
    if args.command == "baseline":
        args.output.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        print(f"Saved baseline for {len(current)} file(s) to {args.output}")
        return 0
    expected = json.loads(args.baseline.read_text(encoding="utf-8"))
    changed = sorted(k for k in expected.keys() & current.keys() if expected[k] != current[k])
    missing = sorted(expected.keys() - current.keys())
    added = sorted(current.keys() - expected.keys())
    for label, entries in (("CHANGED", changed), ("MISSING", missing), ("ADDED", added)):
        for name in entries: print(f"{label}: {name}")
    if not (changed or missing or added):
        print("OK: all files match the baseline."); return 0
    print(f"Summary: {len(changed)} changed, {len(missing)} missing, {len(added)} added.")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
