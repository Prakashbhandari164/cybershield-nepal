"""SHA-256 file integrity baseline tool."""
import argparse
import hashlib
import json
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def collect(root: Path):
    data = {}
    for path in root.rglob("*"):
        if path.is_file() and not any(part in SKIP_DIRS for part in path.parts):
            try:
                data[str(path.relative_to(root))] = digest(path)
            except OSError:
                pass
    return data

def main():
    parser = argparse.ArgumentParser(description="Create or verify a SHA-256 file integrity baseline.")
    parser.add_argument("mode", choices=["baseline", "verify"])
    parser.add_argument("folder", type=Path)
    parser.add_argument("--output", default="integrity-baseline.json")
    parser.add_argument("--baseline", default="integrity-baseline.json")
    args = parser.parse_args()
    root = args.folder.expanduser().resolve()
    if not root.is_dir():
        parser.error("folder must exist")
    if args.mode == "baseline":
        data = collect(root)
        Path(args.output).write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"Saved baseline for {len(data)} files to {args.output}")
        print("Keep the baseline in a trusted location separate from the monitored folder.")
        return
    baseline_path = Path(args.baseline)
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    current = collect(root)
    changed = sorted(k for k in baseline.keys() & current.keys() if baseline[k] != current[k])
    missing = sorted(baseline.keys() - current.keys())
    added = sorted(current.keys() - baseline.keys())
    print(f"Changed: {len(changed)} | Missing: {len(missing)} | Added: {len(added)}")
    for label, paths in (("CHANGED", changed), ("MISSING", missing), ("ADDED", added)):
        for path in paths:
            print(f"{label}: {path}")

if __name__ == "__main__":
    main()
