"""Basic local secret scanner for defensive use on your own code."""
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
PATTERNS = [
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Possible API key/token assignment", re.compile(r"""(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|password)\b\s*[:=]\s*(['"])[^'"]{8,}\2""")),
    ("AWS access key pattern", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token pattern", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
]
TEXT_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".txt", ".go", ".java", ".php", ".rb", ".sh"}

def scan(root: Path):
    findings = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_EXTS and path.name not in {".env", "Dockerfile"}:
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            for label, pattern in PATTERNS:
                if pattern.search(line):
                    # Do not print the potentially sensitive matching line.
                    findings.append((path, number, label))
    return findings

def main():
    if len(sys.argv) != 2:
        print("Usage: python -m app.secret_scan <folder>")
        raise SystemExit(2)
    root = Path(sys.argv[1]).expanduser().resolve()
    if not root.is_dir():
        print("Error: provide a directory you own or are authorized to scan.")
        raise SystemExit(2)
    findings = scan(root)
    if not findings:
        print("No matching patterns found. This does not guarantee that no secrets exist.")
        return
    print(f"Found {len(findings)} possible issue(s):")
    for path, line, label in findings:
        print(f"{path}:{line}: {label} (value hidden)")
    print("Review manually. If a real secret was exposed, revoke/rotate it.")

if __name__ == "__main__":
    main()
