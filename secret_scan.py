import argparse
import re
from pathlib import Path

PATTERNS = {
    "possible_private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "possible_api_key_assignment": re.compile(r"""(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"]{8,}['"]"""),
    "possible_password_assignment": re.compile(r"""(?i)\bpassword\s*[:=]\s*['"][^'"]{4,}['"]"""),
}
SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__"}
SUFFIXES = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".env", ".ini", ".cfg", ".txt", ".md", ".sh"}

def scan(root: Path):
    paths = [root] if root.is_file() else (p for p in root.rglob("*") if p.is_file() and not any(x in SKIP for x in p.parts))
    found = []
    for path in paths:
        if path.suffix.lower() not in SUFFIXES and path.name != ".env":
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            for name, pattern in PATTERNS.items():
                if pattern.search(line):
                    found.append((path, n, name))
    return found

def main():
    parser = argparse.ArgumentParser(description="Find likely hard-coded secrets in local text files.")
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    if not args.path.exists():
        parser.error("path does not exist")
    found = scan(args.path)
    for path, line, name in found:
        print(f"{path}:{line}: {name} (secret value hidden)")
    if not found:
        print("No matching patterns found; this does not prove the absence of secrets.")
    return 1 if found else 0

if __name__ == "__main__":
    raise SystemExit(main())
