# CyberShield Nepal 🇳🇵

An open-source defensive cybersecurity toolkit with a Nepali-friendly dashboard.

## Features
- Website security-header checker for websites you own or have permission to assess.
- Secret scanner for local source-code files (API keys, passwords, tokens).
- File-integrity baseline and verification using SHA-256.
- Nepali/English security tips.
- JSON report export.

> **Ethical use:** Only assess websites and files you own or have explicit permission to test. This project performs basic defensive checks; it is not a penetration-testing suite and cannot guarantee a system is secure.

## Requirements
- Python 3.10+
- Internet access only for checking an authorized website's HTTP headers.

## Run locally
```bash
python -m venv .venv
# Linux/macOS/Termux:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Open `http://127.0.0.1:8000`.

## CLI: scan your own source code
```bash
python -m app.secret_scan ./your-project
```
The scanner skips common dependency and version-control folders. Review findings manually; false positives are possible.

## CLI: file integrity
Create a baseline:
```bash
python -m app.integrity baseline ./important-folder --output integrity-baseline.json
```
Verify against it later:
```bash
python -m app.integrity verify ./important-folder --baseline integrity-baseline.json
```

## Project status
Starter project / educational prototype. Add tests and review before production deployment. Do not put real secrets in issues, screenshots, logs, or public commits.
