# CyberShield Nepal 🛡️
A beginner-friendly defensive cybersecurity toolkit. Use only on systems and websites you own or are authorized to assess.

## Features
- FastAPI security dashboard
- HTTPS security-header checker (public hosts only; redirects not followed)
- Local secret-pattern scanner
- SHA-256 file-integrity baseline and verification
- Automated tests and GitHub Actions workflow

## Run
Python 3.10+ recommended.
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Open http://127.0.0.1:8000

## CLI
```bash
python -m app.secret_scan ./your-project
python -m app.integrity baseline ./your-project --output integrity-baseline.json
python -m app.integrity verify ./your-project --baseline integrity-baseline.json
```

## Tests
```bash
pytest -q
```
The scanner can have false positives and does not guarantee that all secrets are found. A missing security header is not proof of a vulnerability.
