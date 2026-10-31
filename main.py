from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse
from urllib.parse import urlparse
import requests

app = FastAPI(title="CyberShield Nepal", version="0.1.0")

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps reduce certain content-injection risks.",
    "Strict-Transport-Security": "Tells browsers to prefer HTTPS after a secure visit.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps reduce clickjacking risks in supporting browsers.",
    "Referrer-Policy": "Controls how much referrer information is shared.",
    "Permissions-Policy": "Restricts access to browser features."
}

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberShield Nepal</title>
<style>
:root{color-scheme:dark}body{font-family:system-ui,sans-serif;background:#0b1220;color:#e5eefb;margin:0}
main{max-width:900px;margin:auto;padding:28px}header,.card{background:#131f33;border:1px solid #263750;border-radius:16px;padding:22px;margin:16px 0}
h1{margin:0;color:#78e0b2}p,li{line-height:1.6;color:#c5d2e5}input{box-sizing:border-box;width:100%;padding:12px;border-radius:8px;border:1px solid #405574;background:#0b1220;color:white;margin:8px 0}
button{background:#78e0b2;border:0;padding:12px 16px;border-radius:8px;font-weight:700;cursor:pointer}
small{color:#9fb0c8}.badge{color:#78e0b2;font-weight:bold}a{color:#78e0b2}
</style></head><body><main>
<header><h1>🛡️ CyberShield Nepal</h1><p>Defensive security tools • नेपालीमै साइबर सुरक्षा सिकौँ</p>
<small>Only check websites you own or have explicit permission to assess.</small></header>
<section class="card"><h2>Website Security Headers</h2>
<form method="post" action="/check"><label for="url">Authorized website URL</label>
<input id="url" name="url" placeholder="https://example.com" required>
<button type="submit">Check headers</button></form></section>
<section class="card"><h2>Quick security checklist / सुरक्षा सुझाव</h2><ul>
<li>Enable multi-factor authentication on important accounts.</li>
<li>Never commit API keys, passwords, or private tokens to GitHub.</li>
<li>Use HTTPS and keep software and dependencies updated.</li>
<li>Keep offline or versioned backups of important files.</li>
<li>Use a password manager and unique passwords.</li>
</ul></section>
<section class="card"><h2>Command-line tools</h2>
<p>Secret scan: <code>python -m app.secret_scan ./your-project</code></p>
<p>File integrity: see the README for baseline and verification commands.</p></section>
<footer><small>Educational prototype — basic checks do not prove a website is secure.</small></footer>
</main></body></html>"""

@app.get("/", response_class=HTMLResponse)
def home():
    return PAGE

@app.post("/check", response_class=HTMLResponse)
def check_website(url: str = Form(...)):
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return HTMLResponse("<h2>Please enter a valid HTTPS URL.</h2><p>HTTPS-only checks reduce accidental unsafe requests.</p><a href='/'>Back</a>", status_code=400)
    # Prevent obvious local/private network targets; this is a starter safeguard, not a complete SSRF defense.
    host = (parsed.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return HTMLResponse("<h2>Local targets are not allowed by this demo.</h2><a href='/'>Back</a>", status_code=400)
    try:
        response = requests.get(url, timeout=8, allow_redirects=False, headers={"User-Agent": "CyberShieldNepal/0.1"})
        rows = []
        score = 0
        for header, purpose in SECURITY_HEADERS.items():
            present = header in response.headers
            score += int(present)
            rows.append(f"<tr><td>{header}</td><td>{'Present' if present else 'Missing'}</td><td>{purpose}</td></tr>")
        body = f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>
<style>body{{font-family:system-ui;background:#0b1220;color:#e5eefb;padding:24px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:10px;border:1px solid #405574;text-align:left}}a{{color:#78e0b2}}</style></head><body>
<h1>Security Header Report</h1><p>Target: {parsed.hostname}</p><p>HTTP status: {response.status_code}</p>
<p>Headers present: {score}/{len(SECURITY_HEADERS)} (basic indicator only)</p>
<table><tr><th>Header</th><th>Status</th><th>Purpose</th></tr>{''.join(rows)}</table>
<p>Missing headers are suggestions for review, not proof of vulnerability. Some headers may not apply to every site.</p><a href='/'>Back</a></body></html>"""
        return HTMLResponse(body)
    except requests.RequestException:
        return HTMLResponse("<h2>Could not reach the site.</h2><p>Check the URL and try again. No intrusive testing was performed.</p><a href='/'>Back</a>", status_code=502)

@app.get("/health")
def health():
    return {"status": "ok", "project": "CyberShield Nepal", "version": "0.1.0"}

@app.get("/api/tips")
def tips():
    return JSONResponse({"tips": [
        {"language": "ne", "text": "आफ्नो API key वा password सार्वजनिक GitHub repository मा नराख्नुहोस्।"},
        {"language": "ne", "text": "महत्त्वपूर्ण खातामा Multi-Factor Authentication खोल्नुहोस्।"},
        {"language": "en", "text": "Keep dependencies updated and review security advisories."}
    ]})
