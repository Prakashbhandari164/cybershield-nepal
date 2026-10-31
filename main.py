import ipaddress
import socket
from urllib.parse import urlparse
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

app = FastAPI(title="CyberShield Nepal", version="1.0.0")
HEADERS = {
    "content-security-policy": "Helps reduce certain content-injection risks.",
    "strict-transport-security": "Encourages browsers to use HTTPS.",
    "x-content-type-options": "Helps prevent MIME-type sniffing.",
    "referrer-policy": "Controls referrer information.",
    "permissions-policy": "Restricts browser features.",
}
TIPS = [
    {"title": "Enable MFA", "detail": "Use multi-factor authentication on important accounts."},
    {"title": "Protect secrets", "detail": "Never commit API keys, passwords, or tokens."},
    {"title": "Update software", "detail": "Keep your operating system and apps patched."},
    {"title": "Back up files", "detail": "Keep a separate backup and test restoration."},
]

def validate_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Enter a complete HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs with embedded credentials are not allowed.")
    host = parsed.hostname.rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Localhost is not allowed.")
    try:
        answers = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    except OSError:
        raise ValueError("Hostname could not be resolved.") from None
    if not answers or any(not ipaddress.ip_address(a[4][0]).is_global for a in answers):
        raise ValueError("Only public internet hosts are allowed.")
    return url.strip()

async def check_headers(url: str) -> dict:
    url = validate_url(url)
    async with httpx.AsyncClient(timeout=httpx.Timeout(8, connect=4),
                                 follow_redirects=False, trust_env=False) as client:
        response = await client.get(url, headers={"User-Agent": "CyberShieldNepal/1.0"})
    h = {k.lower(): v for k, v in response.headers.items()}
    return {"url": url, "status_code": response.status_code,
            "headers": [{"name": k, "present": k in h, "value": h.get(k, "")[:250],
                         "purpose": purpose} for k, purpose in HEADERS.items()],
            "note": "Missing headers are not proof of a vulnerability."}

@app.get("/health")
def health():
    return {"status": "ok", "project": "CyberShield Nepal"}

@app.get("/api/tips")
def tips():
    return {"tips": TIPS}

@app.post("/api/check-headers")
async def api_check_headers(url: str):
    try:
        return await check_headers(url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="HTTPS request could not be completed.") from None

@app.get("/", response_class=HTMLResponse)
def home():
    tips_html = "".join(f"<li><b>{x['title']}</b><br>{x['detail']}</li>" for x in TIPS)
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberShield Nepal</title><style>
body{{margin:0;background:#081321;color:#e8f1ff;font:16px system-ui}}
main{{max-width:900px;margin:auto;padding:28px 16px}}h1{{font-size:2.8rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}}
.card{{background:#122238;border:1px solid #29415e;border-radius:15px;padding:20px}}
input{{width:95%;padding:12px;background:#081321;color:white;border:1px solid #456;border-radius:8px}}
button{{margin-top:8px;padding:11px 15px;border:0;border-radius:8px;background:#45e0a8;font-weight:bold}}
a{{color:#45e0a8}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;color:#b7f5dc}}
.muted{{color:#a8b7cc}}</style></head><body><main>
<p style="color:#45e0a8">DEFENSIVE CYBERSECURITY • NEPAL</p><h1>🛡️ CyberShield Nepal</h1>
<p class="muted">Tools for learning and protecting systems you own or have permission to assess.</p>
<div class="grid">
<section class="card"><h2>🌐 Security Header Check</h2><form id="f"><input id="url" type="url" placeholder="https://example.com" required><br><button>Check headers</button></form><p class="muted">HTTPS only; private hosts and redirects are blocked.</p><pre id="out"></pre></section>
<section class="card"><h2>🔐 Security Tips</h2><ul>{tips_html}</ul></section>
<section class="card"><h2>🧰 Local Tools</h2><pre>python -m app.secret_scan ./project</pre><pre>python -m app.integrity baseline ./project --output baseline.json</pre><pre>python -m app.integrity verify ./project --baseline baseline.json</pre></section>
<section class="card"><h2>📚 API & Tests</h2><p><a href="/docs">Open API docs</a></p><p>GET /health · GET /api/tips</p><p>Run pytest -q</p></section>
</div><p class="muted">Informational starter project, not a full security audit.</p></main>
<script>document.getElementById('f').addEventListener('submit',async e=>{{e.preventDefault();let o=document.getElementById('out');o.textContent='Checking…';try{{let r=await fetch('/api/check-headers?url='+encodeURIComponent(document.getElementById('url').value),{{method:'POST'}});let d=await r.json();o.textContent=JSON.stringify(d,null,2)}}catch(x){{o.textContent='Request failed'}}}});</script>
</body></html>"""
