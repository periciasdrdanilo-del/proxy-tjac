import os, base64, tempfile
from flask import Flask, request, jsonify
import requests
import urllib3
urllib3.disable_warnings()

def fix_redirect(x, encoding='utf-8'):
    if isinstance(x, bytes):
        try: return x.decode(encoding)
        except Exception: return x.decode('latin-1')
    return x
requests.models.to_native_string = fix_redirect

app = Flask(__name__)
TOKEN = os.environ.get("PROXY_TOKEN", "")
CERT_B64 = os.environ.get("EPROC_CERT_B64", "")
_cert_path = None

def cert_path():
    global _cert_path
    if _cert_path is None and CERT_B64:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        f.write(base64.b64decode(CERT_B64))
        f.close()
        _cert_path = f.name
    return _cert_path

@app.get("/health")
def health():
    return jsonify(ok=True, cert=bool(CERT_B64))

@app.post("/proxy")
def proxy():
    if not TOKEN or request.headers.get("X-Proxy-Token") != TOKEN:
        return jsonify(error="unauthorized"), 401
    b = request.get_json(force=True)
    url = b["url"]
    method = b.get("method", "GET").upper()
    headers = b.get("headers", {})
    body = b.get("body")
    use_cert = b.get("cert", False)
    kw = dict(method=method, headers=headers, timeout=b.get("timeout", 60), verify=False)
    if body:
        kw["data"] = base64.b64decode(body) if isinstance(body, str) else body
    if use_cert:
        cp = cert_path()
        if not cp:
            return jsonify(error="certificado nao configurado"), 500
        kw["cert"] = cp
    for h in ("host", "connection", "content-length"):
        headers.pop(h, None)
    try:
        r = requests.request(url=url, **kw)
        return jsonify(
            status=r.status_code,
            headers=dict(r.headers),
            body_b64=base64.b64encode(r.content).decode(),
        )
    except Exception as e:
        return jsonify(error=str(e)[:500]), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
