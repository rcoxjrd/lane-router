#!/usr/bin/env python3
"""
Lane Router — reference implementation of the Two-Lane Rule.

Every AI request passes through one question: would this data need a BAA?
If sensitivity detectors fire, the request runs on LOCAL models (Ollama,
on this machine, nothing transmitted). If clean, it may use the CLOUD lane.
Every decision is written to an audit log that stores metadata only — never
the text itself.

Run:    python3 server.py            (http://127.0.0.1:8788)
Needs:  Ollama running locally for the local lane (https://ollama.com)
Config (env vars):
  LOCAL_MODEL   Ollama model for the local lane   (default: qwen2.5:14b)
  CLOUD_CMD     command for the cloud lane, prompt appended as final arg
                (e.g. 'claude -p'). Unset = cloud lane disabled.
  PORT          default 8788
  HOST          default 127.0.0.1 (localhost only; change deliberately)

This is a reference implementation for the Two-Lane Rule, not a compliance
product. Detectors are conservative by design: suspicion routes local.
"""
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DIR = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", 8788))
HOST = os.environ.get("HOST", "127.0.0.1")
LOCAL_MODEL = os.environ.get("LOCAL_MODEL", "qwen2.5:14b")
CLOUD_CMD = os.environ.get("CLOUD_CMD", "").strip()
OLLAMA = "http://localhost:11434/api/chat"
LOG = os.path.join(DIR, "lane_log.jsonl")

# ---------------- detectors ----------------
# Conservative: any hit routes LOCAL. False positives are the safe direction.
PATTERNS = [
    ("ssn",        re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("phone",      re.compile(r"\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b")),
    ("email",      re.compile(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", re.I)),
    ("dob",        re.compile(r"\b(dob|date of birth|born)\b[^\n]{0,20}\d{1,4}[/-]\d{1,2}[/-]\d{1,4}", re.I)),
    ("mrn_or_id",  re.compile(r"\b(mrn|member\s*id|patient\s*id|chart\s*#?|auth(?:orization)?\s*#?)\s*[:#]?\s*[A-Z0-9-]{4,}", re.I)),
    ("name_label", re.compile(r"\b(patient|client|member|guardian|parent)\s*(name)?\s*[:=]\s*[A-Z][a-z]+(\s+[A-Z][a-z]+)?", re.I)),
    ("address",    re.compile(r"\b\d{1,5}\s+[A-Z][a-z]+\s+(st|street|ave|avenue|rd|road|blvd|dr|drive|ln|lane|ct|court)\b", re.I)),
    ("dx_code",    re.compile(r"\b[A-Z]\d{2}\.\d{1,2}\b")),  # ICD-10-ish alongside identity is risky
]
KEYWORDS = re.compile(
    r"\b(diagnos\w+|medicaid\s*id|insurance\s*id|discharge summary|session note|"
    r"incident report|treatment plan)\b", re.I)

def load_roster():
    """Optional names.txt: one known client/patient name per line."""
    p = os.path.join(DIR, "names.txt")
    if os.path.exists(p):
        return [n.strip() for n in open(p) if n.strip()]
    return []
ROSTER = load_roster()

def detect(text):
    hits = []
    for label, rx in PATTERNS:
        if rx.search(text):
            hits.append(label)
    if KEYWORDS.search(text):
        hits.append("sensitive_keyword")
    low = text.lower()
    for name in ROSTER:
        if name.lower() in low:
            hits.append("roster_name")
            break
    return hits

def redact(text):
    out = text
    for _, rx in PATTERNS:
        out = rx.sub("[REDACTED]", out)
    for name in ROSTER:
        out = re.sub(re.escape(name), "[REDACTED]", out, flags=re.I)
    return out

# ---------------- lanes ----------------
def run_local(prompt):
    payload = {"model": LOCAL_MODEL,
               "messages": [{"role": "user", "content": prompt}], "stream": False}
    req = urllib.request.Request(OLLAMA, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.load(r)["message"]["content"].strip(), LOCAL_MODEL

def run_cloud(prompt):
    if not CLOUD_CMD:
        return ("[cloud lane not configured — set CLOUD_CMD, e.g. CLOUD_CMD='claude -p'. "
                "The routing decision and audit entry above are the point of this demo.]",
                "unconfigured")
    argv = CLOUD_CMD.split() + [prompt]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    return (r.stdout.strip() or r.stderr.strip()), CLOUD_CMD.split()[0]

def audit(entry):
    with open(LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

def route(text, task=""):
    t0 = time.time()
    hits = detect(text)
    lane = "local" if hits else "cloud"
    reasons = hits if hits else ["no sensitivity detectors fired"]
    try:
        if lane == "local":
            output, model = run_local(text)
        else:
            output, model = run_cloud(text)
        error = None
    except Exception as e:
        output, model, error = f"[{lane} lane unavailable: {e}]", "none", str(e)
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "id": hashlib.sha256(text.encode()).hexdigest()[:12],
        "chars": len(text),
        "task": task[:60],
        "lane": lane,
        "reasons": reasons,
        "model": model,
        "latency_ms": int((time.time() - t0) * 1000),
        "error": error,
    }
    audit(entry)
    return {"decision": entry, "redacted_preview": redact(text)[:220], "output": output}

def read_log(n=100):
    if not os.path.exists(LOG):
        return []
    with open(LOG) as f:
        lines = f.readlines()[-n:]
    return [json.loads(l) for l in lines]

# ---------------- http ----------------
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, body, code=200):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            data = open(os.path.join(DIR, "index.html"), "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/api/log"):
            return self._json({"entries": read_log(), "live": True})
        self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path == "/api/route":
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            text = (body.get("text") or "").strip()
            if not text:
                return self._json({"error": "no text"}, 400)
            return self._json(route(text, body.get("task", "")))
        self.send_response(404); self.end_headers()

if __name__ == "__main__":
    print(f"Lane Router on http://{HOST}:{PORT}")
    print(f"  local lane: {LOCAL_MODEL} via Ollama")
    print(f"  cloud lane: {CLOUD_CMD or 'DISABLED (set CLOUD_CMD to enable)'}")
    print(f"  audit log:  {LOG} (metadata only, never text)")
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
