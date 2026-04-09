#!/usr/bin/env python3
"""
Local OAuth2 callback server — listens on port 8085,
catches the auth code from gcloud redirect,
exchanges it for tokens and saves ADC credentials.

Usage: python auth_server.py
Then open the gcloud auth URL in your browser.
"""

import http.server
import urllib.parse
import urllib.request
import json
import pathlib
import sys

CLIENT_ID     = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
CLIENT_SECRET = "d-FL95Q19q7MQmFpd7hHD0Ty"
REDIRECT_URI  = "http://localhost:8085"
TOKEN_URL     = "https://oauth2.googleapis.com/token"
ADC_PATH      = pathlib.Path.home() / "AppData" / "Roaming" / "gcloud" / "application_default_credentials.json"

code_holder = {}

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if 'code' in params:
            code_holder['code'] = params['code'][0]
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write("""
<html><body style="font-family:sans-serif;padding:40px;background:#1a1a2e;color:#eee;text-align:center">
<h2 style="color:#4caf50">&#10003; Authentication successful!</h2>
<p>Saving credentials... you can close this tab.</p>
</body></html>""".encode())
        elif 'error' in params:
            code_holder['error'] = params['error'][0]
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"Error: {params['error'][0]}".encode())
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Waiting for auth...")

    def log_message(self, *args):
        pass  # quiet


def exchange_code(code):
    data = urllib.parse.urlencode({
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
    }).encode()
    req = urllib.request.Request(TOKEN_URL, data=data,
                                  headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def save_adc(token_data):
    ADC_PATH.parent.mkdir(parents=True, exist_ok=True)
    creds = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": token_data["refresh_token"],
        "type": "authorized_user",
        "universe_domain": "googleapis.com"
    }
    ADC_PATH.write_text(json.dumps(creds, indent=2))
    return str(ADC_PATH)


print(f"\n[*] OAuth server listening on http://localhost:8085")
print(f"[*] Waiting for browser redirect...\n")
sys.stdout.flush()

server = http.server.HTTPServer(('localhost', 8085), Handler)
server.timeout = 1

import time
deadline = time.time() + 180
while time.time() < deadline:
    server.handle_request()
    if 'code' in code_holder or 'error' in code_holder:
        break

server.server_close()

if 'error' in code_holder:
    print(f"[!] Auth error: {code_holder['error']}")
    sys.exit(1)

if 'code' not in code_holder:
    print("[!] Timeout — no auth code received")
    sys.exit(1)

print("[*] Got auth code. Exchanging for tokens...")
sys.stdout.flush()

try:
    tokens = exchange_code(code_holder['code'])
except Exception as e:
    print(f"[!] Token exchange failed: {e}")
    sys.exit(1)

if 'refresh_token' not in tokens:
    print(f"[!] No refresh_token in response: {tokens}")
    sys.exit(1)

path = save_adc(tokens)
print(f"[+] Credentials saved to: {path}")
print(f"[+] Account: {tokens.get('id_token', 'N/A')[:30] if 'id_token' in tokens else 'kobiloya@gmail.com'}")
print(f"\n[+] SUCCESS — MCP server can now authenticate!\n")
sys.stdout.flush()
