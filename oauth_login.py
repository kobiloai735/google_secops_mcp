#!/usr/bin/env python3
"""
Google OAuth2 Login — מאמת ישירות מול Google ומייצר ADC credentials.
מחליף את `gcloud auth application-default login` לחלוטין.

הרץ: python oauth_login.py
"""

import json
import os
import sys
import webbrowser
import socket
import urllib.parse
import urllib.request
import pathlib

# Google OAuth2 endpoints
AUTH_URL   = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL  = "https://oauth2.googleapis.com/token"

# Chronicle scope — cloud-platform is the correct scope for the Chronicle v1alpha API
SCOPE = "https://www.googleapis.com/auth/cloud-platform"

# ADC credentials file path (same location gcloud uses: %APPDATA% on Windows)
if os.name == "nt":
    ADC_PATH = pathlib.Path(os.environ["APPDATA"]) / "gcloud" / "application_default_credentials.json"
else:
    ADC_PATH = pathlib.Path.home() / ".config" / "gcloud" / "application_default_credentials.json"

# ── Use the gcloud installed-app client ID (public, built into gcloud) ────────
# These are the same client_id/secret that gcloud uses for ADC.
# They are public and embedded in the gcloud binary.
CLIENT_ID     = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
CLIENT_SECRET = "d-FL95Q19q7MQmFpd7hHD0Ty"
REDIRECT_PORT = 8085
REDIRECT_URI  = f"http://localhost:{REDIRECT_PORT}"

def find_free_port():
    with socket.socket() as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def start_local_server(port):
    """Start minimal HTTP server to catch the OAuth redirect."""
    import http.server
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
                self.wfile.write(b"""
                <html><body style="font-family:sans-serif;padding:40px;text-align:center">
                <h2 style="color:green">&#10003; Authentication successful!</h2>
                <p>You can close this tab and return to the terminal.</p>
                </body></html>""")
            elif 'error' in params:
                code_holder['error'] = params['error'][0]
                self.send_response(400)
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
        def log_message(self, *args): pass  # suppress output

    server = http.server.HTTPServer(('localhost', port), Handler)
    return server, code_holder

def exchange_code(code, port):
    """Exchange authorization code for tokens."""
    data = urllib.parse.urlencode({
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': f"http://localhost:{port}",
        'grant_type': 'authorization_code',
    }).encode()
    req = urllib.request.Request(TOKEN_URL, data=data,
                                  headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())

def save_adc(token_data):
    """Save credentials in ADC format that google-auth picks up automatically."""
    ADC_PATH.parent.mkdir(parents=True, exist_ok=True)
    creds = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": token_data["refresh_token"],
        "type": "authorized_user",
        "universe_domain": "googleapis.com"
    }
    ADC_PATH.write_text(json.dumps(creds, indent=2))
    print(f"\n  Credentials saved to: {ADC_PATH}")

def main():
    port = REDIRECT_PORT

    # Build auth URL
    params = urllib.parse.urlencode({
        'client_id': CLIENT_ID,
        'redirect_uri': f"http://localhost:{port}",
        'response_type': 'code',
        'scope': SCOPE,
        'access_type': 'offline',
        'prompt': 'consent',
    })
    auth_url = f"{AUTH_URL}?{params}"

    print("\n=== Google SecOps OAuth2 Login ===\n")
    print("פותח דפדפן לאימות Google...")
    print(f"אם הדפדפן לא נפתח, גש לכתובת:\n  {auth_url}\n")

    # Start local redirect server
    server, code_holder = start_local_server(port)
    server.timeout = 1

    # Open browser
    webbrowser.open(auth_url)

    print("ממתין לאישור בדפדפן... (עד 120 שניות)\n")

    # Wait for redirect (up to 120 seconds)
    import time
    deadline = time.time() + 120
    while time.time() < deadline:
        server.handle_request()
        if 'code' in code_holder or 'error' in code_holder:
            break

    server.server_close()

    if 'error' in code_holder:
        print(f"\nAuth failed: {code_holder['error']}")
        sys.exit(1)

    if 'code' not in code_holder:
        print("\nTimeout — no response received. Try again.")
        sys.exit(1)

    print("קיבלתי authorization code. מחליף ל-token...")
    token_data = exchange_code(code_holder['code'], port)

    if 'refresh_token' not in token_data:
        print(f"\nError getting token: {token_data}")
        sys.exit(1)

    save_adc(token_data)

    print("\n=== הצלחה! ===")
    print("ADC credentials נשמרו.")
    print("MCP Server יוכל עכשיו לאמת אוטומטית מול Google SecOps.\n")

    # Test the token
    test_url = f"https://oauth2.googleapis.com/tokeninfo?access_token={token_data.get('access_token','')}"
    try:
        with urllib.request.urlopen(test_url) as r:
            info = json.loads(r.read())
        print(f"Token info:")
        print(f"  Email : {info.get('email', '?')}")
        print(f"  Scope : ...chronicle-backstory: {'Yes' if 'chronicle' in info.get('scope','') else 'No'}")
        print(f"  Expiry: {info.get('expires_in','?')} sec")
    except Exception as e:
        print(f"  (token check skipped: {e})")

if __name__ == "__main__":
    main()
