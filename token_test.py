#!/usr/bin/env python3
"""
Quick connectivity test using a bearer token from the browser.

How to get your token:
1. Go to secops-lab.backstory.chronicle.security in Chrome
2. Press F12 → Console tab
3. Paste this and press Enter:
      fetch('https://oauth2.googleapis.com/tokeninfo?access_token=' +
        document.cookie.split(';')
          .map(c=>c.trim())
          .find(c=>c.startsWith('COMPASS_ACCESS_TOKEN='))
          ?.split('=').slice(1).join('=') || 'NOT_FOUND')
        .then(r=>r.json()).then(d=>console.log(JSON.stringify(d,null,2)))

   -- OR simpler -- open DevTools → Network → reload page →
   find any XHR request to backstory.googleapis.com →
   look for "Authorization: Bearer eyJ..." header → copy the token

4. Run: python token_test.py <TOKEN>
"""

import sys
import json
import requests

if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(1)

TOKEN   = sys.argv[1]
PROJECT = sys.argv[2] if len(sys.argv) > 2 else ""
INSTANCE = sys.argv[3] if len(sys.argv) > 3 else ""
REGION  = "us"

headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

# 1) Validate token
print("\n[1] Validating token...")
r = requests.get(f"https://oauth2.googleapis.com/tokeninfo?access_token={TOKEN}")
info = r.json()
if "error" in info:
    print(f"  Token invalid: {info}")
    sys.exit(1)
print(f"  Email : {info.get('email','?')}")
print(f"  Scope : {info.get('scope','?')[:80]}...")
print(f"  Expiry: {info.get('expires_in','?')} seconds")

# 2) Test SecOps API (if project/instance provided)
if PROJECT and INSTANCE:
    url = (f"https://{REGION}-chronicle.googleapis.com/v1alpha/"
           f"projects/{PROJECT}/locations/{REGION}/instances/{INSTANCE}/rules")
    print(f"\n[2] Testing SecOps API: {url}")
    r2 = requests.get(url, headers=headers, params={"pageSize": 5})
    print(f"  Status: {r2.status_code}")
    if r2.ok:
        data = r2.json()
        rules = data.get("rules", [])
        print(f"  Rules found: {len(rules)}")
        for rule in rules[:3]:
            print(f"   - {rule.get('name','?')} | {rule.get('displayName','?')}")
    else:
        print(f"  Error: {r2.text[:300]}")
else:
    print("\n[2] Skipping SecOps test (no PROJECT/INSTANCE provided)")
    print("    Usage: python token_test.py <TOKEN> <PROJECT_ID> <INSTANCE_ID>")

print("\nDone.")
