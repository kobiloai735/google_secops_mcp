#!/usr/bin/env python3
"""
Google SecOps MCP — Web Dashboard
Runs on http://127.0.0.1:5001
"""

import os, sys, json, time, warnings
from collections import deque
from datetime import datetime
from html import escape as _html_escape

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(__file__))

# Load env vars before importing server
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

os.environ.setdefault("SECOPS_REGION",      "us")

from flask import Flask, jsonify, request, make_response

# Import server functions (avoids triggering mcp.run())
from server import (
    secops_connection_test, secops_list_rules, secops_get_rule,
    secops_create_rule, secops_validate_rule, secops_toggle_rule,
    secops_list_detections, secops_list_alerts, secops_list_reference_lists,
    secops_udm_search,
    # Phase A — Retrohunts + Reference Lists CRUD
    secops_create_retrohunt, secops_get_retrohunt, secops_list_retrohunts,
    secops_create_reference_list, secops_update_reference_list, secops_delete_reference_list,
    # Phase B — Cases / SOAR
    secops_list_cases, secops_get_case, secops_update_case, secops_add_case_comment,
    secops_list_case_alerts, secops_generate_case_report, secops_merge_cases,
    secops_bulk_close_cases,
)

app = Flask(__name__)
_history = deque(maxlen=100)

TOOL_DISPATCH = {
    # Original 10
    "connection_test":        (secops_connection_test,        []),
    "list_rules":             (secops_list_rules,             ["page_size"]),
    "get_rule":               (secops_get_rule,               ["rule_id"]),
    "create_rule":            (secops_create_rule,            ["rule_text"]),
    "validate_rule":          (secops_validate_rule,          ["rule_text"]),
    "toggle_rule":            (secops_toggle_rule,            ["rule_id", "enabled", "alerting"]),
    "list_detections":        (secops_list_detections,        ["rule_id", "hours_back"]),
    "list_alerts":            (secops_list_alerts,            ["hours_back", "state_filter"]),
    "list_reference_lists":   (secops_list_reference_lists,   ["page_size"]),
    "udm_search":             (secops_udm_search,             ["query", "hours_back"]),
    # Phase A — Retrohunts
    "create_retrohunt":       (secops_create_retrohunt,       ["rule_id", "hours_back", "start_time", "end_time"]),
    "get_retrohunt":          (secops_get_retrohunt,          ["rule_id", "retrohunt_id"]),
    "list_retrohunts":        (secops_list_retrohunts,        ["rule_id", "page_size"]),
    # Phase A — Reference Lists CRUD
    "create_reference_list":  (secops_create_reference_list,  ["name", "lines", "description", "syntax_type"]),
    "update_reference_list":  (secops_update_reference_list,  ["list_id", "lines", "description"]),
    "delete_reference_list":  (secops_delete_reference_list,  ["list_id"]),
    # Phase B — Cases
    "list_cases":             (secops_list_cases,             ["page_size", "state_filter", "priority_filter"]),
    "get_case":               (secops_get_case,               ["case_id"]),
    "update_case":            (secops_update_case,            ["case_id", "priority", "stage", "assignee", "name"]),
    "add_case_comment":       (secops_add_case_comment,       ["case_id", "comment"]),
    "list_case_alerts":       (secops_list_case_alerts,       ["case_id", "page_size"]),
    "generate_case_report":   (secops_generate_case_report,   ["case_id"]),
    "merge_cases":            (secops_merge_cases,            ["case_ids", "target_case_id"]),
    "bulk_close_cases":       (secops_bulk_close_cases,       ["case_ids", "reason", "comment"]),
}

def coerce(val, name):
    """Coerce string param values to proper Python types."""
    if val is None or val == "": return None
    if name in ("page_size", "hours_back"):
        try: return int(val)
        except: return val
    if name in ("enabled", "alerting"):
        if isinstance(val, bool): return val
        return str(val).lower() in ("true", "1", "yes")
    if name in ("lines", "case_ids"):
        if isinstance(val, list): return val
        if isinstance(val, str):
            try: return json.loads(val)
            except: return [v.strip() for v in val.splitlines() if v.strip()]
    return val

@app.route("/")
def index():
    page = HTML.replace("__PROJECT_ID__", _html_escape(_srv.PROJECT_ID or "not configured"))
    return make_response(page, 200, {"Content-Type": "text/html; charset=utf-8"})

@app.route("/api/status")
def api_status():
    try:
        result = secops_connection_test()
        return jsonify({"ok": True, "result": result})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/run/<tool_name>", methods=["POST"])
def api_run(tool_name):
    if tool_name not in TOOL_DISPATCH:
        return jsonify({"ok": False, "error": f"Unknown tool: {tool_name}"}), 404

    func, param_names = TOOL_DISPATCH[tool_name]
    body = request.get_json(silent=True) or {}

    kwargs = {}
    for name in param_names:
        val = coerce(body.get(name), name)
        if val is not None:
            kwargs[name] = val

    t0 = time.time()
    try:
        result = func(**kwargs)
        elapsed = int((time.time() - t0) * 1000)
        entry = {
            "tool": tool_name, "params": kwargs,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "duration_ms": elapsed, "status": "ok"
        }
        _history.appendleft(entry)
        return jsonify({"ok": True, "result": result, "history_entry": entry})
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        entry = {
            "tool": tool_name, "params": kwargs,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "duration_ms": elapsed, "status": "error"
        }
        _history.appendleft(entry)
        return jsonify({"ok": False, "error": str(e), "history_entry": entry})

@app.route("/api/history")
def api_history():
    return jsonify(list(_history))


# ── Activity tracing (monkey-patch _request) ──────────────────────────────────
import server as _srv

_activity_log = deque(maxlen=200)
_orig_request = _srv._request

def _traced_request(method, endpoint, payload=None, params=None):
    url = _srv._api_url(endpoint)
    t0 = time.time()
    try:
        result = _orig_request(method, endpoint, payload, params)
        _activity_log.appendleft({
            "method": method, "endpoint": endpoint, "url": url,
            "params": json.dumps(params)[:300] if params else None,
            "payload_keys": list(payload.keys()) if payload else None,
            "status": "ok",
            "duration_ms": int((time.time() - t0) * 1000),
            "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3]
        })
        return result
    except Exception as e:
        _activity_log.appendleft({
            "method": method, "endpoint": endpoint, "url": url,
            "status": "error", "error": str(e)[:300],
            "duration_ms": int((time.time() - t0) * 1000),
            "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3]
        })
        raise

_srv._request = _traced_request


@app.route("/api/activity")
def api_activity():
    return jsonify(list(_activity_log))


@app.route("/api/analyze/explorer")
def analyze_explorer():
    import concurrent.futures as _cf

    TOOLS = [
        {"name":"secops_connection_test","method":"GET","endpoint":"rules?pageSize=1","icon":"🔌",
         "desc_en":"Verify authentication and API connectivity to Chronicle. Run first to confirm setup.",
         "desc_he":"בדיקת קישוריות ואימות — הפעל ראשון לאישור ההגדרה.",
         "inputs":[],"outputs":["status: ok|error|misconfigured","project_id","instance_id","region","rule_count","error (if failed)"],
         "tags":["connection","auth","test","verify","status"]},
        {"name":"secops_list_rules","method":"GET","endpoint":"rules","icon":"📋",
         "desc_en":"List all YARA-L 2.0 detection rules. Each rule includes ID, display name, YARA-L source, type, and deployment state.",
         "desc_he":"רשימת כל חוקי YARA-L 2.0. כולל קוד מקור, סוג, מצב פריסה ותדירות הרצה.",
         "inputs":["page_size (int, default 100)"],
         "outputs":["rules[].name","rules[].displayName","rules[].text (YARA-L source)","rules[].type: SINGLE_EVENT|MULTI_EVENT","rules[].deploymentState: ENABLED|DISABLED","rules[].allowedRunFrequencies: LIVE|HOURLY|DAILY","rules[].author","rules[].severity"],
         "tags":["rules","list","yara","detection","all"]},
        {"name":"secops_get_rule","method":"GET","endpoint":"rules/{rule_id}","icon":"🔍",
         "desc_en":"Retrieve a single rule by ID including full YARA-L source and metadata.",
         "desc_he":"שליפת חוק בודד עם קוד מקור מלא ומטה-דאטה.",
         "inputs":["rule_id: str — e.g. ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"],
         "outputs":["name","displayName","text (full YARA-L 2.0)","type","deploymentState","author","severity","createTime","revisionId"],
         "tags":["rule","get","yara","source","single"]},
        {"name":"secops_create_rule","method":"POST","endpoint":"rules","icon":"✏️",
         "desc_en":"Create a new YARA-L 2.0 detection rule. Use validate_rule first to check syntax.",
         "desc_he":"יצירת חוק YARA-L 2.0 חדש. הפעל validate_rule לפני כדי לוודא תחביר.",
         "inputs":["rule_text: str — full YARA-L 2.0 source code"],
         "outputs":["name (assigned rule ID)","displayName","text","createTime","revisionId"],
         "tags":["create","rule","new","write","yara"]},
        {"name":"secops_validate_rule","method":"POST","endpoint":":verifyRuleText","icon":"✅",
         "desc_en":"Validate (compile) a YARA-L rule without saving. Zero side-effects — safe for testing.",
         "desc_he":"בדיקת תחביר YARA-L ללא שמירה. בטוח לשימוש — אין השפעה על המערכת.",
         "inputs":["rule_text: str — YARA-L source to validate"],
         "outputs":["success: true (absent on compile error)","compilationDiagnostics[].message","compilationDiagnostics[].position","compilationDiagnostics[].severity"],
         "tags":["validate","verify","syntax","compile","test","rule"]},
        {"name":"secops_toggle_rule","method":"PATCH","endpoint":"rules/{id}/deployment","icon":"⚡",
         "desc_en":"Enable or disable a detection rule and its alerting. Disabling enabled=False also disables alerting.",
         "desc_he":"הפעלה/כיבוי של חוק ו-alerting שלו. כיבוי החוק מכבה גם את ההתראות.",
         "inputs":["rule_id: str","enabled: bool (default True)","alerting: bool (default True)"],
         "outputs":["enabled: bool","alerting: bool","runFrequency","lastAlertStatusChangeTime"],
         "tags":["toggle","enable","disable","rule","deployment"]},
        {"name":"secops_list_detections","method":"GET","endpoint":"rules/{id}/detections","icon":"🎯",
         "desc_en":"List rule matches (detections) for a specific rule in a given time window.",
         "desc_he":"רשימת גילויים (matches) של חוק ספציפי בטווח זמן — מה החוק זיהה?",
         "inputs":["rule_id: str","hours_back: int (default 48)","start_time: str (ISO-8601)","end_time: str (ISO-8601)"],
         "outputs":["detections[].id","detections[].ruleId","detections[].timeWindow.startTime","detections[].timeWindow.endTime","detections[].collectionElements[].references[].event (UDM)"],
         "tags":["detections","matches","findings","rule","events"]},
        {"name":"secops_list_alerts","method":"GET","endpoint":"legacy:legacySearchDetections","icon":"🚨",
         "desc_en":"List aggregated alerts from the SecOps alert feed. Requires chronicle-backstory OAuth scope (unavailable for Gmail accounts on demo instances).",
         "desc_he":"רשימת התראות. דורש OAuth scope מיוחד — לא זמין בחשבונות Gmail בסביבות demo.",
         "inputs":["hours_back: int (default 24)","state_filter: NEW|REVIEWED|CLOSED|empty","start_time: str","end_time: str"],
         "outputs":["alerts[].id","alerts[].ruleId","alerts[].ruleName","alerts[].severity: CRITICAL|HIGH|MEDIUM|LOW","alerts[].state","alerts[].createdTime","alerts[].detectionTime"],
         "tags":["alerts","feed","severity","state","new","reviewed","closed"]},
        {"name":"secops_list_reference_lists","method":"GET","endpoint":"referenceLists","icon":"📚",
         "desc_en":"List all reference lists (allowlists, blocklists, IOC lists) including IPs, domains, hashes, CIDRs, and regex patterns.",
         "desc_he":"רשימות עזר: IPs, domains, hashes, CIDRs, regex — allowlists ו-blocklists.",
         "inputs":["page_size: int (default 50)"],
         "outputs":["referenceLists[].name","referenceLists[].description","referenceLists[].type: PLAIN_TEXT_STRING|CIDR|REGEX","referenceLists[].lines[] (IOC entries)","referenceLists[].createTime"],
         "tags":["reference","list","ioc","allowlist","blocklist","ip","domain","hash","cidr","regex"]},
        {"name":"secops_udm_search","method":"GET","endpoint":"udmEvents","icon":"🔎",
         "desc_en":"Search all UDM events with a filter expression. The most powerful query tool — can retrieve any field from any event.",
         "desc_he":"חיפוש UDM — הכלי החזק ביותר. ניתן לשלוף כל שדה מכל אירוע עם filter expression.",
         "inputs":["query: str (UDM filter e.g. metadata.event_type = \"USER_LOGIN\")","hours_back: int (default 24)","start_time: str","end_time: str"],
         "outputs":["events[].metadata (type, timestamp, product)","events[].principal (ip, hostname, user, process)","events[].target (ip, port, url, user, file)","events[].network (http, dns, protocol)","events[].security_result (action, severity, threat)","events[].src","totalCount: int"],
         "tags":["search","udm","events","query","all","filter","network","user","file","process"]},
    ]

    UDM_SECTIONS = {
        "metadata": {
            "desc": "Event metadata — type, source product, timestamps",
            "color": "var(--blue)",
            "fields": [
                ("metadata.event_type", "סוג האירוע", "USER_LOGIN, NETWORK_CONNECTION, FILE_MODIFICATION, PROCESS_LAUNCH, USER_LOGOUT, NETWORK_DNS, EMAIL_TRANSACTION, etc."),
                ("metadata.timestamp", "חותמת זמן", "Event occurrence time in ISO-8601 format"),
                ("metadata.collected_timestamp", "זמן איסוף", "When the event was ingested into Chronicle"),
                ("metadata.product_name", "שם המוצר", "Log source product (e.g. Windows, CrowdStrike Falcon, Palo Alto)"),
                ("metadata.vendor_name", "יצרן", "Vendor name (e.g. Microsoft, CrowdStrike, Zscaler)"),
                ("metadata.log_type", "סוג לוג", "e.g. WINDOWS_SYSMON, CROWDSTRIKE_EDR, PAN_FIREWALL"),
                ("metadata.id", "מזהה ייחודי", "Unique event identifier"),
                ("metadata.description", "תיאור", "Human-readable description of the event"),
            ]
        },
        "principal": {
            "desc": "Actor/source — the entity that initiated the action",
            "color": "var(--green)",
            "fields": [
                ("principal.ip", "IP מקור", "Source IP address — e.g. principal.ip = \"10.0.0.1\""),
                ("principal.hostname", "שם מחשב", "Source hostname — e.g. principal.hostname = \"WORKSTATION-01\""),
                ("principal.mac", "MAC address", "Network MAC address of the source"),
                ("principal.user.userid", "שם משתמש", "User account name — e.g. principal.user.userid = \"jsmith\""),
                ("principal.user.email_addresses", "אימייל", "User email address"),
                ("principal.user.department", "מחלקה", "Organizational department"),
                ("principal.user.title", "תפקיד", "Job title"),
                ("principal.process.pid", "PID תהליך", "Process ID"),
                ("principal.process.command_line", "שורת פקודה", "Full process command line — e.g. powershell.exe -enc ..."),
                ("principal.process.file.full_path", "נתיב קובץ", "Executable file path"),
                ("principal.process.file.sha256", "SHA-256", "Process file hash"),
                ("principal.asset.hostname", "שם נכס", "Managed asset hostname from asset database"),
                ("principal.location.country_or_region", "מדינה", "Geographic location of the source"),
            ]
        },
        "target": {
            "desc": "Target entity — the subject of the action",
            "color": "var(--red)",
            "fields": [
                ("target.ip", "IP יעד", "Destination IP address"),
                ("target.hostname", "שם מחשב יעד", "Destination hostname"),
                ("target.port", "פורט", "Destination port number — e.g. target.port = 443"),
                ("target.url", "כתובת URL", "Target URL — e.g. target.url = \"https://evil.com/payload\""),
                ("target.user.userid", "משתמש יעד", "Target user account"),
                ("target.file.full_path", "נתיב קובץ", "Target file path"),
                ("target.file.sha256", "SHA-256", "Target file hash for malware detection"),
                ("target.file.size", "גודל קובץ", "File size in bytes"),
                ("target.application", "אפליקציה", "Target application name"),
                ("target.registry.registry_key", "מפתח רגיסטרי", "Windows registry key path"),
                ("target.registry.registry_value_name", "ערך רגיסטרי", "Registry value name"),
            ]
        },
        "network": {
            "desc": "Network communication details — HTTP, DNS, email, protocol",
            "color": "var(--yellow)",
            "fields": [
                ("network.ip_protocol", "פרוטוקול", "TCP, UDP, ICMP, etc."),
                ("network.direction", "כיוון", "INBOUND, OUTBOUND, UNKNOWN_DIRECTION"),
                ("network.http.method", "HTTP Method", "GET, POST, PUT, DELETE, PATCH, etc."),
                ("network.http.response_code", "HTTP Status", "Response code — e.g. 200, 403, 404, 500"),
                ("network.http.user_agent", "User Agent", "Browser/client user agent string"),
                ("network.http.referral_url", "Referrer", "HTTP referrer URL"),
                ("network.dns.question.name", "DNS Query", "Domain name being resolved — e.g. network.dns.question.name = \"evil.com\""),
                ("network.dns.response_code", "DNS Response", "NOERROR, NXDOMAIN, SERVFAIL, etc."),
                ("network.email.from", "מאת (Email)", "Sender email address"),
                ("network.email.subject", "נושא", "Email subject line — useful for phishing detection"),
                ("network.email.to", "אל (Email)", "Recipient email address"),
                ("network.session_id", "Session ID", "Network session identifier"),
            ]
        },
        "security_result": {
            "desc": "Security verdict, threat detection results, and rule matches",
            "color": "var(--purple)",
            "fields": [
                ("security_result.action", "פעולה", "ALLOW, BLOCK, UNKNOWN_ACTION"),
                ("security_result.severity", "חומרה", "CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL"),
                ("security_result.threat_name", "שם איום", "Detected threat or malware name"),
                ("security_result.category_details", "קטגוריה", "Threat category (e.g. Trojan, Ransomware)"),
                ("security_result.rule_name", "שם חוק", "Name of the detection rule that fired"),
                ("security_result.rule_id", "מזהה חוק", "Detection rule ID"),
                ("security_result.confidence", "רמת ביטחון", "Detection confidence score (0-100)"),
                ("security_result.summary", "סיכום", "Human-readable security result summary"),
                ("security_result.about[].hostname", "מחשב קשור", "Hosts associated with the security event"),
            ]
        },
        "src": {
            "desc": "Source network endpoint (alternative to principal for network flow events)",
            "color": "var(--muted)",
            "fields": [
                ("src.ip", "IP מקור", "Source IP (used in NETWORK_CONNECTION events)"),
                ("src.hostname", "שם מחשב", "Source hostname"),
                ("src.port", "פורט מקור", "Source port number"),
                ("intermediary.ip", "IP ביניים", "Intermediate hop IP address (proxy, gateway)"),
                ("observer.hostname", "מחשב צופה", "Observing system (e.g. IDS sensor)"),
            ]
        },
    }

    AI_INFO = {
        "via_mcp": [
            {"icon":"✅","title":"UDM Search","desc_en":"Query any event with AI-style natural language filters mapped to UDM expressions. Use secops_udm_search.","desc_he":"חיפוש אירועים עם filter expressions — הכי קרוב ל-AI query."},
            {"icon":"✅","title":"Rule Creation","desc_en":"Generate and deploy YARA-L detection rules via create_rule + validate_rule.","desc_he":"יצירת ופריסת חוקי YARA-L — כולל בדיקת תחביר לפני שמירה."},
            {"icon":"✅","title":"IOC Management","desc_en":"Manage threat intelligence lists (IPs, domains, hashes) via list_reference_lists.","desc_he":"ניהול רשימות IOC — IPs, domains, hashes, CIDRs."},
            {"icon":"✅","title":"Detection Results","desc_en":"Retrieve rule matches and correlate with event data via list_detections.","desc_he":"שליפת תוצאות גילוי ומתאם עם נתוני אירועים."},
        ],
        "ui_only": [
            {"icon":"🔜","title":"Gemini AI Summaries","desc_en":"Natural language summaries of alerts and investigations — available in Chronicle UI, not yet in API.","desc_he":"סיכומי AI של התראות — זמין בממשק ה-UI, לא ב-API עדיין."},
            {"icon":"🔜","title":"AI Rule Suggestions","desc_en":"Gemini-powered YARA-L rule generation from natural language — UI only.","desc_he":"הצעות YARA-L מ-Gemini על בסיס שפה טבעית — UI בלבד."},
            {"icon":"🔜","title":"SOAR Playbooks","desc_en":"Automated response playbooks — requires SOAR API (separate from Chronicle API).","desc_he":"Playbooks לתגובה אוטומטית — דורש SOAR API נפרד."},
            {"icon":"🔜","title":"Case Management","desc_en":"Security case tracking and assignment — accessible via SOAR API, not Chronicle API.","desc_he":"ניהול תיקי חקירה — SOAR API, לא Chronicle API."},
            {"icon":"🔜","title":"Threat Intelligence Graph","desc_en":"Visual threat graph and entity relationships — UI feature only.","desc_he":"גרף קשרי איומים — תכונת UI בלבד."},
        ],
        "enrichments": [
            {"field":"security_result.threat_name","source":"GCTI / VirusTotal","desc":"Threat intelligence enrichment embedded in events"},
            {"field":"principal.location.*","source":"MaxMind GeoIP","desc":"Geographic enrichment auto-added to network events"},
            {"field":"target.file.prevalence_rate","source":"VirusTotal","desc":"File prevalence data (rare = suspicious)"},
            {"field":"network.dns.question.name","source":"Passive DNS","desc":"Domain resolution history and age"},
            {"field":"principal.user.department","source":"HR/LDAP","desc":"User identity enrichment from directory"},
        ],
        "udm_query_examples": [
            {"desc":"Login events","q":'metadata.event_type = "USER_LOGIN"'},
            {"desc":"Failed logins","q":'metadata.event_type = "USER_LOGIN" AND security_result.action = "BLOCK"'},
            {"desc":"PowerShell execution","q":'metadata.event_type = "PROCESS_LAUNCH" AND target.process.command_line = /powershell/i'},
            {"desc":"DNS to suspicious domain","q":'metadata.event_type = "NETWORK_DNS" AND network.dns.question.name != ""'},
            {"desc":"Outbound HTTP to port 80","q":'metadata.event_type = "NETWORK_CONNECTION" AND target.port = 80 AND network.direction = "OUTBOUND"'},
            {"desc":"File with specific hash","q":'target.file.sha256 = "abc123..."'},
            {"desc":"High severity alerts","q":'security_result.severity = "HIGH" OR security_result.severity = "CRITICAL"'},
            {"desc":"Specific user activity","q":'principal.user.userid = "jsmith"'},
            {"desc":"Lateral movement (admin shares)","q":'metadata.event_type = "NETWORK_CONNECTION" AND target.url = /admin\$/i'},
            {"desc":"Email with attachment","q":'metadata.event_type = "EMAIL_TRANSACTION" AND network.email.subject != ""'},
        ],
    }

    # Fetch live system stats in parallel
    live_stats = {"rule_count": "?", "ref_list_count": "?", "live_rules": "?"}
    try:
        with __import__("concurrent.futures", fromlist=["ThreadPoolExecutor"]).ThreadPoolExecutor(max_workers=2) as ex:
            f_rules = ex.submit(secops_list_rules, 200)
            f_refs  = ex.submit(secops_list_reference_lists, 5)
            rules_data = f_rules.result()
            refs_data  = f_refs.result()
        rules = rules_data.get("rules", [])
        live_stats["rule_count"] = len(rules)
        live_stats["live_rules"] = sum(1 for r in rules if "LIVE" in r.get("allowedRunFrequencies", []))
        live_stats["ref_list_count"] = refs_data.get("totalSize", len(refs_data.get("referenceLists", [])))
    except Exception:
        pass

    return jsonify({"ok": True, "result": {
        "live_stats": live_stats,
        "tools": TOOLS,
        "udm_sections": {k: {"desc": v["desc"], "color": v["color"], "fields": v["fields"]} for k, v in UDM_SECTIONS.items()},
        "ai_info": AI_INFO,
    }})


@app.route("/api/analyze/connection")
def analyze_connection():
    import time as _time
    steps = []

    def do_step(name, fn):
        t0 = _time.time()
        try:
            detail = fn()
            ms = int((_time.time() - t0) * 1000)
            steps.append({"step": name, "status": "ok", "detail": detail, "ms": ms})
            return True
        except Exception as exc:
            ms = int((_time.time() - t0) * 1000)
            steps.append({"step": name, "status": "error", "detail": str(exc)[:300], "ms": ms})
            return False

    import server as _s

    # Step 1: Config validation
    def _step_config():
        pid = _s.PROJECT_ID
        iid = _s.INSTANCE_ID
        reg = _s.REGION
        if not pid or not iid:
            raise RuntimeError("Missing SECOPS_PROJECT_ID or SECOPS_INSTANCE_ID in .env")
        return f"Project: {pid}  |  Region: {reg}  |  Instance: {iid[:8]}…{iid[-4:]}"
    do_step("Load configuration (.env)", _step_config)

    # Step 2: Auth method detection
    def _step_auth_method():
        sa = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
        if sa and os.path.exists(sa):
            return f"Service Account JSON  →  {os.path.basename(sa)}"
        elif sa:
            return f"GOOGLE_APPLICATION_CREDENTIALS set but file not found: {sa}"
        return "Application Default Credentials (ADC)  —  gcloud auth application-default login"
    do_step("Resolve authentication method", _step_auth_method)

    # Step 3: Obtain OAuth2 token
    def _step_token():
        creds = _s._get_credentials()
        token_preview = (creds.token or "")[:16] + "..." if creds.token else "(no token)"
        exp = getattr(creds, 'expiry', None)
        exp_str = exp.strftime("%H:%M UTC") if exp else "N/A"
        return f"Bearer token obtained  |  Preview: {token_preview}  |  Expires: {exp_str}"
    do_step("Obtain OAuth2 access token", _step_token)

    # Step 4: Build endpoint URL
    def _step_url():
        return f"{_s.BASE_URL}/v1alpha/{_s.INSTANCE_PATH}/rules"
    do_step("Build Chronicle API endpoint URL", _step_url)

    # Step 5: API handshake
    def _step_api():
        result = _s._request("GET", "rules", params={"pageSize": 5})
        rules = result.get("rules", [])
        sample = ", ".join(r.get("displayName", "?") for r in rules[:3])
        return f"HTTP 200 OK  |  API responding  |  Sample: {sample}…"
    do_step("API handshake — GET /rules", _step_api)

    overall = "ok" if all(s["status"] == "ok" for s in steps) else "error"
    total_ms = sum(s["ms"] for s in steps)

    sa_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    config_snapshot = {
        "SECOPS_PROJECT_ID":  _s.PROJECT_ID,
        "SECOPS_INSTANCE_ID": _s.INSTANCE_ID,
        "SECOPS_REGION":      _s.REGION,
        "BASE_URL":           _s.BASE_URL,
        "INSTANCE_PATH":      _s.INSTANCE_PATH,
        "AUTH_METHOD":        "Service Account" if (sa_file and os.path.exists(sa_file)) else "ADC",
        "CREDENTIALS_FILE":   sa_file or "(not set — using ADC)",
    }
    return jsonify({"ok": True, "result": {
        "overall": overall,
        "total_ms": total_ms,
        "steps": steps,
        "config": config_snapshot,
    }})


@app.route("/api/analyze/rules")
def analyze_rules():
    import re as _re
    try:
        rules_data = secops_list_rules(page_size=200)
        rules = rules_data.get("rules", [])

        # Category inference from displayName (no extra API calls needed)
        CATEGORIES = {
            "malware": ["malware", "trojan", "backdoor", "rat", "rootkit", "worm", "virus"],
            "APT / Threat Actor": ["apt", "plugx", "cobalt", "mimikatz", "lazarus", "cozy"],
            "Ransomware": ["ransom", "encrypt", "lockbit", "revil", "ryuk"],
            "Network": ["network", "dns", "http", "smtp", "ftp", "lateral", "c2", "beaconing", "port_scan"],
            "Authentication": ["auth", "login", "brute", "kerberos", "ntlm", "credential", "password"],
            "Suspicious / Anomaly": ["suspicious", "anomal", "unusual", "rare", "detect"],
            "Data Exfiltration": ["exfil", "data_leak", "dlp", "upload"],
            "Phishing": ["phish", "spear", "lure"],
            "Execution": ["exec", "powershell", "cmd", "script", "wmi", "schtask", "cron"],
            "Persistence": ["persist", "registry", "startup", "autorun", "service_install"],
            "Privilege Escalation": ["priv_esc", "privilege", "sudo", "uac", "elevation"],
        }

        analyzed, cat_counts, author_counts = [], {}, {}
        freq_counts, type_counts = {}, {}
        live_capable = 0

        for rule in rules:
            name_lower = rule.get("displayName", "").lower()
            # Categorize by displayName keywords
            cat = "Other"
            for c, keywords in CATEGORIES.items():
                if any(kw in name_lower for kw in keywords):
                    cat = c
                    break
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

            # Author
            auth = rule.get("author", "Unknown")
            author_counts[auth] = author_counts.get(auth, 0) + 1

            # Type (SINGLE_EVENT / MULTI_EVENT)
            rtype = rule.get("type", "UNKNOWN")
            type_counts[rtype] = type_counts.get(rtype, 0) + 1

            # Run frequencies
            freqs = rule.get("allowedRunFrequencies", [])
            for f in freqs:
                freq_counts[f] = freq_counts.get(f, 0) + 1
            if "LIVE" in freqs:
                live_capable += 1

            enabled = rule.get("deploymentState") == "ENABLED"
            analyzed.append({
                "id": rule.get("name", "").split("/")[-1],
                "name": rule.get("displayName", "?"),
                "enabled": enabled,
                "category": cat,
                "author": auth,
                "type": rtype,
                "live_capable": "LIVE" in freqs,
            })

        enabled_count = sum(1 for r in analyzed if r["enabled"])
        return jsonify({"ok": True, "result": {
            "total": len(analyzed),
            "enabled": enabled_count,
            "disabled": len(analyzed) - enabled_count,
            "live_capable": live_capable,
            "category_breakdown": dict(sorted(cat_counts.items(), key=lambda x: -x[1])),
            "author_breakdown": dict(sorted(author_counts.items(), key=lambda x: -x[1])),
            "type_breakdown": type_counts,
            "frequency_breakdown": freq_counts,
            "rules": analyzed,
        }})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/analyze/timeline")
def analyze_timeline():
    import re as _re
    from datetime import datetime, timezone, timedelta
    try:
        alerts_data = secops_list_alerts(hours_back=72)
        alerts = alerts_data.get("alerts", alerts_data.get("detections", []))
        now = datetime.now(timezone.utc)

        hourly, daily, by_rule, by_host, by_priority, rule_labels = {}, {}, {}, {}, {}, {}
        no_time_count = 0

        for alert in alerts:
            # ── time bucketing ──────────────────────────────────────────────
            t_str = (alert.get("detectionTime") or alert.get("createdTime") or
                     alert.get("timeWindow", {}).get("startTime", ""))
            try:
                if t_str:
                    t = datetime.fromisoformat(t_str.replace("Z", "+00:00"))
                    hourly[t.strftime("%Y-%m-%d %H:00")] = hourly.get(t.strftime("%Y-%m-%d %H:00"), 0) + 1
                    daily[t.strftime("%Y-%m-%d")] = daily.get(t.strftime("%Y-%m-%d"), 0) + 1
                else:
                    no_time_count += 1
            except Exception:
                no_time_count += 1

            # ── rule ────────────────────────────────────────────────────────
            det = alert.get("detection", [])
            rule = (det[0].get("ruleName") if isinstance(det, list) and det
                    else alert.get("ruleName", "Unknown"))
            by_rule[rule] = by_rule.get(rule, 0) + 1

            # ── rule labels / categories ────────────────────────────────────
            if isinstance(det, list):
                for d in det:
                    for lbl in d.get("ruleLabels", []):
                        v = lbl.get("value", "")
                        if v:
                            rule_labels[v] = rule_labels.get(v, 0) + 1

            # ── host from alert name field ──────────────────────────────────
            name_field = alert.get("name", "")
            # format: projects/.../alerts/XXX  OR hostname:wrk-pac...
            host_m = _re.search(r"hostname:([^\s,/]+)", name_field)
            if not host_m:
                # also check inside detection outcomes
                for d in (det if isinstance(det, list) else []):
                    for outcome in d.get("outcomes", []):
                        if outcome.get("key", "").lower() == "hostname":
                            host_m_tmp = outcome.get("value", "")
                            if host_m_tmp:
                                by_host[host_m_tmp] = by_host.get(host_m_tmp, 0) + 1
            else:
                h = host_m.group(1)
                by_host[h] = by_host.get(h, 0) + 1

            # ── priority ────────────────────────────────────────────────────
            p = str(alert.get("priority", alert.get("severity", "UNSPECIFIED")))
            by_priority[p] = by_priority.get(p, 0) + 1

        # ── trend: compare last 24h vs prev 24h ────────────────────────────
        fmt = "%Y-%m-%d %H:00"
        cut24 = (now - timedelta(hours=24)).strftime(fmt)
        cut48 = (now - timedelta(hours=48)).strftime(fmt)
        last24 = sum(v for k, v in hourly.items() if k >= cut24)
        prev24 = sum(v for k, v in hourly.items() if cut48 <= k < cut24)
        if prev24 > 0:
            trend_pct = round((last24 - prev24) / prev24 * 100)
        elif last24 > 0:
            trend_pct = 100
        else:
            trend_pct = 0

        # ── peak hour ───────────────────────────────────────────────────────
        peak_hour = max(hourly, key=hourly.get) if hourly else ""
        peak_count = hourly.get(peak_hour, 0)

        api_note = alerts_data.get("_api_note", "")
        if not alerts and api_note:
            # Fallback: rich rule-based timeline context
            rules_data = secops_list_rules(page_size=200)
            rules = rules_data.get("rules", [])
            freq_dist = {}
            for r in rules:
                for f in r.get("allowedRunFrequencies", []):
                    freq_dist[f] = freq_dist.get(f, 0) + 1
            return jsonify({"ok": True, "result": {
                "total": 0, "window_hours": 72,
                "api_unavailable": True,
                "api_note": api_note,
                "rules_total": len(rules),
                "rules_frequency_dist": freq_dist,
                "rules_live": sum(1 for r in rules if "LIVE" in r.get("allowedRunFrequencies", [])),
                "rules_multi_event": sum(1 for r in rules if r.get("type") == "MULTI_EVENT"),
                "hourly": {}, "daily": {},
                "by_rule": {}, "by_host": {}, "by_priority": {},
                "rule_labels": {}, "last_24h": 0, "prev_24h": 0,
                "trend_pct": 0, "peak_hour": "", "peak_count": 0,
            }})

        return jsonify({"ok": True, "result": {
            "total": len(alerts),
            "window_hours": 72,
            "no_timestamp": no_time_count,
            "hourly": dict(sorted(hourly.items())),
            "daily": dict(sorted(daily.items())),
            "by_rule": dict(sorted(by_rule.items(), key=lambda x: -x[1])[:12]),
            "by_host": dict(sorted(by_host.items(), key=lambda x: -x[1])[:20]),
            "by_priority": by_priority,
            "rule_labels": dict(sorted(rule_labels.items(), key=lambda x: -x[1])[:15]),
            "last_24h": last24,
            "prev_24h": prev24,
            "trend_pct": trend_pct,
            "peak_hour": peak_hour,
            "peak_count": peak_count,
        }})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/analyze/alerts")
def analyze_alerts_analysis():
    try:
        alerts_data = secops_list_alerts(hours_back=48)
        alerts = alerts_data.get("alerts", alerts_data.get("detections", []))
        api_note = alerts_data.get("_api_note", "")

        if not alerts and api_note:
            # API unavailable — return enriched rules + reference lists summary
            rules_data = secops_list_rules(page_size=200)
            rules = rules_data.get("rules", [])
            ref_data = secops_list_reference_lists(page_size=50)
            ref_lists = ref_data.get("referenceLists", [])
            return jsonify({"ok": True, "result": {
                "total": 0,
                "api_unavailable": True,
                "api_note": api_note,
                "rules_total": len(rules),
                "rules_live_capable": sum(1 for r in rules if "LIVE" in r.get("allowedRunFrequencies", [])),
                "reference_lists_total": len(ref_lists),
                "reference_lists": [
                    {"name": rl.get("name","").split("/")[-1],
                     "description": rl.get("description",""),
                     "type": rl.get("syntaxType",""),
                     "updated": rl.get("revisionCreateTime","")[:10]}
                    for rl in ref_lists
                ],
            }})

        by_sev, by_rule, by_state = {}, {}, {}
        for alert in alerts:
            sev = str(alert.get("severity", alert.get("riskScore", "UNKNOWN")))
            by_sev[sev] = by_sev.get(sev, 0) + 1
            det = alert.get("detection", [])
            rule = (det[0].get("ruleName") if isinstance(det, list) and det
                    else alert.get("ruleName", alert.get("rule_name", "Unknown")))
            by_rule[rule] = by_rule.get(rule, 0) + 1
            fb = alert.get("feedbackSummary", {})
            state = fb.get("status", alert.get("state", "UNSPECIFIED"))
            by_state[state] = by_state.get(state, 0) + 1
        return jsonify({"ok": True, "result": {
            "total": len(alerts), "window_hours": 48,
            "by_severity": dict(sorted(by_sev.items(), key=lambda x: -x[1])),
            "by_rule": dict(sorted(by_rule.items(), key=lambda x: -x[1])[:15]),
            "by_state": by_state,
        }})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/analyze/intelligence")
def analyze_intelligence():
    import concurrent.futures as _cf
    try:
        with _cf.ThreadPoolExecutor(max_workers=2) as executor:
            f_rules = executor.submit(secops_list_rules, 200)
            f_refs  = executor.submit(secops_list_reference_lists, 100)
            rules_data = f_rules.result()
            refs_data  = f_refs.result()

        rules     = rules_data.get("rules", [])
        ref_lists = refs_data.get("referenceLists", [])

        CATEGORIES = {
            "MITRE ATT&CK":         ["mitre_attack","t1021","t1003","t1090","t1110","t1059","t1055","lolbin","recon","ntdsdit"],
            "Threat Intelligence":  ["safebrowsing","gcti","prevalence","vt_spreader","vt_enrichment","virustotal","whois","fusion_threat","hash_prevalence","domain_prevalence","ip_target","previously_observed"],
            "Risk Scoring":         ["composite","risk_score","cumulative","multi_tactic","multi_tactic"],
            "Malware & Trojans":    ["malware","trojan","backdoor","rat","rootkit","worm","virus","ransomware","ransom","ursnif","process_launch_graph"],
            "APT & Threat Actors":  ["apt","plugx","cobalt","mimikatz","lazarus","cozy","fancy","bear","panda","remote_access_tool"],
            "Network Threats":      ["network","dns","http","smtp","ftp","lateral","c2","beacon","port_scan","scan","tunnel","port_proxy","admin_share","windows_admin_share"],
            "Identity & Auth":      ["auth","login","brute","kerberos","ntlm","credential","password","identity","token","password_spray","t1110"],
            "Suspicious Activity":  ["suspicious","anomal","unusual","rare","indicator","ioc","risky_activity"],
            "Data Protection":      ["exfil","data_leak","dlp","upload","copy","transfer","download"],
            "Phishing & Social Eng":["phish","spear","lure","social","email_threat","invoice"],
            "Execution & Scripts":  ["exec","powershell","cmd","script","wmi","schtask","cron","macro","office","process_creation","process_launch"],
            "Persistence":          ["persist","registry","startup","autorun","service","scheduled","boot","windows_event_log"],
            "Privilege Escalation": ["priv","privilege","sudo","uac","elevation","impersonat"],
            "Cloud & SaaS":         ["cloud","aws","gcp","azure","saas","o365","workspace","drive","sharepoint"],
        }

        cat_counts, author_counts, freq_counts, type_counts = {}, {}, {}, {}
        live_rules, multi_event_rules = [], []

        for rule in rules:
            name_lower = rule.get("displayName", "").lower()
            cat = "Other"
            for c, keywords in CATEGORIES.items():
                if any(kw in name_lower for kw in keywords):
                    cat = c
                    break
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
            author_counts[rule.get("author", "Unknown")] = author_counts.get(rule.get("author", "Unknown"), 0) + 1
            rtype = rule.get("type", "UNKNOWN")
            type_counts[rtype] = type_counts.get(rtype, 0) + 1
            freqs = rule.get("allowedRunFrequencies", [])
            for f in freqs:
                freq_counts[f] = freq_counts.get(f, 0) + 1
            if "LIVE" in freqs:
                live_rules.append(rule.get("displayName", "?"))
            if rtype == "MULTI_EVENT":
                multi_event_rules.append(rule.get("displayName", "?"))

        ref_type_counts = {}
        for rl in ref_lists:
            rt = rl.get("syntaxType", "UNKNOWN").replace("REFERENCE_LIST_SYNTAX_TYPE_", "")
            ref_type_counts[rt] = ref_type_counts.get(rt, 0) + 1

        covered_cats = sum(1 for c in CATEGORIES if c in cat_counts)
        coverage_score = min(100, int(
            (covered_cats / len(CATEGORIES)) * 60 +
            (min(len(ref_lists), 30) / 30) * 25 +
            (min(freq_counts.get("LIVE", 0), 20) / 20) * 15
        ))

        return jsonify({"ok": True, "result": {
            "total_rules":              len(rules),
            "total_ref_lists":          len(ref_lists),
            "live_rules_count":         freq_counts.get("LIVE", 0),
            "multi_event_count":        type_counts.get("MULTI_EVENT", 0),
            "coverage_score":           coverage_score,
            "covered_categories":       covered_cats,
            "category_breakdown":       dict(sorted(cat_counts.items(), key=lambda x: -x[1])),
            "author_breakdown":         dict(sorted(author_counts.items(), key=lambda x: -x[1])[:8]),
            "freq_breakdown":           freq_counts,
            "type_breakdown":           type_counts,
            "ref_type_breakdown":       ref_type_counts,
            "ref_lists": [
                {
                    "name":        rl.get("name","").split("/")[-1],
                    "displayName": rl.get("displayName",""),
                    "description": rl.get("description",""),
                    "type":        rl.get("syntaxType","").replace("REFERENCE_LIST_SYNTAX_TYPE_",""),
                    "updated":     rl.get("revisionCreateTime","")[:10],
                }
                for rl in ref_lists
            ],
            "live_rules_sample":        live_rules[:12],
            "multi_event_rules_sample": multi_event_rules[:12],
        }})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ── AI Bot ───────────────────────────────────────────────────────────────────

import re, concurrent.futures as _cf_bot

def _bot_detect_intent(query: str) -> str:
    q = query.lower()
    if any(k in q for k in ["retrohunt","ציד היסטורי","historical","replay","הרץ על עבר"]):
        return "retrohunt"
    if any(k in q for k in ["case","תיק","incident","soar","חקירה","חקור","investigate"]):
        return "cases"
    if any(k in q for k in ["block","חסום","ioc list","reference list","blocklist","allowlist","רשימה חדשה","הוסף ל"]):
        return "ioc_manage"
    if any(k in q for k in ["rule","חוק","yara","create rule","צור חוק","validate"]):
        return "rules"
    if any(k in q for k in ["alert","התראה","התראות","severity","critical","high alert"]):
        return "alerts"
    if any(k in q for k in ["report","דוח","סכם","summary","overview","מה קרה","status","daily"]):
        return "report"
    if any(k in q for k in ["search","חפש","find","מצא","udm","login","brute","powershell","ip ","user ","משתמש","network"]):
        return "search"
    return "report"

def _bot_build_udm_query(query: str) -> str:
    q = query.lower()
    parts = []
    if any(k in q for k in ["failed login","כניסה כושלת","brute force","wrong password","login block"]):
        parts = ['metadata.event_type = "USER_LOGIN"', 'security_result.action = "BLOCK"']
    elif any(k in q for k in ["powershell","פאוורשל"]):
        parts = ['metadata.event_type = "PROCESS_LAUNCH"', 'target.process.command_line = /powershell/i']
    elif any(k in q for k in ["dns","domain query"]):
        parts = ['metadata.event_type = "NETWORK_DNS"', 'network.dns.question.name != ""']
    elif any(k in q for k in ["network","connection","חיבור רשת"]):
        parts = ['metadata.event_type = "NETWORK_CONNECTION"']
    elif any(k in q for k in ["file","קובץ","write","creation"]):
        parts = ['metadata.event_type = "FILE_MODIFICATION"']
    else:
        # extract IP / user from query
        ip = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', query)
        user = re.search(r'user[:\s]+(\w+)|משתמש[:\s]+(\w+)', query, re.I)
        if ip:
            parts = [f'principal.ip = "{ip.group(1)}"']
        elif user:
            uid = user.group(1) or user.group(2)
            parts = [f'principal.user.userid = "{uid}"']
        else:
            parts = ['security_result.severity = "HIGH"']
    return " AND ".join(parts)

@app.route("/api/bot", methods=["POST"])
def api_bot():
    body = request.get_json(silent=True) or {}
    query = body.get("query", "").strip()
    if not query:
        return jsonify({"ok": False, "error": "query is required"})

    intent = _bot_detect_intent(query)
    steps = []
    result_html = ""

    try:
        if intent == "search":
            udm_q = _bot_build_udm_query(query)
            data = secops_udm_search(query=udm_q, hours_back=24)
            events = data.get("events", [])
            steps.append({"tool": "secops_udm_search", "query": udm_q})
            result_html = _bot_fmt_events(events, udm_q)

        elif intent == "alerts":
            hours = 24
            m = re.search(r'(\d+)\s*(hour|שעה|שעות|h\b)', query, re.I)
            if m: hours = int(m.group(1))
            data = secops_list_alerts(hours_back=hours)
            alerts = data.get("alerts", data.get("detections", []))
            steps.append({"tool": "secops_list_alerts", "hours_back": hours})
            result_html = _bot_fmt_alerts(alerts, hours)

        elif intent == "rules":
            data = secops_list_rules(page_size=100)
            rules = data.get("rules", [])
            steps.append({"tool": "secops_list_rules"})
            result_html = _bot_fmt_rules(rules)

        elif intent == "cases":
            data = secops_list_cases(page_size=50, state_filter="OPEN")
            cases = data.get("cases", [])
            steps.append({"tool": "secops_list_cases", "state": "OPEN"})
            result_html = _bot_fmt_cases(cases)

        elif intent == "retrohunt":
            data = secops_list_rules(page_size=100)
            rules = data.get("rules", [])
            steps.append({"tool": "secops_list_rules"})
            result_html = _bot_fmt_retrohunt_prompt(rules, query)

        elif intent == "ioc_manage":
            data = secops_list_reference_lists(page_size=50)
            lists_ = data.get("referenceLists", [])
            steps.append({"tool": "secops_list_reference_lists"})
            result_html = _bot_fmt_ref_lists(lists_, query)

        else:  # report — run all in parallel
            with _cf_bot.ThreadPoolExecutor(max_workers=3) as ex:
                f_rules  = ex.submit(secops_list_rules, 100)
                f_alerts = ex.submit(secops_list_alerts, 24)
                f_cases  = ex.submit(secops_list_cases, 20, "OPEN")
            rules   = f_rules.result().get("rules", [])
            alerts  = f_alerts.result().get("alerts", f_alerts.result().get("detections", []))
            cases   = f_cases.result().get("cases", [])
            steps = [{"tool":"secops_list_rules"},{"tool":"secops_list_alerts"},{"tool":"secops_list_cases"}]
            result_html = _bot_fmt_report(rules, alerts, cases)

        return jsonify({"ok": True, "intent": intent, "steps": steps, "html": result_html})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "intent": intent})


def _sev_badge(sev):
    colors = {"CRITICAL":"#f85149","HIGH":"#e3b341","MEDIUM":"#58a6ff","LOW":"#39d353"}
    c = colors.get(str(sev).upper(), "#8b949e")
    return f'<span style="background:{c}20;color:{c};border:1px solid {c}40;border-radius:4px;padding:1px 6px;font-size:11px;font-weight:600">{sev}</span>'

def _bot_fmt_events(events, query):
    if not events:
        return f'<div class="bot-empty">🔍 No events found for: <code>{query}</code></div>'
    rows = ""
    for e in events[:20]:
        meta = e.get("metadata", {})
        princ = e.get("principal", {})
        tgt = e.get("target", {})
        sr = e.get("securityResult", [{}])
        sev = sr[0].get("severity","") if isinstance(sr,list) and sr else ""
        ts = meta.get("eventTimestamp","")[:19].replace("T"," ")
        etype = meta.get("eventType","")
        ip = princ.get("ip",[""])[0] if isinstance(princ.get("ip"),list) else princ.get("ip","")
        user = princ.get("user",{}).get("userid","")
        action = sr[0].get("action","") if isinstance(sr,list) and sr else ""
        rows += f'<tr><td>{ts}</td><td><code>{etype}</code></td><td>{ip}</td><td>{user}</td><td>{_sev_badge(sev) if sev else ""}</td><td>{action}</td></tr>'
    return f'''<div class="bot-section">
<div class="bot-header">🔍 UDM Search Results — <code>{query}</code></div>
<div class="bot-stat">Found <strong>{len(events)}</strong> events (showing top 20)</div>
<table class="bot-table"><thead><tr><th>Time</th><th>Type</th><th>Source IP</th><th>User</th><th>Severity</th><th>Action</th></tr></thead>
<tbody>{rows}</tbody></table></div>'''

def _bot_fmt_alerts(alerts, hours):
    if not alerts:
        return f'<div class="bot-empty">✅ No alerts in the last {hours} hours.</div>'
    by_sev = {}
    for a in alerts:
        s = str(a.get("severity", a.get("riskScore","UNKNOWN"))).upper()
        by_sev[s] = by_sev.get(s,0) + 1
    badges = "".join(f'{_sev_badge(s)} <strong>{c}</strong>&nbsp;&nbsp;' for s,c in sorted(by_sev.items(), key=lambda x:-x[1]))
    rows = ""
    for a in alerts[:15]:
        det = a.get("detection",[])
        rule = det[0].get("ruleName","") if isinstance(det,list) and det else a.get("ruleName","Unknown")
        sev = str(a.get("severity", a.get("riskScore",""))).upper()
        state = a.get("feedbackSummary",{}).get("status", a.get("state",""))
        ts = a.get("detectionTimestamp","")[:19].replace("T"," ")
        rows += f'<tr><td>{ts}</td><td>{rule}</td><td>{_sev_badge(sev)}</td><td>{state}</td></tr>'
    return f'''<div class="bot-section">
<div class="bot-header">🚨 Alert Summary — last {hours}h</div>
<div class="bot-stat">{len(alerts)} total &nbsp; {badges}</div>
<table class="bot-table"><thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>State</th></tr></thead>
<tbody>{rows}</tbody></table></div>'''

def _bot_fmt_rules(rules):
    enabled = [r for r in rules if r.get("deploymentState","").upper() == "ENABLED"]
    live = [r for r in rules if "LIVE" in r.get("allowedRunFrequencies",[])]
    rows = ""
    for r in rules[:30]:
        name = r.get("displayName", r.get("name","").split("/")[-1])
        state = r.get("deploymentState","")
        dot = '<span style="color:#39d353">●</span>' if state=="ENABLED" else '<span style="color:#8b949e">●</span>'
        rtype = r.get("type","")
        sev = r.get("metaData",{}).get("severity","") if isinstance(r.get("metaData"),dict) else ""
        rows += f'<tr><td>{dot}</td><td>{name}</td><td>{rtype}</td><td>{_sev_badge(sev) if sev else ""}</td></tr>'
    return f'''<div class="bot-section">
<div class="bot-header">📋 Detection Rules Overview</div>
<div class="bot-stat"><strong>{len(rules)}</strong> total &nbsp; <strong style="color:#39d353">{len(enabled)}</strong> enabled &nbsp; <strong style="color:#58a6ff">{len(live)}</strong> LIVE</div>
<table class="bot-table"><thead><tr><th></th><th>Name</th><th>Type</th><th>Severity</th></tr></thead>
<tbody>{rows}</tbody></table></div>'''

def _bot_fmt_cases(cases):
    if not cases:
        return '<div class="bot-empty">📁 No open cases found.</div>'
    rows = ""
    pri_colors = {"CRITICAL":"#f85149","HIGH":"#e3b341","MEDIUM":"#58a6ff","LOW":"#39d353"}
    for c in cases[:20]:
        cid = c.get("displayId", c.get("name","").split("/")[-1])
        name = c.get("displayName", c.get("name",""))
        pri = c.get("priority","")
        stage = c.get("stage","")
        assignee = c.get("assignee","—")
        col = pri_colors.get(pri,"#8b949e")
        rows += f'<tr><td><code>{cid}</code></td><td>{name[:50]}</td><td><span style="color:{col};font-weight:600">{pri}</span></td><td>{stage}</td><td>{assignee}</td></tr>'
    return f'''<div class="bot-section">
<div class="bot-header">📁 Open Cases</div>
<div class="bot-stat"><strong>{len(cases)}</strong> open cases</div>
<table class="bot-table"><thead><tr><th>ID</th><th>Name</th><th>Priority</th><th>Stage</th><th>Assignee</th></tr></thead>
<tbody>{rows}</tbody></table></div>'''

def _bot_fmt_ref_lists(lists_, query):
    rows = ""
    for l in lists_[:20]:
        nm = l.get("name","").split("/")[-1]
        desc = l.get("description","")
        stype = l.get("syntaxType","")
        cnt = len(l.get("lines",[]))
        rows += f'<tr><td><code>{nm}</code></td><td>{desc[:40]}</td><td>{stype}</td><td>{cnt}</td></tr>'
    return f'''<div class="bot-section">
<div class="bot-header">📝 Reference Lists (IOC / Blocklists)</div>
<div class="bot-stat"><strong>{len(lists_)}</strong> lists found</div>
<table class="bot-table"><thead><tr><th>Name</th><th>Description</th><th>Type</th><th>Entries</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="bot-tip">💡 Use <strong>Create Reference List</strong> or <strong>Update Reference List</strong> from the sidebar to manage entries.</div></div>'''

def _bot_fmt_retrohunt_prompt(rules, query):
    rows = ""
    for r in rules[:20]:
        name = r.get("displayName", r.get("name","").split("/")[-1])
        rid = r.get("name","").split("/")[-1]
        rows += f'<tr><td><code>{rid}</code></td><td>{name}</td><td>{r.get("deploymentState","")}</td></tr>'
    return f'''<div class="bot-section">
<div class="bot-header">⏮️ Retrohunt — Available Rules</div>
<div class="bot-stat">Select a rule below, then use <strong>Create Retrohunt</strong> from the sidebar.</div>
<table class="bot-table"><thead><tr><th>Rule ID</th><th>Name</th><th>State</th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="bot-tip">💡 Paste the Rule ID into <strong>Create Retrohunt</strong> with your desired time range.</div></div>'''

def _bot_fmt_report(rules, alerts, cases):
    from datetime import date
    today = date.today().strftime("%Y-%m-%d")
    enabled = sum(1 for r in rules if r.get("deploymentState","").upper()=="ENABLED")
    live = sum(1 for r in rules if "LIVE" in r.get("allowedRunFrequencies",[]))
    by_sev = {}
    for a in alerts:
        s = str(a.get("severity","UNKNOWN")).upper()
        by_sev[s] = by_sev.get(s,0)+1
    crit = by_sev.get("CRITICAL",0)
    high = by_sev.get("HIGH",0)
    sev_html = "".join(f'{_sev_badge(s)} <strong>{c}</strong>&nbsp;&nbsp;' for s,c in sorted(by_sev.items()))
    top_cases = ""
    for c in cases[:5]:
        cid = c.get("displayId","")
        nm = c.get("displayName","")[:40]
        pri = c.get("priority","")
        col = {"CRITICAL":"#f85149","HIGH":"#e3b341","MEDIUM":"#58a6ff","LOW":"#39d353"}.get(pri,"#8b949e")
        top_cases += f'<li><code>{cid}</code> {nm} — <span style="color:{col}">{pri}</span></li>'
    actions = []
    if crit > 0: actions.append(f"⚠️ {crit} CRITICAL alerts require immediate investigation")
    if high > 5: actions.append(f"🔍 {high} HIGH alerts — review for false positives")
    if len(cases) > 10: actions.append("📁 High open case volume — consider bulk triage")
    if not actions: actions.append("✅ Security posture looks normal")
    actions_html = "".join(f'<li>{a}</li>' for a in actions)
    return f'''<div class="bot-section">
<div class="bot-header">📊 SOC Daily Report — {today}</div>
<div class="bot-kpis">
  <div class="bot-kpi"><div class="bot-kpi-val">{len(rules)}</div><div class="bot-kpi-lbl">Total Rules</div></div>
  <div class="bot-kpi"><div class="bot-kpi-val" style="color:#39d353">{enabled}</div><div class="bot-kpi-lbl">Enabled</div></div>
  <div class="bot-kpi"><div class="bot-kpi-val" style="color:#58a6ff">{live}</div><div class="bot-kpi-lbl">LIVE</div></div>
  <div class="bot-kpi"><div class="bot-kpi-val" style="color:#f85149">{len(alerts)}</div><div class="bot-kpi-lbl">24h Alerts</div></div>
  <div class="bot-kpi"><div class="bot-kpi-val" style="color:#e3b341">{len(cases)}</div><div class="bot-kpi-lbl">Open Cases</div></div>
</div>
<div class="bot-sub">Alert Severity Breakdown</div>
<div style="margin:6px 0 12px">{sev_html or "No alerts"}</div>
{'<div class="bot-sub">Open Cases (top 5)</div><ul class="bot-list">' + top_cases + '</ul>' if top_cases else ''}
<div class="bot-sub">Recommended Actions</div>
<ul class="bot-list">{actions_html}</ul>
</div>'''


# ── HTML ─────────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Google SecOps Dashboard</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css">
<style>
:root{
  --bg:        #0d1117;
  --surface:   #161b22;
  --elevated:  #21262d;
  --border:    #30363d;
  --green:     #39d353;
  --red:       #f85149;
  --blue:      #58a6ff;
  --yellow:    #e3b341;
  --purple:    #bc8cff;
  --text:      #c9d1d9;
  --muted:     #8b949e;
  --mono:      'JetBrains Mono','Fira Code','Cascadia Code',monospace;
  --ui:        'Inter',system-ui,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--ui);font-size:14px;display:flex;flex-direction:column;height:100vh;overflow:hidden}

/* HEADER */
header{background:var(--surface);border-bottom:1px solid var(--border);padding:0 20px;height:52px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0;z-index:10}
.header-left{display:flex;align-items:center;gap:12px}
.logo{font-size:18px;font-weight:700;color:var(--text);letter-spacing:-0.3px}
.logo span{color:var(--blue)}
#status-badge{display:flex;align-items:center;gap:6px;padding:4px 10px;border-radius:20px;background:var(--elevated);border:1px solid var(--border);font-size:12px;cursor:pointer}
#status-dot{width:8px;height:8px;border-radius:50%;background:var(--muted);transition:background .3s}
#status-dot.ok{background:var(--green);box-shadow:0 0 6px var(--green)}
#status-dot.error{background:var(--red);box-shadow:0 0 6px var(--red)}
#status-text{color:var(--muted);font-size:12px}
.header-right{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px}

/* LAYOUT */
.main-layout{display:flex;flex:1;overflow:hidden}

/* SIDEBAR */
aside{width:220px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow-y:auto;flex-shrink:0}
.sidebar-section{padding:12px 8px 4px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--muted)}
.tool-btn{display:flex;align-items:center;gap:10px;width:100%;padding:8px 12px;background:none;border:none;border-radius:6px;color:var(--text);font-size:13px;font-family:var(--ui);cursor:pointer;text-align:left;transition:background .15s}
.tool-btn:hover{background:var(--elevated)}
.tool-btn.active{background:var(--elevated);color:var(--blue)}
.tool-btn .icon{font-size:16px;width:20px;text-align:center;flex-shrink:0}
.tool-btn .badge{margin-left:auto;background:var(--elevated);border:1px solid var(--border);border-radius:10px;padding:1px 6px;font-size:10px;color:var(--muted)}
.tool-btn.active .badge{border-color:var(--blue);color:var(--blue)}

/* CONTENT */
.content{flex:1;display:flex;flex-direction:column;overflow:hidden}

/* BOT PANEL */
.bot-panel{display:flex;flex-direction:column;flex:1;overflow:hidden;background:var(--bg)}
.bot-messages{flex:1;overflow-y:auto;padding:16px 24px;display:flex;flex-direction:column;gap:12px}
.bot-input-row{display:flex;gap:8px;padding:12px 24px;background:var(--surface);border-top:1px solid var(--border)}
.bot-input{flex:1;background:var(--elevated);border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:8px;font-size:13px;font-family:var(--ui);outline:none;transition:border .2s}
.bot-input:focus{border-color:var(--blue)}
.bot-send{background:var(--blue);color:#000;border:none;border-radius:8px;padding:10px 18px;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .2s}
.bot-send:hover{opacity:.85}
.bot-send:disabled{opacity:.4;cursor:default}
.bot-msg{display:flex;gap:10px}
.bot-msg-user{flex-direction:row-reverse}
.bot-bubble{max-width:80%;padding:10px 14px;border-radius:10px;font-size:13px;line-height:1.5}
.bot-bubble-user{background:var(--blue);color:#000;border-radius:10px 10px 2px 10px}
.bot-bubble-bot{background:var(--elevated);border:1px solid var(--border);color:var(--text);border-radius:10px 10px 10px 2px}
.bot-avatar{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0;margin-top:2px}
.bot-avatar-user{background:var(--blue);color:#000}
.bot-avatar-bot{background:var(--elevated);border:1px solid var(--border)}
.bot-thinking{display:flex;gap:4px;align-items:center;padding:10px 14px}
.bot-dot{width:6px;height:6px;border-radius:50%;background:var(--muted);animation:botdot 1.2s infinite}
.bot-dot:nth-child(2){animation-delay:.2s}
.bot-dot:nth-child(3){animation-delay:.4s}
@keyframes botdot{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-6px)}}
/* Bot result HTML */
.bot-section{padding:4px 0}
.bot-header{font-size:15px;font-weight:700;color:var(--text);margin-bottom:8px}
.bot-stat{font-size:13px;color:var(--muted);margin-bottom:10px}
.bot-sub{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin:10px 0 4px}
.bot-kpis{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.bot-kpi{background:var(--elevated);border:1px solid var(--border);border-radius:8px;padding:10px 16px;text-align:center;min-width:80px}
.bot-kpi-val{font-size:22px;font-weight:700;color:var(--text)}
.bot-kpi-lbl{font-size:11px;color:var(--muted);margin-top:2px}
.bot-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px}
.bot-table th{text-align:left;padding:6px 8px;color:var(--muted);border-bottom:1px solid var(--border);font-weight:600;font-size:11px;text-transform:uppercase}
.bot-table td{padding:5px 8px;border-bottom:1px solid var(--border)20;color:var(--text)}
.bot-table tr:hover td{background:var(--elevated)50}
.bot-empty{padding:24px;text-align:center;color:var(--muted);font-size:13px}
.bot-tip{margin-top:12px;padding:8px 12px;background:var(--blue)15;border:1px solid var(--blue)30;border-radius:6px;font-size:12px;color:var(--blue)}
.bot-list{padding-left:18px;font-size:13px;line-height:1.8}
.bot-steps{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.bot-step-chip{background:var(--elevated);border:1px solid var(--border);border-radius:12px;padding:2px 10px;font-size:11px;color:var(--muted);font-family:var(--mono)}
/* FORM PANEL */
.form-panel{padding:20px 24px;background:var(--surface);border-bottom:1px solid var(--border);overflow-y:auto;max-height:45vh;flex-shrink:0}
.form-title{font-size:16px;font-weight:600;color:var(--text);margin-bottom:4px;display:flex;align-items:center;gap:8px}
.form-desc{font-size:12px;color:var(--muted);margin-bottom:16px}
.field-group{margin-bottom:14px}
label{display:block;font-size:12px;color:var(--muted);margin-bottom:4px;font-weight:500}
input[type=text],input[type=number],select,textarea{width:100%;background:var(--elevated);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;padding:8px 10px;outline:none;transition:border-color .15s;font-family:var(--ui)}
textarea{font-family:var(--mono);font-size:12px;resize:vertical}
input:focus,textarea:focus,select:focus{border-color:var(--blue)}
select option{background:var(--elevated)}
.checkbox-row{display:flex;align-items:center;gap:8px;padding:8px 0}
.checkbox-row input{width:auto}
.checkbox-row label{margin:0;color:var(--text)}
.form-actions{display:flex;gap:10px;margin-top:16px}
.btn-run{background:var(--blue);color:#0d1117;border:none;border-radius:6px;padding:8px 20px;font-size:13px;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:6px;transition:opacity .15s}
.btn-run:hover{opacity:.85}
.btn-run:disabled{opacity:.4;cursor:not-allowed}
.btn-clear{background:var(--elevated);color:var(--muted);border:1px solid var(--border);border-radius:6px;padding:8px 14px;font-size:13px;cursor:pointer;transition:background .15s}
.btn-clear:hover{background:var(--border)}
.empty-state{color:var(--muted);font-size:14px;padding:40px;text-align:center}
.empty-state .big-icon{font-size:48px;margin-bottom:12px}

/* RESULT PANEL */
.result-panel{flex:1;overflow-y:auto;overflow-x:hidden;padding:20px 24px}
#result-wrap{min-height:100px}
.result-meta{display:flex;align-items:center;gap:12px;margin-bottom:12px;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:8px}
.result-status{padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600;text-transform:uppercase}
.result-status.ok{background:rgba(57,211,83,.15);color:var(--green);border:1px solid rgba(57,211,83,.3)}
.result-status.error{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.result-time{color:var(--muted);font-size:12px}
.result-count{color:var(--blue);font-size:12px;font-weight:600}
.code-wrap{background:var(--elevated);border:1px solid var(--border);border-radius:8px;overflow:hidden;position:relative}
.code-header{display:flex;align-items:center;justify-content:space-between;padding:8px 14px;background:var(--surface);border-bottom:1px solid var(--border);font-size:11px;color:var(--muted)}
.btn-copy{background:var(--elevated);border:1px solid var(--border);border-radius:4px;color:var(--muted);padding:2px 8px;font-size:11px;cursor:pointer}
.btn-copy:hover{color:var(--text)}
.code-wrap pre{margin:0!important;background:var(--elevated)!important;border-radius:0!important;max-height:400px;overflow-y:auto}
.rules-table{width:100%;border-collapse:collapse;margin-bottom:16px;font-size:12px}
.rules-table th{background:var(--surface);padding:8px 12px;text-align:left;color:var(--muted);font-weight:600;border-bottom:1px solid var(--border)}
.rules-table td{padding:8px 12px;border-bottom:1px solid var(--border)}
.rules-table tr:hover td{background:var(--elevated)}
.rule-id-link{color:var(--blue);cursor:pointer;font-family:var(--mono);font-size:11px}
.rule-id-link:hover{text-decoration:underline}
.pill{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:500}
.pill-green{background:rgba(57,211,83,.15);color:var(--green)}
.pill-red{background:rgba(248,81,73,.15);color:var(--red)}
.pill-muted{background:var(--elevated);color:var(--muted)}
.conn-card{display:flex;flex-direction:column;gap:8px;background:var(--elevated);border:1px solid var(--border);border-radius:10px;padding:20px;max-width:400px}
.conn-card .field{display:flex;justify-content:space-between;font-size:13px}
.conn-card .field .key{color:var(--muted)}
.conn-card .field .val{color:var(--text);font-family:var(--mono);font-size:12px}
.section-title{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:16px 0 8px}

/* SUB-TABS (connection / reference) */
.sub-tabs{display:flex;gap:6px;margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:8px}
.sub-tab{background:transparent;border:1px solid var(--border);border-radius:6px;color:var(--muted);padding:5px 14px;font-size:12px;cursor:pointer;transition:all .15s}
.sub-tab.active{background:var(--blue);border-color:var(--blue);color:#fff}
.sub-tab:hover:not(.active){color:var(--text)}

/* STEP PIPELINE */
.step-pipeline{display:flex;flex-direction:column;gap:0}
.step-row{display:flex;align-items:flex-start;gap:10px;padding:10px 14px;background:var(--elevated);border:1px solid var(--border);border-radius:8px}
.step-idx{min-width:22px;height:22px;border-radius:50%;background:var(--blue);color:#fff;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}
.step-body{flex:1;min-width:0}
.step-name{font-size:12px;font-weight:600;color:var(--text);margin-bottom:3px}
.step-detail{font-size:11px;color:var(--muted);font-family:var(--mono);word-break:break-all}
.step-ms{font-size:11px;font-family:var(--mono);white-space:nowrap;padding-top:2px}
.step-connector{width:2px;height:8px;background:var(--border);margin:0 0 0 21px}

/* CONFIG GRID */
.config-grid{display:flex;flex-direction:column;gap:5px}
.config-row{display:flex;gap:10px;padding:7px 12px;background:var(--elevated);border:1px solid var(--border);border-radius:6px;align-items:flex-start}
.config-key{min-width:155px;font-size:11px;font-weight:600;color:var(--text);flex-shrink:0}
.config-val{font-family:var(--mono);font-size:11px;color:var(--blue);word-break:break-all;flex:1}

/* REFERENCE CARDS */
.ref-card{background:var(--elevated);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:12px}
.ref-card-header{padding:8px 14px;background:rgba(255,255,255,.04);font-size:12px;font-weight:600;color:var(--text);border-bottom:1px solid var(--border)}
.ref-card-body{padding:10px 14px;display:flex;flex-direction:column;gap:6px}
.ref-env-row{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.ref-env-key{font-family:var(--mono);font-size:11px;color:var(--yellow);min-width:210px;white-space:nowrap}
.ref-env-desc{font-size:11px;color:var(--muted)}

/* AUTH STEP CARDS */
.auth-step-card{display:flex;gap:8px;align-items:center;background:var(--elevated);border:1px solid var(--border);border-radius:8px;padding:10px 12px;flex:1;min-width:130px}
.auth-step-num{width:22px;height:22px;border-radius:50%;background:var(--purple);color:#fff;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}

/* EXPLORER */
.explorer-search{width:100%;box-sizing:border-box;background:var(--elevated);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:13px;padding:9px 12px;outline:none;transition:border .15s;margin-bottom:10px}
.explorer-search:focus{border-color:var(--blue)}
.q-chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px}
.q-chip{background:var(--elevated);border:1px solid var(--border);border-radius:14px;color:var(--muted);font-size:11px;padding:4px 10px;cursor:pointer;transition:all .15s;white-space:nowrap}
.q-chip:hover{border-color:var(--blue);color:var(--blue)}
.q-chip.active{background:rgba(88,166,255,.15);border-color:var(--blue);color:var(--blue)}
.tool-kb-card{background:var(--elevated);border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin-bottom:8px;transition:border .15s}
.tool-kb-card:hover{border-color:rgba(88,166,255,.4)}
.tool-kb-card.hidden{display:none}
.tool-kb-header{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.tool-kb-name{font-family:var(--mono);font-size:12px;color:var(--blue);font-weight:600}
.tool-kb-ep{font-family:var(--mono);font-size:10px;color:var(--muted);margin-bottom:6px}
.tool-kb-desc{font-size:11px;color:var(--text);margin-bottom:4px}
.tool-kb-desc-he{font-size:10px;color:var(--muted);direction:rtl;text-align:right;margin-bottom:8px}
.tool-kb-io{display:flex;gap:10px;flex-wrap:wrap}
.tool-kb-io-box{flex:1;min-width:110px;background:var(--surface);border-radius:6px;padding:7px 9px}
.tool-kb-io-title{font-size:10px;color:var(--muted);font-weight:600;margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px}
.tool-kb-io-item{font-size:10px;font-family:var(--mono);color:var(--text);padding:1px 0}
.udm-section-card{background:var(--elevated);border:1px solid var(--border);border-radius:8px;margin-bottom:10px;overflow:hidden}
.udm-section-card.hidden{display:none}
.udm-section-hdr{padding:9px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border)}
.udm-section-title{font-size:12px;font-weight:600;color:var(--text)}
.udm-section-desc{font-size:11px;color:var(--muted)}
.udm-field-row{display:flex;gap:8px;padding:6px 14px;border-bottom:1px solid rgba(255,255,255,.04);align-items:baseline;flex-wrap:wrap}
.udm-field-row:last-child{border-bottom:none}
.udm-field-row.hidden{display:none}
.udm-field-name{font-family:var(--mono);font-size:11px;color:var(--blue);min-width:220px;flex-shrink:0}
.udm-field-he{font-size:10px;color:var(--yellow);min-width:80px;flex-shrink:0}
.udm-field-desc{font-size:11px;color:var(--muted);flex:1}
.ai-cap-row{display:flex;gap:10px;padding:9px 14px;border-bottom:1px solid rgba(255,255,255,.04);align-items:flex-start}
.ai-cap-row:last-child{border-bottom:none}
.ai-cap-icon{font-size:16px;flex-shrink:0;width:22px;text-align:center}
.ai-cap-title{font-size:12px;font-weight:600;color:var(--text);margin-bottom:2px}
.ai-cap-en{font-size:11px;color:var(--muted)}
.ai-cap-he{font-size:10px;color:var(--muted);direction:rtl;text-align:right}
.udm-eg-row{display:flex;gap:10px;padding:7px 14px;border-bottom:1px solid rgba(255,255,255,.04);align-items:baseline;flex-wrap:wrap}
.udm-eg-row:last-child{border-bottom:none}
.udm-eg-desc{font-size:11px;color:var(--text);min-width:140px;flex-shrink:0}
.udm-eg-q{font-family:var(--mono);font-size:10px;color:var(--green);flex:1;word-break:break-all}
/* FUNCTION REFERENCE CARDS */
.func-list{display:flex;flex-direction:column;gap:7px;margin-top:8px}
.func-card{background:var(--elevated);border:1px solid var(--border);border-radius:7px;padding:10px 12px}
.func-card-top{display:flex;align-items:center;flex-wrap:wrap;gap:6px;margin-bottom:4px}
.func-card-name{font-family:var(--mono);font-size:11px;color:var(--blue)}
.func-card-ep{font-family:var(--mono);font-size:10px;color:var(--muted);margin-bottom:4px}
.func-card-desc{font-size:11px;color:var(--text);margin-bottom:2px}
.func-card-he{font-size:10px;color:var(--muted);direction:rtl;text-align:right}
.http-method{padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.3px}

/* HISTORY */
.history-bar{background:var(--surface);border-top:1px solid var(--border);flex-shrink:0}
.history-header{display:flex;align-items:center;justify-content:space-between;padding:6px 16px;cursor:pointer;user-select:none}
.history-header span{font-size:12px;font-weight:600;color:var(--muted)}
.history-toggle{color:var(--muted);font-size:11px}
.history-list{max-height:0;overflow:hidden;transition:max-height .25s ease}
.history-list.open{max-height:120px;overflow-y:auto}
.history-item{display:flex;align-items:center;gap:10px;padding:5px 16px;font-size:12px;border-top:1px solid var(--border);font-family:var(--mono)}
.history-item .ts{color:var(--muted);width:60px;flex-shrink:0}
.history-item .tool-name{color:var(--blue);min-width:160px}
.history-item .dur{color:var(--muted);margin-left:auto}
.history-item .st.ok{color:var(--green)}
.history-item .st.error{color:var(--red)}

/* SPINNER */
.spin{display:inline-block;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* STAT CARDS */
.stat-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.stat-card{background:var(--elevated);border:1px solid var(--border);border-radius:8px;padding:14px 20px;min-width:90px;text-align:center}
.stat-card.green{border-color:rgba(57,211,83,.3)}
.stat-card.muted{opacity:.7}
.stat-num{font-size:26px;font-weight:700;color:var(--text);line-height:1}
.stat-label{font-size:11px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.5px}

/* BREAKDOWN BARS */
.breakdown-list{margin-bottom:16px}
.breakdown-row{display:flex;align-items:center;gap:10px;padding:4px 0}
.breakdown-label{min-width:170px;max-width:170px;font-size:12px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.breakdown-bar-wrap{flex:1;height:8px;background:var(--surface);border-radius:4px;overflow:hidden;border:1px solid var(--border)}
.breakdown-bar{height:100%;border-radius:4px;transition:width .4s ease}
.breakdown-count{min-width:28px;text-align:right;font-size:12px;color:var(--muted);font-family:var(--mono)}

/* RESULT TABS */
.result-tabs{display:flex;background:var(--surface);border-bottom:1px solid var(--border);flex-shrink:0;padding:0 4px}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;padding:9px 16px;font-size:13px;color:var(--muted);cursor:pointer;font-family:var(--ui);transition:color .15s;margin-bottom:-1px}
.tab-btn:hover{color:var(--text)}
.tab-btn.active{color:var(--blue);border-bottom-color:var(--blue)}

/* ACTIVITY LOG */
.activity-log{display:flex;flex-direction:column;gap:8px}
.activity-item{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 14px}
.activity-header{display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap}
.activity-ts{color:var(--muted);font-family:var(--mono);font-size:11px;width:95px;flex-shrink:0}
.activity-method{font-weight:700;font-family:var(--mono);font-size:11px;padding:1px 7px;border-radius:3px;flex-shrink:0}
.activity-method.GET{color:#39d353;background:rgba(57,211,83,.12)}
.activity-method.POST{color:#58a6ff;background:rgba(88,166,255,.12)}
.activity-method.PATCH{color:#e3b341;background:rgba(227,179,65,.12)}
.activity-endpoint{color:var(--text);font-family:var(--mono);font-size:12px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.activity-dur{color:var(--muted);font-size:11px;flex-shrink:0}
.activity-url{color:var(--muted);font-family:var(--mono);font-size:10px;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:default}
.activity-url:hover{white-space:normal;word-break:break-all}
.activity-params{color:var(--muted);font-size:11px;margin-top:3px;font-family:var(--mono)}
.activity-error{color:var(--red);font-size:11px;margin-top:4px}
.activity-status{padding:1px 6px!important;font-size:10px!important}

/* TIMELINE CHART */
.timeline-chart{display:flex;gap:4px;align-items:flex-end;padding:12px 12px 0;background:var(--elevated);border:1px solid var(--border);border-radius:8px;margin-bottom:16px;height:160px;overflow-x:auto}
.tl-col{display:flex;flex-direction:column;align-items:center;gap:3px;min-width:46px;flex:1;height:100%}
.tl-bar-wrap{flex:1;width:100%;display:flex;align-items:flex-end}
.tl-bar{width:100%;border-radius:4px 4px 0 0;transition:height .4s ease;min-height:3px;cursor:default}
.tl-bar:hover{opacity:.8}
.tl-label{font-size:10px;color:var(--muted);font-family:var(--mono);white-space:nowrap;padding-bottom:6px}
.tl-count{font-size:10px;color:var(--text);font-weight:600;padding-bottom:2px}
.trend-up{color:var(--red)}
.trend-down{color:var(--green)}
.trend-flat{color:var(--muted)}
.insight-box{background:var(--elevated);border:1px solid var(--border);border-left:3px solid var(--blue);border-radius:6px;padding:12px 16px;margin-bottom:12px;font-size:13px;line-height:1.6}
.insight-box .insight-item{color:var(--muted);padding:2px 0}
.insight-box .insight-item span{color:var(--text)}
</style>
</head>
<body>

<header>
  <div class="header-left">
    <div class="logo">Google <span>SecOps</span> Dashboard</div>
    <div id="status-badge" onclick="checkStatus()">
      <div id="status-dot"></div>
      <span id="status-text">Checking...</span>
    </div>
  </div>
  <div class="header-right">
    <span>Google SecOps</span> &nbsp;|&nbsp;
    <span id="project-info">__PROJECT_ID__</span>
  </div>
</header>

<div class="main-layout">
  <aside>
    <div class="sidebar-section">Connectivity</div>
    <button class="tool-btn" onclick="openAnalysis('connection', this)">
      <span class="icon">🔌</span> Connection Test
    </button>

    <div class="sidebar-section">Detection Rules</div>
    <button class="tool-btn" onclick="selectTool('list_rules', this)">
      <span class="icon">📋</span> List Rules
    </button>
    <button class="tool-btn" onclick="selectTool('get_rule', this)">
      <span class="icon">🔍</span> Get Rule
    </button>
    <button class="tool-btn" onclick="selectTool('create_rule', this)">
      <span class="icon">✏️</span> Create Rule
    </button>
    <button class="tool-btn" onclick="selectTool('validate_rule', this)">
      <span class="icon">✅</span> Validate Rule
    </button>
    <button class="tool-btn" onclick="selectTool('toggle_rule', this)">
      <span class="icon">⚡</span> Toggle Rule
    </button>

    <div class="sidebar-section">Alerts & Detections</div>
    <button class="tool-btn" onclick="selectTool('list_detections', this)">
      <span class="icon">🎯</span> List Detections
    </button>
    <button class="tool-btn" onclick="selectTool('list_alerts', this)">
      <span class="icon">🚨</span> List Alerts
    </button>

    <div class="sidebar-section">Intelligence</div>
    <button class="tool-btn" onclick="selectTool('udm_search', this)">
      <span class="icon">🔎</span> UDM Search
    </button>
    <button class="tool-btn" onclick="selectTool('list_reference_lists', this)">
      <span class="icon">📑</span> Reference Lists
    </button>

    <div class="sidebar-section">⏮️ Retrohunts</div>
    <button class="tool-btn" onclick="selectTool('create_retrohunt', this)">
      <span class="icon">🔁</span> Create Retrohunt
    </button>
    <button class="tool-btn" onclick="selectTool('list_retrohunts', this)">
      <span class="icon">📋</span> List Retrohunts
    </button>
    <button class="tool-btn" onclick="selectTool('get_retrohunt', this)">
      <span class="icon">🔍</span> Get Retrohunt
    </button>

    <div class="sidebar-section">📁 Cases (SOAR)</div>
    <button class="tool-btn" onclick="selectTool('list_cases', this)">
      <span class="icon">📂</span> List Cases
    </button>
    <button class="tool-btn" onclick="selectTool('get_case', this)">
      <span class="icon">🔍</span> Get Case
    </button>
    <button class="tool-btn" onclick="selectTool('update_case', this)">
      <span class="icon">✏️</span> Update Case
    </button>
    <button class="tool-btn" onclick="selectTool('add_case_comment', this)">
      <span class="icon">💬</span> Add Comment
    </button>
    <button class="tool-btn" onclick="selectTool('list_case_alerts', this)">
      <span class="icon">🚨</span> Case Alerts
    </button>
    <button class="tool-btn" onclick="selectTool('generate_case_report', this)">
      <span class="icon">📄</span> Generate Report
    </button>
    <button class="tool-btn" onclick="selectTool('merge_cases', this)">
      <span class="icon">🔀</span> Merge Cases
    </button>
    <button class="tool-btn" onclick="selectTool('bulk_close_cases', this)">
      <span class="icon">✅</span> Bulk Close
    </button>

    <div class="sidebar-section">📝 IOC Management</div>
    <button class="tool-btn" onclick="selectTool('list_reference_lists', this)">
      <span class="icon">📑</span> List All
    </button>
    <button class="tool-btn" onclick="selectTool('create_reference_list', this)">
      <span class="icon">➕</span> Create List
    </button>
    <button class="tool-btn" onclick="selectTool('update_reference_list', this)">
      <span class="icon">✏️</span> Update List
    </button>
    <button class="tool-btn" onclick="selectTool('delete_reference_list', this)">
      <span class="icon">🗑️</span> Delete List
    </button>

    <div class="sidebar-section">🧠 Analysis</div>
    <button class="tool-btn" onclick="openAnalysis('rules', this)">
      <span class="icon">📊</span> Analyze All Rules
    </button>
    <button class="tool-btn" onclick="openAnalysis('alerts', this)">
      <span class="icon">🔍</span> 48h Alert Analysis
    </button>
    <button class="tool-btn" onclick="openAnalysis('timeline', this)">
      <span class="icon">📅</span> Timeline &amp; Trends
    </button>
    <button class="tool-btn" onclick="openAnalysis('intelligence', this)">
      <span class="icon">🔬</span> Intelligence Report
    </button>

    <div class="sidebar-section">🤖 AI Bot</div>
    <button class="tool-btn" onclick="openBot(this)">
      <span class="icon">🧠</span> SOC Assistant
    </button>

    <div class="sidebar-section">🔎 Explorer</div>
    <button class="tool-btn" onclick="openAnalysis('explorer', this)">
      <span class="icon">🔎</span> MCP Explorer
    </button>
  </aside>

  <div class="content" id="main-content">
    <!-- Tool mode -->
    <div id="tool-mode" style="display:flex;flex-direction:column;flex:1;overflow:hidden">
      <div class="form-panel" id="form-panel">
        <div class="empty-state">
          <div class="big-icon">🛡️</div>
          <div>Select a tool from the sidebar to get started</div>
        </div>
      </div>
      <div class="result-tabs">
        <button class="tab-btn active" id="tab-results" onclick="switchTab('results', this)">📊 Results</button>
        <button class="tab-btn" id="tab-activity" onclick="switchTab('activity', this)">📡 Activity Log</button>
      </div>
      <div class="result-panel" id="panel-results">
        <div id="result-wrap">
          <div class="empty-state" style="padding:60px">
            <div class="big-icon">📊</div>
            <div>Results will appear here</div>
        </div>
      </div>
    </div>
    <div class="result-panel" id="panel-activity" style="display:none">
      <div id="activity-wrap">
        <div class="empty-state" style="padding:60px">
          <div class="big-icon">📡</div>
          <div>No API calls yet — run a tool to see the trace</div>
        </div>
      </div>
    </div>
  </div>

  <!-- AI Bot mode -->
  <div id="bot-mode" style="display:none;flex-direction:column;flex:1;overflow:hidden">
    <div style="background:var(--surface);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;gap:10px">
      <span style="font-size:18px">🧠</span>
      <div>
        <div style="font-weight:600;font-size:14px">SOC AI Assistant</div>
        <div style="font-size:11px;color:var(--muted)">Ask me anything about your SecOps environment</div>
      </div>
      <button onclick="closeBot()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);padding:4px 12px;border-radius:6px;cursor:pointer;font-size:12px">← Back to Tools</button>
    </div>
    <div class="bot-messages" id="bot-messages">
      <div class="bot-msg">
        <div class="bot-avatar bot-avatar-bot">🧠</div>
        <div class="bot-bubble bot-bubble-bot">
          <strong>SOC Assistant</strong> — powered by Google SecOps API<br><br>
          Ask me in Hebrew or English:<br>
          <span style="color:var(--muted)">• "תן לי דוח על מה שקרה היום"</span><br>
          <span style="color:var(--muted)">• "חפש כניסות כושלות מה-24 שעות האחרונות"</span><br>
          <span style="color:var(--muted)">• "תראה לי תיקים פתוחים בעדיפות גבוהה"</span><br>
          <span style="color:var(--muted)">• "SOC daily report"</span><br>
          <span style="color:var(--muted)">• "show me all detection rules"</span>
        </div>
      </div>
    </div>
    <div class="bot-input-row">
      <input class="bot-input" id="bot-input" type="text" placeholder="שאל אותי על SecOps... / Ask me about SecOps..." onkeydown="if(event.key==='Enter')sendBotMsg()">
      <button class="bot-send" id="bot-send-btn" onclick="sendBotMsg()">Send ▶</button>
    </div>
  </div>
</div>

<div class="history-bar">
  <div class="history-header" onclick="toggleHistory()">
    <span>📜 Command History</span>
    <span class="history-toggle" id="hist-toggle">▲ expand</span>
  </div>
  <div class="history-list" id="history-list"></div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-json.min.js"></script>
<script>
// ── Tool form definitions ────────────────────────────────────────────────────
window.TOOLS = {
  connection_test: {
    title: "Connection Test", icon: "🔌",
    desc: "Verify authentication and API connectivity to Google SecOps.",
    fields: []
  },
  list_rules: {
    title: "List Rules", icon: "📋",
    desc: "List all YARA-L 2.0 detection rules in the SecOps instance.",
    fields: [{name:"page_size",type:"number",label:"Max rules",default:50}]
  },
  get_rule: {
    title: "Get Rule", icon: "🔍",
    desc: "Retrieve a single YARA-L rule and its full source code by ID.",
    fields: [{name:"rule_id",type:"text",label:"Rule ID",placeholder:"ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",required:true}]
  },
  create_rule: {
    title: "Create Rule", icon: "✏️",
    desc: "Create a new YARA-L 2.0 detection rule.",
    fields: [{name:"rule_text",type:"textarea",label:"YARA-L 2.0 Rule Source",rows:14,required:true,
      placeholder:'rule detect_brute_force {\\n  meta:\\n    author = "soc@company.com"\\n    severity = "HIGH"\\n  events:\\n    $e.metadata.event_type = "USER_LOGIN"\\n    $e.security_result.action = "BLOCK"\\n  match:\\n    $e.principal.user.userid over 5m\\n  condition:\\n    #e > 10\\n}'}]
  },
  validate_rule: {
    title: "Validate Rule", icon: "✅",
    desc: "Compile-check a YARA-L rule without saving it.",
    fields: [{name:"rule_text",type:"textarea",label:"YARA-L 2.0 Rule Source",rows:10,required:true,
      placeholder:'rule test_rule {\\n  events:\\n    $e.metadata.event_type = "USER_LOGIN"\\n  condition:\\n    $e\\n}'}]
  },
  toggle_rule: {
    title: "Toggle Rule", icon: "⚡",
    desc: "Enable or disable a detection rule.",
    fields: [
      {name:"rule_id",type:"text",label:"Rule ID",placeholder:"ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",required:true},
      {name:"enabled",type:"checkbox",label:"Enable rule",default:true},
      {name:"alerting",type:"checkbox",label:"Enable alerting",default:true}
    ]
  },
  list_detections: {
    title: "List Detections", icon: "🎯",
    desc: "List detection matches (rule hits) for a specific rule.",
    fields: [
      {name:"rule_id",type:"text",label:"Rule ID",placeholder:"ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",required:true},
      {name:"hours_back",type:"number",label:"Lookback (hours)",default:48}
    ]
  },
  list_alerts: {
    title: "List Alerts", icon: "🚨",
    desc: "List security alerts from the alert feed.",
    fields: [
      {name:"hours_back",type:"number",label:"Lookback (hours)",default:24},
      {name:"state_filter",type:"select",label:"State Filter",options:["","NEW","REVIEWED","CLOSED"]}
    ]
  },
  udm_search: {
    title: "UDM Search", icon: "🔎",
    desc: "Search security events using UDM (Unified Data Model) filter expressions.",
    fields: [
      {name:"query",type:"textarea",label:"UDM Filter Query",rows:3,required:true,
        placeholder:'metadata.event_type = "USER_LOGIN"'},
      {name:"hours_back",type:"number",label:"Lookback (hours)",default:24}
    ]
  },
  list_reference_lists: {
    title: "Reference Lists", icon: "📑",
    desc: "List all reference lists (allowlists / blocklists) in the instance.",
    fields: [{name:"page_size",type:"number",label:"Max lists",default:50}]
  },
  // ── Phase A — Retrohunts ──────────────────────────────────────────────────
  create_retrohunt: {
    title: "Create Retrohunt", icon: "🔁",
    desc: "Run an existing YARA-L rule against historical data to find past threats.",
    fields: [
      {name:"rule_id",type:"text",label:"Rule ID",placeholder:"ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",required:true},
      {name:"hours_back",type:"number",label:"Lookback (hours)",default:168,placeholder:"168 = 7 days"},
      {name:"start_time",type:"text",label:"Start Time (optional)",placeholder:"2024-01-01T00:00:00Z"},
      {name:"end_time",type:"text",label:"End Time (optional)",placeholder:"2024-01-08T00:00:00Z"}
    ]
  },
  list_retrohunts: {
    title: "List Retrohunts", icon: "📋",
    desc: "List all retrohunts for a given rule.",
    fields: [
      {name:"rule_id",type:"text",label:"Rule ID",placeholder:"ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",required:true},
      {name:"page_size",type:"number",label:"Max results",default:50}
    ]
  },
  get_retrohunt: {
    title: "Get Retrohunt", icon: "🔍",
    desc: "Check the status and results of a retrohunt.",
    fields: [
      {name:"rule_id",type:"text",label:"Rule ID",required:true,placeholder:"ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
      {name:"retrohunt_id",type:"text",label:"Retrohunt ID",required:true,placeholder:"oh_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}
    ]
  },
  // ── Phase A — Reference Lists CRUD ───────────────────────────────────────
  create_reference_list: {
    title: "Create Reference List", icon: "➕",
    desc: "Create a new IOC blocklist / allowlist.",
    fields: [
      {name:"name",type:"text",label:"List Name",required:true,placeholder:"malicious_ips"},
      {name:"description",type:"text",label:"Description",placeholder:"Known bad IPs from threat intel"},
      {name:"syntax_type",type:"select",label:"Type",options:["PLAIN_TEXT_STRING","CIDR","REGEX"]},
      {name:"lines",type:"textarea",label:"Entries (one per line)",rows:8,required:true,placeholder:"1.2.3.4\\n5.6.7.8\\n10.0.0.0/8"}
    ]
  },
  update_reference_list: {
    title: "Update Reference List", icon: "✏️",
    desc: "Replace all entries in an existing reference list.",
    fields: [
      {name:"list_id",type:"text",label:"List ID / Name",required:true,placeholder:"malicious_ips"},
      {name:"description",type:"text",label:"New Description (optional)"},
      {name:"lines",type:"textarea",label:"New Entries (one per line, replaces all)",rows:8,required:true,placeholder:"1.2.3.4\\n9.9.9.9"}
    ]
  },
  delete_reference_list: {
    title: "Delete Reference List", icon: "🗑️",
    desc: "Permanently delete a reference list. This action cannot be undone.",
    fields: [
      {name:"list_id",type:"text",label:"List ID / Name",required:true,placeholder:"malicious_ips"}
    ]
  },
  // ── Phase B — Cases ───────────────────────────────────────────────────────
  list_cases: {
    title: "List Cases", icon: "📂",
    desc: "List security cases (SOAR incidents) with optional filters.",
    fields: [
      {name:"page_size",type:"number",label:"Max cases",default:50},
      {name:"state_filter",type:"select",label:"State",options:["","OPEN","CLOSED"]},
      {name:"priority_filter",type:"select",label:"Priority",options:["","LOW","MEDIUM","HIGH","CRITICAL"]}
    ]
  },
  get_case: {
    title: "Get Case", icon: "🔍",
    desc: "Retrieve full details of a specific security case.",
    fields: [
      {name:"case_id",type:"text",label:"Case ID",required:true,placeholder:"1234"}
    ]
  },
  update_case: {
    title: "Update Case", icon: "✏️",
    desc: "Update priority, stage, assignee, or name of a case.",
    fields: [
      {name:"case_id",type:"text",label:"Case ID",required:true,placeholder:"1234"},
      {name:"priority",type:"select",label:"Priority",options:["","LOW","MEDIUM","HIGH","CRITICAL"]},
      {name:"stage",type:"text",label:"Stage",placeholder:"Investigation / Containment / Eradication"},
      {name:"assignee",type:"text",label:"Assignee Email",placeholder:"analyst@company.com"},
      {name:"name",type:"text",label:"Display Name"}
    ]
  },
  add_case_comment: {
    title: "Add Case Comment", icon: "💬",
    desc: "Add an analyst note / comment to a security case.",
    fields: [
      {name:"case_id",type:"text",label:"Case ID",required:true,placeholder:"1234"},
      {name:"comment",type:"textarea",label:"Comment",rows:4,required:true,placeholder:"Investigated source IP — confirmed false positive from internal scanner"}
    ]
  },
  list_case_alerts: {
    title: "Case Alerts", icon: "🚨",
    desc: "List all alerts associated with a specific case.",
    fields: [
      {name:"case_id",type:"text",label:"Case ID",required:true,placeholder:"1234"},
      {name:"page_size",type:"number",label:"Max alerts",default:100}
    ]
  },
  generate_case_report: {
    title: "Generate Case Report", icon: "📄",
    desc: "Generate a full incident report for a case.",
    fields: [
      {name:"case_id",type:"text",label:"Case ID",required:true,placeholder:"1234"}
    ]
  },
  merge_cases: {
    title: "Merge Cases", icon: "🔀",
    desc: "Merge multiple duplicate cases into one.",
    fields: [
      {name:"case_ids",type:"textarea",label:"Case IDs (one per line)",rows:4,required:true,placeholder:"1234\\n5678\\n9012"},
      {name:"target_case_id",type:"text",label:"Target Case ID (merge INTO)",placeholder:"1234 (leave empty for first)"}
    ]
  },
  bulk_close_cases: {
    title: "Bulk Close Cases", icon: "✅",
    desc: "Close multiple cases at once.",
    fields: [
      {name:"case_ids",type:"textarea",label:"Case IDs (one per line)",rows:4,required:true,placeholder:"1234\\n5678"},
      {name:"reason",type:"select",label:"Closure Reason",options:["Resolved","False Positive","Duplicate","Other"]},
      {name:"comment",type:"text",label:"Closing Comment (optional)"}
    ]
  }
};

let currentTool = null;
let historyOpen = false;

// ── Sidebar ───────────────────────────────────────────────────────────────────
function selectTool(name, btn) {
  currentTool = name;
  document.querySelectorAll('.tool-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderForm(name);
}

function renderForm(name) {
  const t = TOOLS[name];
  const panel = document.getElementById('form-panel');
  let html = `<div class="form-title">${t.icon} ${t.title}</div>
              <div class="form-desc">${t.desc}</div>`;

  t.fields.forEach(f => {
    if (f.type === 'checkbox') {
      html += `<div class="checkbox-row">
        <input type="checkbox" id="f_${f.name}" name="${f.name}" ${f.default ? 'checked' : ''}>
        <label for="f_${f.name}">${f.label}</label>
      </div>`;
    } else if (f.type === 'textarea') {
      html += `<div class="field-group">
        <label>${f.label}${f.required ? ' *' : ''}</label>
        <textarea id="f_${f.name}" name="${f.name}" rows="${f.rows||5}"
          placeholder="${f.placeholder||''}">${f.default||''}</textarea>
      </div>`;
    } else if (f.type === 'select') {
      const opts = f.options.map(o => `<option value="${o}">${o || '— All —'}</option>`).join('');
      html += `<div class="field-group"><label>${f.label}</label>
        <select id="f_${f.name}" name="${f.name}">${opts}</select></div>`;
    } else {
      html += `<div class="field-group">
        <label>${f.label||f.name}${f.required ? ' *' : ''}</label>
        <input type="${f.type}" id="f_${f.name}" name="${f.name}"
          value="${f.default !== undefined ? f.default : ''}"
          placeholder="${f.placeholder||''}">
      </div>`;
    }
  });

  html += `<div class="form-actions">
    <button class="btn-run" id="run-btn" onclick="runTool()">▶ Run</button>
    <button class="btn-clear" onclick="clearResult()">Clear</button>
  </div>`;

  panel.innerHTML = html;
}

// ── Run tool ─────────────────────────────────────────────────────────────────
async function runTool() {
  if (!currentTool) return;
  const t = TOOLS[currentTool];
  const params = {};

  for (const f of t.fields) {
    const el = document.getElementById('f_' + f.name);
    if (!el) continue;
    if (f.type === 'checkbox') params[f.name] = el.checked;
    else params[f.name] = el.value;
  }

  const btn = document.getElementById('run-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin">⏳</span> Running...';

  showLoading();

  try {
    const resp = await fetch('/api/run/' + currentTool, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(params)
    });
    const data = await resp.json();
    renderResult(currentTool, data);
    if (data.history_entry) prependHistory(data.history_entry);
  } catch(e) {
    renderError('Network error: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '▶ Run';
  }
}

// ── Results ──────────────────────────────────────────────────────────────────
function showLoading() {
  document.getElementById('result-wrap').innerHTML =
    '<div class="empty-state"><span class="spin" style="font-size:32px">⏳</span><div style="margin-top:12px;color:var(--muted)">Fetching from SecOps API...</div></div>';
}

function clearResult() {
  document.getElementById('result-wrap').innerHTML =
    '<div class="empty-state" style="padding:60px"><div class="big-icon">📊</div><div>Results will appear here</div></div>';
}

function renderError(msg) {
  document.getElementById('result-wrap').innerHTML = `
    <div class="result-meta">
      <span class="result-status error">ERROR</span>
      <span style="color:var(--red);font-family:var(--mono);font-size:12px">${escHtml(msg)}</span>
    </div>`;
}

function renderResult(toolName, data) {
  const wrap = document.getElementById('result-wrap');
  const ok = data.ok;
  const ms = data.history_entry ? data.history_entry.duration_ms : '';
  let html = `<div class="result-meta">
    <span class="result-status ${ok ? 'ok' : 'error'}">${ok ? 'SUCCESS' : 'ERROR'}</span>
    ${ms ? `<span class="result-time">${ms}ms</span>` : ''}
  </div>`;

  if (!ok) {
    html += codeBlock('Error', escHtml(data.error || 'Unknown error'), 'language-none');
    wrap.innerHTML = html;
    return;
  }

  const res = data.result;

  // Connection test: special card
  if (toolName === 'connection_test') {
    html += `<div class="conn-card">
      <div class="field"><span class="key">Status</span><span class="val" style="color:var(--${res.status==='ok'?'green':'red'})">${res.status}</span></div>
      <div class="field"><span class="key">Project ID</span><span class="val">${res.project_id}</span></div>
      <div class="field"><span class="key">Instance ID</span><span class="val" style="font-size:11px">${res.instance_id}</span></div>
      <div class="field"><span class="key">Region</span><span class="val">${res.region}</span></div>
      ${res.rule_count !== undefined ? `<div class="field"><span class="key">Rules visible</span><span class="val" style="color:var(--blue)">${res.rule_count}</span></div>` : ''}
      ${res.error ? `<div class="field"><span class="key" style="color:var(--red)">Error</span><span class="val" style="color:var(--red)">${res.error}</span></div>` : ''}
    </div>`;
    wrap.innerHTML = html;
    return;
  }

  // Rules list: table + raw JSON
  if (toolName === 'list_rules' && res.rules) {
    const count = res.rules.length;
    html += `<div class="result-count">${count} rule${count!==1?'s':''} found</div>
    <div class="section-title">Rules</div>
    <table class="rules-table">
      <tr><th>Display Name</th><th>Rule ID</th><th>Status</th></tr>
      ${res.rules.map(r => {
        const id = r.name ? r.name.split('/').pop() : '?';
        const enabled = r.deploymentState === 'ENABLED' || r.enabled;
        return `<tr>
          <td>${escHtml(r.displayName||'?')}</td>
          <td><span class="rule-id-link" onclick="loadRule('${id}')">${id}</span></td>
          <td><span class="pill ${enabled?'pill-green':'pill-muted'}">${enabled?'enabled':'disabled'}</span></td>
        </tr>`;
      }).join('')}
    </table>`;
    html += `<div class="section-title">Raw JSON</div>` + codeBlock('JSON', jsonHighlight(res), 'language-json');
    wrap.innerHTML = html;
    Prism.highlightAll();
    return;
  }

  // Rule detail: extract YARA-L source
  if ((toolName === 'get_rule' || toolName === 'create_rule') && (res.text || res.ruleText)) {
    const yaraText = res.text || res.ruleText || '';
    const ruleId = res.name ? res.name.split('/').pop() : '';
    html += `<div class="section-title">YARA-L Source</div>`;
    html += codeBlock('YARA-L 2.0', escHtml(yaraText), 'language-clike', true);
    html += `<div class="section-title">Full Response</div>`;
    html += codeBlock('JSON', jsonHighlight(res), 'language-json');
    wrap.innerHTML = html;
    Prism.highlightAll();
    return;
  }

  // Alerts/detections: count
  if (toolName === 'list_alerts' || toolName === 'list_detections') {
    const items = res.alerts || res.detections || [];
    html += `<div class="result-count">${items.length} item${items.length!==1?'s':''} found</div>`;
  }

  // Reference lists: table
  if (toolName === 'list_reference_lists' && res.referenceLists) {
    const lists = res.referenceLists;
    html += `<div class="result-count">${lists.length} list${lists.length!==1?'s':''} found</div>
    <table class="rules-table">
      <tr><th>Name</th><th>Description</th><th>Lines</th></tr>
      ${lists.map(l => `<tr>
        <td style="font-family:var(--mono);font-size:12px">${escHtml(l.name?l.name.split('/').pop():'?')}</td>
        <td>${escHtml(l.description||'—')}</td>
        <td>${(l.lines||[]).length}</td>
      </tr>`).join('')}
    </table>`;
  }

  // Default: JSON
  html += codeBlock('JSON', jsonHighlight(res), 'language-json');
  wrap.innerHTML = html;
  Prism.highlightAll();
}

function codeBlock(label, content, langClass, copyBtn=true) {
  const id = 'cb_' + Math.random().toString(36).slice(2);
  return `<div class="code-wrap">
    <div class="code-header">
      <span>${label}</span>
      ${copyBtn ? `<button class="btn-copy" onclick="copyCode('${id}')">Copy</button>` : ''}
    </div>
    <pre id="${id}"><code class="${langClass}">${content}</code></pre>
  </div>`;
}

function jsonHighlight(obj) {
  return escHtml(JSON.stringify(obj, null, 2));
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function copyCode(id) {
  const el = document.getElementById(id);
  if (el) navigator.clipboard.writeText(el.innerText).catch(()=>{});
}

function loadRule(ruleId) {
  selectToolByName('get_rule');
  setTimeout(() => {
    const el = document.getElementById('f_rule_id');
    if (el) { el.value = ruleId; }
  }, 50);
}

function selectToolByName(name) {
  const btns = document.querySelectorAll('.tool-btn');
  btns.forEach(b => {
    if (b.getAttribute('onclick') && b.getAttribute('onclick').includes(`'${name}'`)) {
      b.click();
    }
  });
}

// ── Status ────────────────────────────────────────────────────────────────────
async function checkStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    const dot = document.getElementById('status-dot');
    const txt = document.getElementById('status-text');
    if (d.ok && d.result && d.result.status === 'ok') {
      dot.className = 'ok';
      txt.textContent = 'Connected · ' + d.result.project_id;
    } else {
      dot.className = 'error';
      txt.textContent = 'Error: ' + (d.error || 'unknown');
    }
  } catch(e) {
    document.getElementById('status-dot').className = '';
    document.getElementById('status-text').textContent = 'Unreachable';
  }
}

// ── History ───────────────────────────────────────────────────────────────────
function toggleHistory() {
  historyOpen = !historyOpen;
  document.getElementById('history-list').classList.toggle('open', historyOpen);
  document.getElementById('hist-toggle').textContent = historyOpen ? '▼ collapse' : '▲ expand';
}

function prependHistory(entry) {
  const list = document.getElementById('history-list');
  const row = document.createElement('div');
  row.className = 'history-item';
  row.innerHTML = `
    <span class="ts">${entry.timestamp}</span>
    <span class="tool-name">${entry.tool}()</span>
    <span class="st ${entry.status}">${entry.status}</span>
    <span class="dur">${entry.duration_ms}ms</span>`;
  list.prepend(row);
}

async function loadHistory() {
  try {
    const r = await fetch('/api/history');
    const items = await r.json();
    items.forEach(prependHistory);
  } catch(e) {}
}

// ── Tabs ─────────────────────────────────────────────────────────────────────
function switchTab(name, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('panel-results').style.display = name === 'results' ? '' : 'none';
  document.getElementById('panel-activity').style.display = name === 'activity' ? '' : 'none';
  if (name === 'activity') loadActivity();
}

// ── Activity Log ──────────────────────────────────────────────────────────────
async function loadActivity() {
  try {
    const r = await fetch('/api/activity');
    const items = await r.json();
    const wrap = document.getElementById('activity-wrap');
    if (!items.length) {
      wrap.innerHTML = '<div class="empty-state" style="padding:60px"><div class="big-icon">📡</div><div>No API calls yet — run a tool first</div></div>';
      return;
    }
    let html = '<div class="activity-log">';
    for (const item of items) {
      const ok = item.status === 'ok';
      const params = item.params ? item.params.replace(/</g,'&lt;').replace(/>/g,'&gt;') : '';
      html += '<div class="activity-item">' +
        '<div class="activity-header">' +
          '<span class="activity-ts">' + item.ts + '</span>' +
          '<span class="activity-method ' + item.method + '">' + item.method + '</span>' +
          '<span class="activity-endpoint">' + escHtml(item.endpoint) + '</span>' +
          '<span class="activity-dur">' + item.duration_ms + 'ms</span>' +
          '<span class="result-status activity-status ' + (ok ? 'ok' : 'error') + '">' + (ok ? 'OK' : 'ERR') + '</span>' +
        '</div>' +
        '<div class="activity-url" title="' + escHtml(item.url || '') + '">' + escHtml(item.url || '') + '</div>' +
        (params ? '<div class="activity-params">params: ' + params + '</div>' : '') +
        (item.error ? '<div class="activity-error">' + escHtml(item.error) + '</div>' : '') +
      '</div>';
    }
    html += '</div>';
    wrap.innerHTML = html;
  } catch(e) {
    document.getElementById('activity-wrap').innerHTML = '<div class="empty-state">Error loading activity: ' + e.message + '</div>';
  }
}

// ── Analysis Prompts ──────────────────────────────────────────────────────────
const ANALYSIS_META = {
  connection: {
    title: '🔌 Connection Test | בדיקת חיבור',
    desc: 'Test authentication and API connectivity to Google SecOps Chronicle — view each phase of the connection with live timing. Switch to the Reference tab for full function docs and config file details.'
  },
  rules: {
    title: '📊 Analyze All Rules',
    desc: 'Fetches all YARA-L detection rules and analyzes: severity distribution, monitored event types, enabled/disabled breakdown, and key patterns per rule.'
  },
  alerts: {
    title: '🔍 48-Hour Alert Analysis',
    desc: 'Aggregates all security alerts from the last 48 hours and shows: total count, breakdown by severity, state (NEW/REVIEWED/CLOSED), and top triggering rules.'
  },
  timeline: {
    title: '📅 Timeline & Trends (72h)',
    desc: 'Deep-dive into the last 72 hours: daily distribution chart, 24h trend (↑↓), exposed hosts, top triggering rules, rule label categories, and peak activity window.'
  },
  intelligence: {
    title: '🔬 Intelligence Report | דוח מודיעין',
    desc: 'Full security posture: rule category coverage with donut charts, threat intel feed analysis, detection approach breakdown, LIVE rules, and SOC insights in Hebrew & English.'
  },
  explorer: {
    title: '🤖 MCP Explorer | חקרן יכולות',
    desc: 'Explore all 10 MCP tool capabilities, queryable UDM data fields, and AI integration options. Search by keyword or browse — ask what data you can get from the system.'
  }
};

function openAnalysis(type, btn) {
  currentTool = null;
  window._currentAnalysis = type;
  document.querySelectorAll('.tool-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  const m = ANALYSIS_META[type];
  document.getElementById('form-panel').innerHTML =
    '<div class="form-title">' + m.title + '</div>' +
    '<div class="form-desc">' + m.desc + '</div>' +
    '<div class="form-actions">' +
      '<button class="btn-run" id="run-btn" onclick="runAnalysis()">&#9654; Run Analysis</button>' +
    '</div>';
  document.getElementById('tab-results').click();
}

async function runAnalysis() {
  const type = window._currentAnalysis;
  const btn = document.getElementById('run-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spin">&#x23F3;</span> Analyzing...'; }
  showLoading();
  const t0 = performance.now();
  try {
    const resp = await fetch('/api/analyze/' + type);
    const data = await resp.json();
    const ms = Math.round(performance.now() - t0);
    renderAnalysis(type, data, ms);
    // Also refresh activity tab data in background
    fetch('/api/activity');
  } catch(e) {
    renderError('Network error: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '&#9654; Run Analysis'; }
  }
}

function renderAnalysis(type, data, ms) {
  const wrap = document.getElementById('result-wrap');
  if (!data.ok) { renderError(data.error || 'Unknown error'); return; }
  const res = data.result;
  let html = '<div class="result-meta">' +
    '<span class="result-status ok">ANALYSIS COMPLETE</span>' +
    (ms ? '<span class="result-time">' + ms + 'ms</span>' : '') +
    '</div>';

  // Helper: API unavailable notice
  function _apiUnavailableBanner(note) {
    return '<div class="insight-box" style="border-left-color:var(--yellow);margin-bottom:16px">' +
      '<div style="color:var(--yellow);font-weight:600;margin-bottom:6px">&#9888; Alerts API Not Accessible in Demo Environment</div>' +
      '<div style="font-size:12px;color:var(--muted)">The <code>legacySearchDetections</code> endpoint requires the <code>chronicle-backstory</code> OAuth scope, which is unavailable for Gmail accounts. The 435 detections shown in the SecOps UI are accessible via the Chronicle web interface only.</div>' +
      '<div style="font-size:12px;color:var(--muted);margin-top:6px">Showing available data: Detection Rules &amp; Reference Lists.</div>' +
    '</div>';
  }

  // ── MCP Explorer ─────────────────────────────────────────────────────────────
  if (type === 'explorer') {
    const st = res.live_stats;

    // Live system stats bar
    html += '<div class="stat-row">' +
      '<div class="stat-card"><div class="stat-num" style="color:var(--blue)">' + (st.rule_count !== '?' ? st.rule_count : '—') + '</div><div class="stat-label">YARA-L Rules</div></div>' +
      '<div class="stat-card green"><div class="stat-num">' + (st.live_rules !== '?' ? st.live_rules : '—') + '</div><div class="stat-label">LIVE Rules</div></div>' +
      '<div class="stat-card"><div class="stat-num" style="color:var(--yellow)">' + (st.ref_list_count !== '?' ? st.ref_list_count : '—') + '</div><div class="stat-label">Reference Lists</div></div>' +
      '<div class="stat-card"><div class="stat-num" style="color:var(--purple)">10</div><div class="stat-label">MCP Tools</div></div>' +
    '</div>';

    // Search + chips
    html += '<input class="explorer-search" id="ex-search" placeholder="🔍 Search tools, UDM fields, AI capabilities... e.g. IP, login, sha256, AI, alert" oninput="exFilter(this.value)" />';
    html += '<div class="q-chips">';
    var chips = [
      ['🔌 מה כלי ה-MCP?','tools'],['🗃️ שדות UDM','udm'],['🤖 יכולות AI','ai'],
      ['🌐 IP / Network','ip network dns'],['👤 User / Login','user login userid'],
      ['📁 File / Hash','file sha256 hash'],['🚨 Alerts / Severity','alert severity critical'],
      ['🔎 How to search','search query udm_search'],
    ];
    chips.forEach(function(c) {
      html += '<button class="q-chip" onclick="exChip(this,' + JSON.stringify(c[1]) + ')">' + c[0] + '</button>';
    });
    html += '</div>';

    // Sub-tabs
    html += '<div class="sub-tabs">' +
      '<button class="sub-tab active" id="extab-tools" data-tab="tools" onclick="switchExTab(this.dataset.tab)">🛠️ MCP Tools (10)</button>' +
      '<button class="sub-tab" id="extab-udm" data-tab="udm" onclick="switchExTab(this.dataset.tab)">🗃️ UDM Fields</button>' +
      '<button class="sub-tab" id="extab-ai" data-tab="ai" onclick="switchExTab(this.dataset.tab)">🤖 AI & Integration</button>' +
    '</div>';

    // ── Tab: Tools ────────────────────────────────────────────────────────────
    html += '<div id="ex-panel-tools">';
    res.tools.forEach(function(t) {
      const mc = t.method === 'GET' ? 'var(--blue)' : t.method === 'POST' ? 'var(--green)' : 'var(--yellow)';
      const tagStr = t.tags.join(' ');
      html += '<div class="tool-kb-card" data-tags="' + escHtml(tagStr) + '">' +
        '<div class="tool-kb-header">' +
          '<span style="font-size:16px">' + t.icon + '</span>' +
          '<span class="tool-kb-name">' + t.name + '</span>' +
          '<span class="http-method" style="background:' + mc + '20;color:' + mc + '">' + t.method + '</span>' +
        '</div>' +
        '<div class="tool-kb-ep">' + escHtml(t.endpoint) + '</div>' +
        '<div class="tool-kb-desc">' + escHtml(t.desc_en) + '</div>' +
        '<div class="tool-kb-desc-he">' + escHtml(t.desc_he) + '</div>' +
        '<div class="tool-kb-io">' +
          (t.inputs.length ? '<div class="tool-kb-io-box"><div class="tool-kb-io-title">📥 Inputs</div>' + t.inputs.map(function(i){return '<div class="tool-kb-io-item">' + escHtml(i) + '</div>';}).join('') + '</div>' : '') +
          '<div class="tool-kb-io-box"><div class="tool-kb-io-title">📤 Returns</div>' + t.outputs.map(function(o){return '<div class="tool-kb-io-item">' + escHtml(o) + '</div>';}).join('') + '</div>' +
        '</div>' +
      '</div>';
    });
    html += '</div>'; // ex-panel-tools

    // ── Tab: UDM Fields ───────────────────────────────────────────────────────
    html += '<div id="ex-panel-udm" style="display:none">';
    for (var sec in res.udm_sections) {
      var sd = res.udm_sections[sec];
      html += '<div class="udm-section-card" data-sec="' + sec + '">' +
        '<div class="udm-section-hdr">' +
          '<div class="udm-dot" style="width:10px;height:10px;border-radius:50%;background:' + sd.color + ';flex-shrink:0"></div>' +
          '<div>' +
            '<div class="udm-section-title">' + sec.toUpperCase() + '</div>' +
            '<div class="udm-section-desc">' + escHtml(sd.desc) + '</div>' +
          '</div>' +
        '</div>';
      sd.fields.forEach(function(f) {
        html += '<div class="udm-field-row" data-field="' + escHtml(f[0] + ' ' + f[1] + ' ' + f[2]).toLowerCase() + '">' +
          '<span class="udm-field-name">' + escHtml(f[0]) + '</span>' +
          '<span class="udm-field-he">' + escHtml(f[1]) + '</span>' +
          '<span class="udm-field-desc">' + escHtml(f[2]) + '</span>' +
        '</div>';
      });
      html += '</div>'; // udm-section-card
    }
    html += '</div>'; // ex-panel-udm

    // ── Tab: AI & Integration ─────────────────────────────────────────────────
    html += '<div id="ex-panel-ai" style="display:none">';

    // Note box
    html += '<div class="insight-box" style="border-left-color:var(--blue);margin-bottom:16px">' +
      '<div style="font-weight:600;margin-bottom:6px">🤖 Google SecOps AI (Gemini for Security)</div>' +
      '<div style="font-size:12px;color:var(--muted)">ה-AI המובנה של Google SecOps (Gemini for Security) זמין דרך ממשק המשתמש אך <strong style="color:var(--yellow)">לא דרך Chronicle API v1alpha</strong> שבו ה-MCP משתמש. ניתן לשלב Claude (מודל AI חיצוני) עם נתוני ה-MCP לשאילתות טבעיות.</div>' +
      '<div style="font-size:12px;color:var(--muted);margin-top:4px">Gemini for Security AI features are available in the Chronicle UI but are not yet exposed via the Chronicle v1alpha API used by this MCP. You can combine Claude (external AI) with MCP data for natural-language queries.</div>' +
    '</div>';

    // Available via MCP
    html += '<div class="section-title">✅ Available via MCP | זמין דרך MCP</div>';
    html += '<div class="ref-card" style="margin-bottom:14px"><div class="ref-card-body" style="padding:0">';
    res.ai_info.via_mcp.forEach(function(c) {
      html += '<div class="ai-cap-row"><div class="ai-cap-icon">' + c.icon + '</div><div>' +
        '<div class="ai-cap-title">' + escHtml(c.title) + '</div>' +
        '<div class="ai-cap-en">' + escHtml(c.desc_en) + '</div>' +
        '<div class="ai-cap-he">' + escHtml(c.desc_he) + '</div>' +
      '</div></div>';
    });
    html += '</div></div>';

    // UI Only
    html += '<div class="section-title">🔜 In SecOps UI — Not Yet in API | רק ב-UI</div>';
    html += '<div class="ref-card" style="margin-bottom:14px"><div class="ref-card-body" style="padding:0">';
    res.ai_info.ui_only.forEach(function(c) {
      html += '<div class="ai-cap-row"><div class="ai-cap-icon">' + c.icon + '</div><div>' +
        '<div class="ai-cap-title" style="color:var(--muted)">' + escHtml(c.title) + '</div>' +
        '<div class="ai-cap-en">' + escHtml(c.desc_en) + '</div>' +
        '<div class="ai-cap-he">' + escHtml(c.desc_he) + '</div>' +
      '</div></div>';
    });
    html += '</div></div>';

    // Enrichments
    html += '<div class="section-title">🧬 Auto-Enrichments in UDM Events | העשרות אוטומטיות</div>';
    html += '<div class="ref-card" style="margin-bottom:14px"><div class="ref-card-body" style="padding:0">';
    res.ai_info.enrichments.forEach(function(e) {
      html += '<div class="udm-eg-row">' +
        '<span class="udm-field-name" style="font-size:10px">' + escHtml(e.field) + '</span>' +
        '<span style="font-size:10px;color:var(--purple);min-width:120px;flex-shrink:0">' + escHtml(e.source) + '</span>' +
        '<span class="udm-field-desc">' + escHtml(e.desc) + '</span>' +
      '</div>';
    });
    html += '</div></div>';

    // UDM Query examples
    html += '<div class="section-title">💡 UDM Query Examples | דוגמאות שאילתה</div>';
    html += '<div class="ref-card"><div class="ref-card-body" style="padding:0">';
    res.ai_info.udm_query_examples.forEach(function(eg) {
      html += '<div class="udm-eg-row">' +
        '<span class="udm-eg-desc">' + escHtml(eg.desc) + '</span>' +
        '<span class="udm-eg-q">' + escHtml(eg.q) + '</span>' +
      '</div>';
    });
    html += '</div></div>';
    html += '</div>'; // ex-panel-ai

    wrap.innerHTML = html;

    // ── Explorer JS helpers ───────────────────────────────────────────────────
    window.switchExTab = function(tab) {
      ['tools','udm','ai'].forEach(function(t) {
        document.getElementById('extab-' + t).classList.toggle('active', t === tab);
        document.getElementById('ex-panel-' + t).style.display = t === tab ? 'block' : 'none';
      });
    };

    window.exFilter = function(q) {
      var lq = q.toLowerCase();
      // Filter tool cards
      document.querySelectorAll('.tool-kb-card').forEach(function(el) {
        var tags = el.dataset.tags || '';
        var text = el.textContent.toLowerCase();
        el.classList.toggle('hidden', lq.length > 0 && !text.includes(lq) && !tags.includes(lq));
      });
      // Filter UDM field rows
      document.querySelectorAll('.udm-field-row').forEach(function(el) {
        var d = el.dataset.field || '';
        el.classList.toggle('hidden', lq.length > 0 && !d.includes(lq));
      });
      // Show/hide UDM section cards based on if they have visible rows
      document.querySelectorAll('.udm-section-card').forEach(function(card) {
        if (!lq) { card.classList.remove('hidden'); return; }
        var visible = Array.from(card.querySelectorAll('.udm-field-row')).some(function(r){return !r.classList.contains('hidden');});
        card.classList.toggle('hidden', !visible);
      });
      // Update chip state
      document.querySelectorAll('.q-chip').forEach(function(c) { c.classList.remove('active'); });
    };

    window.exChip = function(btn, q) {
      var active = btn.classList.contains('active');
      document.querySelectorAll('.q-chip').forEach(function(c) { c.classList.remove('active'); });
      if (!active) {
        btn.classList.add('active');
        document.getElementById('ex-search').value = q;
        // Special chips that switch tabs
        if (q === 'tools') { switchExTab('tools'); exFilter(''); return; }
        if (q === 'udm') { switchExTab('udm'); exFilter(''); return; }
        if (q === 'ai') { switchExTab('ai'); exFilter(''); return; }
        exFilter(q);
      } else {
        document.getElementById('ex-search').value = '';
        exFilter('');
      }
    };

    return;
  }

  // ── Connection analysis ───────────────────────────────────────────────────────
  if (type === 'connection') {
    const statusOk = res.overall === 'ok';
    const statusIcon = statusOk ? '✅' : '❌';
    const statusColor = statusOk ? 'var(--green)' : 'var(--red)';
    const statusLabel = statusOk ? 'Connected Successfully | חיבור הצליח' : 'Connection Failed | חיבור נכשל';

    html += '<div style="display:flex;align-items:center;gap:14px;margin-bottom:14px">' +
      '<span style="color:' + statusColor + ';font-weight:700;font-size:15px">' + statusIcon + ' ' + statusLabel + '</span>' +
      '<span style="color:var(--muted);font-size:12px">Total: ' + res.total_ms + 'ms</span>' +
    '</div>';

    // ── Sub-tab bar ───────────────────────────────────────────────────────────
    html += '<div class="sub-tabs">' +
      '<button class="sub-tab active" id="subtab-process" data-tab="process" onclick="switchConnTab(this.dataset.tab)">🔌 תהליך החיבור | Process</button>' +
      '<button class="sub-tab" id="subtab-reference" data-tab="reference" onclick="switchConnTab(this.dataset.tab)">📖 תיעוד | Reference</button>' +
    '</div>';

    // ══ PANEL: Process ════════════════════════════════════════════════════════
    html += '<div id="conn-panel-process">';

    html += '<div class="section-title" style="margin-top:4px">EXECUTION TRACE | מסלול ביצוע</div>';
    html += '<div class="step-pipeline">';
    res.steps.forEach(function(s, i) {
      const icon = s.status === 'ok' ? '✅' : '❌';
      const col  = s.status === 'ok' ? 'var(--green)' : 'var(--red)';
      html += '<div class="step-row">' +
        '<div class="step-idx">' + (i+1) + '</div>' +
        '<div class="step-body">' +
          '<div class="step-name">' + icon + ' ' + escHtml(s.step) + '</div>' +
          '<div class="step-detail">' + escHtml(s.detail) + '</div>' +
        '</div>' +
        '<div class="step-ms" style="color:' + col + '">' + s.ms + 'ms</div>' +
      '</div>';
      if (i < res.steps.length - 1) html += '<div class="step-connector"></div>';
    });
    html += '</div>'; // step-pipeline

    html += '<div class="section-title" style="margin-top:20px">ACTIVE CONFIGURATION | הגדרות פעילות</div>';
    html += '<div class="config-grid">';
    const cfgLabels = {
      SECOPS_PROJECT_ID: ['GCP Project ID', 'מזהה פרויקט GCP'],
      SECOPS_INSTANCE_ID:['Instance ID (Tenant)','מזהה מופע / טנאנט'],
      SECOPS_REGION:     ['API Region','אזור'],
      BASE_URL:          ['Chronicle Base URL','כתובת בסיס API'],
      AUTH_METHOD:       ['Auth Method','שיטת אימות'],
      CREDENTIALS_FILE:  ['Credentials File','קובץ הרשאות'],
    };
    for (const [k, v] of Object.entries(res.config)) {
      if (!cfgLabels[k]) continue;
      const [en, he] = cfgLabels[k];
      html += '<div class="config-row">' +
        '<div class="config-key"><div>' + en + '</div><div style="color:var(--muted);font-size:10px;font-weight:400">' + he + '</div></div>' +
        '<div class="config-val">' + escHtml(String(v)) + '</div>' +
      '</div>';
    }
    html += '</div>'; // config-grid
    html += '</div>'; // conn-panel-process

    // ══ PANEL: Reference ═════════════════════════════════════════════════════
    html += '<div id="conn-panel-reference" style="display:none">';

    // Config files
    html += '<div class="section-title" style="margin-top:4px">⚙️ Configuration Files | קבצי הגדרה</div>';
    html += '<div class="ref-card">' +
      '<div class="ref-card-header">📄 .env <span style="color:var(--muted);font-size:11px;font-weight:400">(root directory — copy from .env.example)</span></div>' +
      '<div class="ref-card-body">' +
        '<div class="ref-env-row"><span class="ref-env-key">SECOPS_PROJECT_ID</span><span class="ref-env-desc">GCP Project ID המקושר לטנאנט SecOps</span></div>' +
        '<div class="ref-env-row"><span class="ref-env-key">SECOPS_INSTANCE_ID</span><span class="ref-env-desc">GUID של המופע — Settings → SIEM Settings → Tenant Information</span></div>' +
        '<div class="ref-env-row"><span class="ref-env-key">SECOPS_REGION</span><span class="ref-env-desc">אזור ה-API: "us" | "eu" | "asia-southeast1" (ברירת מחדל: us)</span></div>' +
        '<div class="ref-env-row"><span class="ref-env-key">GOOGLE_APPLICATION_CREDENTIALS</span><span class="ref-env-desc">נתיב לקובץ Service Account JSON (אופציונלי — ברירת מחדל: ADC)</span></div>' +
      '</div>' +
    '</div>';
    html += '<div class="ref-card">' +
      '<div class="ref-card-header">🐍 server.py <span style="color:var(--muted);font-size:11px;font-weight:400">(auto-configured from .env)</span></div>' +
      '<div class="ref-card-body">' +
        '<div class="ref-env-row"><span class="ref-env-key">CHRONICLE_SCOPE</span><span class="ref-env-desc">https://www.googleapis.com/auth/cloud-platform</span></div>' +
        '<div class="ref-env-row"><span class="ref-env-key">BASE_URL</span><span class="ref-env-desc">https://{region}-chronicle.googleapis.com</span></div>' +
        '<div class="ref-env-row"><span class="ref-env-key">INSTANCE_PATH</span><span class="ref-env-desc">projects/{project_id}/locations/{region}/instances/{instance_id}</span></div>' +
        '<div class="ref-env-row"><span class="ref-env-key">_get_credentials()</span><span class="ref-env-desc">מחזיר SA credentials אם הוגדר קובץ, אחרת ADC דרך gcloud</span></div>' +
        '<div class="ref-env-row"><span class="ref-env-key">_headers()</span><span class="ref-env-desc">מוסיף Authorization: Bearer {token} + Content-Type לכל בקשה</span></div>' +
        '<div class="ref-env-row"><span class="ref-env-key">_request(method, endpoint)</span><span class="ref-env-desc">שולח HTTP request מאומת ל-Chronicle API, מחזיר JSON</span></div>' +
      '</div>' +
    '</div>';

    // Auth flow
    html += '<div class="section-title">🔐 Authentication Flow | תהליך אימות</div>';
    html += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px;align-items:center">' +
      '<div class="auth-step-card"><div class="auth-step-num">1</div><div>' +
        '<div style="font-weight:600;font-size:12px">GOOGLE_APPLICATION_CREDENTIALS</div>' +
        '<div style="font-size:11px;color:var(--muted)">קובץ Service Account JSON — הכי מאובטח לפרודקשן</div>' +
      '</div></div>' +
      '<div style="color:var(--muted);font-size:16px;padding:0 2px">→</div>' +
      '<div class="auth-step-card"><div class="auth-step-num">2</div><div>' +
        '<div style="font-weight:600;font-size:12px">Application Default Credentials</div>' +
        '<div style="font-size:11px;color:var(--muted)">Fallback: gcloud auth application-default login</div>' +
      '</div></div>' +
      '<div style="color:var(--muted);font-size:16px;padding:0 2px">→</div>' +
      '<div class="auth-step-card"><div class="auth-step-num">3</div><div>' +
        '<div style="font-weight:600;font-size:12px">Bearer Token → API</div>' +
        '<div style="font-size:11px;color:var(--muted)">Authorization: Bearer {token} בכל request</div>' +
      '</div></div>' +
    '</div>';

    // Function reference table
    html += '<div class="section-title">🛠️ Function Reference | מדריך פונקציות (10 MCP Tools)</div>';
    const FUNCS = [
      {name:'secops_connection_test', method:'GET',   ep:'rules?pageSize=1',          params:'—',                        ret:'status, project_id, rule_count',   he:'בדיקת קישוריות ואימות. תמיד ראשון.',        en:'Verify auth & connectivity to Chronicle API.'},
      {name:'secops_list_rules',      method:'GET',   ep:'rules',                     params:'page_size',                ret:'{ rules[] }',                      he:'כל חוקי YARA-L 2.0 במופע.',                 en:'List all YARA-L 2.0 detection rules.'},
      {name:'secops_get_rule',        method:'GET',   ep:'rules/{rule_id}',           params:'rule_id *',                ret:'Full rule + YARA-L source',        he:'שליפת חוק בודד עם קוד מקור מלא.',           en:'Retrieve one rule by ID with full source.'},
      {name:'secops_create_rule',     method:'POST',  ep:'rules',                     params:'rule_text *',              ret:'Created rule object',              he:'יצירת חוק YARA-L חדש (השתמש ב-validate קודם).', en:'Create new YARA-L 2.0 detection rule.'},
      {name:'secops_validate_rule',   method:'POST',  ep:':verifyRuleText',           params:'rule_text *',              ret:'{ success } or { compilationDiagnostics[] }', he:'קומפילציה + בדיקת תחביר ללא שמירה.',         en:'Validate YARA-L syntax without saving.'},
      {name:'secops_toggle_rule',     method:'PATCH', ep:'rules/{id}/deployment',     params:'rule_id, enabled, alerting',ret:'Deployment object',               he:'הפעלה/כיבוי חוק והתראות.',                  en:'Enable or disable a rule and alerting.'},
      {name:'secops_list_detections', method:'GET',   ep:'rules/{id}/detections',     params:'rule_id, hours_back',      ret:'{ detections[] }',                 he:'כל הגילויים של חוק ספציפי בטווח זמן.',       en:'List matches for a specific rule in time window.'},
      {name:'secops_list_alerts',     method:'GET',   ep:'legacy:legacySearchDetections', params:'hours_back, state_filter', ret:'{ alerts[] }',                he:'התראות מה-feed (דורש OAuth scope מיוחד).',    en:'List aggregated alerts — needs chronicle-backstory scope.'},
      {name:'secops_list_reference_lists', method:'GET', ep:'referenceLists',         params:'page_size',                ret:'{ referenceLists[] }',             he:'רשימות עזר: IPs, domains, hashes, CIDRs, regex.', en:'List all allowlists / blocklists.'},
      {name:'secops_udm_search',      method:'GET',   ep:'udmEvents',                 params:'query, hours_back',        ret:'{ events[], totalCount }',         he:'חיפוש UDM — query: metadata.event_type = "USER_LOGIN".', en:'Search UDM events with a filter expression.'},
    ];
    html += '<div class="func-list">';
    FUNCS.forEach(function(f) {
      const mc = f.method === 'GET' ? 'var(--blue)' : f.method === 'POST' ? 'var(--green)' : 'var(--yellow)';
      html += '<div class="func-card">' +
        '<div class="func-card-top">' +
          '<span class="func-card-name">' + f.name + '</span>' +
          '<span class="http-method" style="background:' + mc + '20;color:' + mc + '">' + f.method + '</span>' +
          (f.params !== '—' ? '<span style="font-size:10px;color:var(--muted)">params: ' + escHtml(f.params) + '</span>' : '') +
        '</div>' +
        '<div class="func-card-ep">' + escHtml(f.ep) + '</div>' +
        '<div class="func-card-desc">' + escHtml(f.en) + '</div>' +
        '<div class="func-card-he">' + escHtml(f.he) + '</div>' +
      '</div>';
    });
    html += '</div>';

    html += '</div>'; // conn-panel-reference

    wrap.innerHTML = html;

    // Sub-tab toggle function
    window.switchConnTab = function(tab) {
      ['process','reference'].forEach(function(t) {
        document.getElementById('subtab-' + t).classList.toggle('active', t === tab);
        document.getElementById('conn-panel-' + t).style.display = t === tab ? 'block' : 'none';
      });
    };
    return;
  }

  if (type === 'rules') {
    html += '<div class="stat-row">' +
      '<div class="stat-card"><div class="stat-num">' + res.total + '</div><div class="stat-label">Total Rules</div></div>' +
      '<div class="stat-card green"><div class="stat-num">' + (res.live_capable||0) + '</div><div class="stat-label">LIVE-Capable</div></div>' +
      '<div class="stat-card muted"><div class="stat-num">' + (res.disabled||0) + '</div><div class="stat-label">Disabled</div></div>' +
    '</div>';

    // Category breakdown
    if (res.category_breakdown && Object.keys(res.category_breakdown).length) {
      html += '<div class="section-title">Attack Category Coverage</div><div class="breakdown-list">';
      const tot = Object.values(res.category_breakdown).reduce((a,b)=>a+b,0);
      const catColors = {'malware':'var(--red)','APT / Threat Actor':'var(--red)','Ransomware':'var(--red)',
        'Network':'var(--blue)','Authentication':'var(--yellow)','Suspicious / Anomaly':'var(--purple)',
        'Data Exfiltration':'var(--yellow)','Phishing':'var(--yellow)','Execution':'var(--green)',
        'Persistence':'var(--green)','Privilege Escalation':'var(--green)','Other':'var(--muted)'};
      for (const [cat, cnt] of Object.entries(res.category_breakdown)) {
        const pct = Math.round(cnt/tot*100);
        const col = catColors[cat] || 'var(--muted)';
        html += '<div class="breakdown-row"><span class="breakdown-label" style="color:' + col + '">' + escHtml(cat) + '</span><div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:' + pct + '%;background:' + col + '"></div></div><span class="breakdown-count">' + cnt + '</span></div>';
      }
      html += '</div>';
    }

    // Author breakdown
    if (res.author_breakdown && Object.keys(res.author_breakdown).length) {
      html += '<div class="section-title">Rule Authors</div><div class="breakdown-list">';
      const tot = Object.values(res.author_breakdown).reduce((a,b)=>a+b,0);
      for (const [auth, cnt] of Object.entries(res.author_breakdown)) {
        const pct = Math.round(cnt/tot*100);
        html += '<div class="breakdown-row"><span class="breakdown-label" style="color:var(--text)">' + escHtml(auth||'Unknown') + '</span><div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:' + pct + '%;background:var(--blue)"></div></div><span class="breakdown-count">' + cnt + '</span></div>';
      }
      html += '</div>';
    }

    // Type + frequency in one row
    html += '<div class="stat-row" style="margin-bottom:16px">';
    if (res.type_breakdown) {
      for (const [t, cnt] of Object.entries(res.type_breakdown)) {
        html += '<div class="stat-card"><div class="stat-num" style="font-size:18px">' + cnt + '</div><div class="stat-label">' + escHtml(t.replace('_',' ')) + '</div></div>';
      }
    }
    if (res.frequency_breakdown) {
      for (const [f, cnt] of Object.entries(res.frequency_breakdown)) {
        const col = f==='LIVE'?'var(--green)':f==='HOURLY'?'var(--blue)':'var(--muted)';
        html += '<div class="stat-card" style="border-color:' + col + '40"><div class="stat-num" style="font-size:18px;color:' + col + '">' + cnt + '</div><div class="stat-label">' + escHtml(f) + '</div></div>';
      }
    }
    html += '</div>';

    // Rules table with category
    html += '<div class="section-title">All Rules (' + res.rules.length + ')</div>';
    html += '<table class="rules-table"><tr><th>Name</th><th>Category</th><th>Author</th><th>Type</th><th>LIVE</th></tr>';
    for (const r of res.rules) {
      html += '<tr>' +
        '<td style="font-family:var(--mono);font-size:11px">' + escHtml(r.name) + '</td>' +
        '<td><span class="pill pill-muted" style="font-size:10px">' + escHtml(r.category) + '</span></td>' +
        '<td style="font-size:11px;color:var(--muted)">' + escHtml(r.author||'—') + '</td>' +
        '<td style="font-size:11px;color:var(--muted)">' + escHtml((r.type||'').replace('_EVENT','')) + '</td>' +
        '<td><span class="pill ' + (r.live_capable?'pill-green':'pill-muted') + '" style="font-size:10px">' + (r.live_capable?'LIVE':'—') + '</span></td>' +
      '</tr>';
    }
    html += '</table>';
  }

  if (type === 'alerts') {
    if (res.api_unavailable) {
      html += _apiUnavailableBanner(res.api_note);
      html += '<div class="stat-row">' +
        '<div class="stat-card"><div class="stat-num">' + (res.rules_total||0) + '</div><div class="stat-label">Detection Rules</div></div>' +
        '<div class="stat-card green"><div class="stat-num">' + (res.rules_live_capable||0) + '</div><div class="stat-label">LIVE-Capable Rules</div></div>' +
        '<div class="stat-card"><div class="stat-num">' + (res.reference_lists_total||0) + '</div><div class="stat-label">Reference Lists</div></div>' +
      '</div>';
      if (res.reference_lists && res.reference_lists.length) {
        html += '<div class="section-title">Reference Lists (Threat Intel Feeds)</div>';
        html += '<table class="rules-table"><tr><th>List Name</th><th>Description</th><th>Type</th><th>Updated</th></tr>';
        for (const rl of res.reference_lists) {
          html += '<tr>' +
            '<td style="font-family:var(--mono);font-size:11px;color:var(--blue)">' + escHtml(rl.name) + '</td>' +
            '<td style="font-size:11px">' + escHtml(rl.description||'—') + '</td>' +
            '<td style="font-size:11px;color:var(--muted)">' + escHtml((rl.type||'').replace('REFERENCE_LIST_SYNTAX_TYPE_','')) + '</td>' +
            '<td style="font-size:11px;color:var(--muted);font-family:var(--mono)">' + escHtml(rl.updated||'—') + '</td>' +
          '</tr>';
        }
        html += '</table>';
      }
    } else {
      html += '<div class="stat-row">' +
        '<div class="stat-card"><div class="stat-num">' + res.total + '</div><div class="stat-label">Alerts (48h)</div></div>';
      if (res.by_state) {
        for (const [state, cnt] of Object.entries(res.by_state)) {
          html += '<div class="stat-card"><div class="stat-num">' + cnt + '</div><div class="stat-label">' + escHtml(state) + '</div></div>';
        }
      }
      html += '</div>';
      if (res.by_severity && Object.keys(res.by_severity).length) {
        html += '<div class="section-title">By Severity</div><div class="breakdown-list">';
        const tot = Object.values(res.by_severity).reduce((a,b)=>a+b,0);
        for (const [sev, cnt] of Object.entries(res.by_severity)) {
          const pct = Math.round(cnt/tot*100);
          const col = (sev.includes('HIGH')||sev.includes('CRIT')) ? 'var(--red)' : sev.includes('MED') ? 'var(--yellow)' : sev.includes('LOW') ? 'var(--green)' : 'var(--muted)';
          html += '<div class="breakdown-row"><span class="breakdown-label" style="color:' + col + '">' + escHtml(sev) + '</span><div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:' + pct + '%;background:' + col + '"></div></div><span class="breakdown-count">' + cnt + '</span></div>';
        }
        html += '</div>';
      }
      if (res.by_rule && Object.keys(res.by_rule).length) {
        html += '<div class="section-title">Top Triggering Rules</div><table class="rules-table"><tr><th>Rule Name</th><th>Alerts</th></tr>';
        for (const [rule, cnt] of Object.entries(res.by_rule)) {
          html += '<tr><td style="font-family:var(--mono);font-size:11px">' + escHtml(rule) + '</td><td style="color:var(--blue);font-weight:600">' + cnt + '</td></tr>';
        }
        html += '</table>';
      }
      if (res.total === 0) html += '<div class="empty-state" style="padding:32px"><div>No alerts found</div></div>';
    }
  }

  if (type === 'timeline') {
    if (res.api_unavailable) {
      html += _apiUnavailableBanner(res.api_note);
      html += '<div class="stat-row">' +
        '<div class="stat-card"><div class="stat-num">' + (res.rules_total||0) + '</div><div class="stat-label">Total Rules</div></div>' +
        '<div class="stat-card green"><div class="stat-num">' + (res.rules_live||0) + '</div><div class="stat-label">LIVE Rules</div></div>' +
        '<div class="stat-card"><div class="stat-num">' + (res.rules_multi_event||0) + '</div><div class="stat-label">Multi-Event Rules</div></div>' +
      '</div>';
      if (res.rules_frequency_dist && Object.keys(res.rules_frequency_dist).length) {
        html += '<div class="section-title">Rule Run Frequencies (Detection Coverage)</div><div class="breakdown-list">';
        const tot = Object.values(res.rules_frequency_dist).reduce((a,b)=>a+b,0);
        const freqCols = {LIVE:'var(--green)',HOURLY:'var(--blue)',DAILY:'var(--muted)'};
        for (const [f, cnt] of Object.entries(res.rules_frequency_dist)) {
          const pct = Math.round(cnt/tot*100);
          const col = freqCols[f] || 'var(--muted)';
          html += '<div class="breakdown-row"><span class="breakdown-label" style="color:' + col + '">' + f + '</span><div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:' + pct + '%;background:' + col + '"></div></div><span class="breakdown-count">' + cnt + '</span></div>';
        }
        html += '</div>';
      }
      html += '<div class="insight-box" style="border-left-color:var(--blue);margin-top:16px">' +
        '<div style="font-size:13px;color:var(--text);margin-bottom:8px">&#128270; What you can see in the SecOps UI (not via REST API with Gmail):</div>' +
        '<div class="insight-item">&#128202; 435 active detections visible in Alerts &amp; IOCs tab</div>' +
        '<div class="insight-item">&#128683; Filter active: <code>feedback_summary.status != CLOSED</code></div>' +
        '<div class="insight-item">&#128338; Detection window: 2026-04-02 to 2026-04-05 (72h)</div>' +
        '<div class="insight-item">&#9888; Priority: Medium | Rules: suspicious_file_hash, suspicious_ip_threat</div>' +
        '<div class="insight-item">&#128187; Hosts affected: wrk-pac*, win-ser*, win-adf* (workstations &amp; servers)</div>' +
      '</div>';
      wrap.innerHTML = html;
      return;
    }
    const trendPct = res.trend_pct || 0;
    const trendDir = trendPct > 0 ? '&#8593;' : trendPct < 0 ? '&#8595;' : '&#8594;';
    const trendCls = trendPct > 0 ? 'trend-up' : trendPct < 0 ? 'trend-down' : 'trend-flat';

    // ── Stat row ──────────────────────────────────────────────────────────
    html += '<div class="stat-row">' +
      '<div class="stat-card"><div class="stat-num">' + res.total + '</div><div class="stat-label">Total (72h)</div></div>' +
      '<div class="stat-card"><div class="stat-num">' + res.last_24h + '</div><div class="stat-label">Last 24h</div></div>' +
      '<div class="stat-card muted"><div class="stat-num">' + res.prev_24h + '</div><div class="stat-label">Prev 24h</div></div>' +
      '<div class="stat-card" style="border-color:' + (trendPct>0?'rgba(248,81,73,.3)':'rgba(57,211,83,.3)') + '">' +
        '<div class="stat-num ' + trendCls + '">' + trendDir + Math.abs(trendPct) + '%</div>' +
        '<div class="stat-label">24h Trend</div>' +
      '</div>' +
      (res.peak_hour ? '<div class="stat-card" style="min-width:130px"><div class="stat-num" style="font-size:16px;color:var(--yellow)">' + res.peak_hour.slice(5) + '</div><div class="stat-label">Peak Hour (' + res.peak_count + ' hits)</div></div>' : '') +
    '</div>';

    // ── Insight box ───────────────────────────────────────────────────────
    const ruleCount = res.by_rule ? Object.keys(res.by_rule).length : 0;
    const hostCount = res.by_host ? Object.keys(res.by_host).length : 0;
    const topRule = res.by_rule ? Object.keys(res.by_rule)[0] || 'N/A' : 'N/A';
    const topHost = res.by_host ? Object.keys(res.by_host)[0] || 'N/A' : 'N/A';
    html += '<div class="insight-box">' +
      '<div class="insight-item">&#128270; <span>' + ruleCount + ' unique rules</span> triggered in the last 72h</div>' +
      '<div class="insight-item">&#128187; <span>' + hostCount + ' unique hosts</span> were involved in detections</div>' +
      '<div class="insight-item">&#128293; Top rule: <span>' + escHtml(topRule) + '</span> (' + (res.by_rule[topRule]||0) + ' hits)</div>' +
      '<div class="insight-item">&#128275; Most-hit host: <span>' + escHtml(topHost) + '</span> (' + (res.by_host[topHost]||0) + ' alerts)</div>' +
      (trendPct > 10 ? '<div class="insight-item" style="color:var(--red)">&#9888; Alert volume is <span>increasing (' + trendPct + '%)</span> compared to previous 24h</div>' : '') +
      (trendPct < -10 ? '<div class="insight-item" style="color:var(--green)">&#10003; Alert volume is <span>decreasing (' + Math.abs(trendPct) + '%)</span> compared to previous 24h</div>' : '') +
    '</div>';

    // ── Daily bar chart ───────────────────────────────────────────────────
    if (res.daily && Object.keys(res.daily).length) {
      const vals = Object.values(res.daily);
      const maxVal = Math.max(...vals, 1);
      html += '<div class="section-title">Daily Distribution</div><div class="timeline-chart">';
      for (const [day, cnt] of Object.entries(res.daily)) {
        const pct = Math.round(cnt / maxVal * 100);
        const col = cnt === maxVal ? 'var(--yellow)' : 'var(--blue)';
        html += '<div class="tl-col">' +
          '<div class="tl-count">' + cnt + '</div>' +
          '<div class="tl-bar-wrap"><div class="tl-bar" style="height:' + pct + '%;background:' + col + '" title="' + day + ': ' + cnt + ' alerts"></div></div>' +
          '<div class="tl-label">' + day.slice(5) + '</div>' +
        '</div>';
      }
      html += '</div>';
    } else {
      html += '<div class="insight-box" style="border-left-color:var(--yellow)">No timestamp data returned by API — alerts fetched but detection times unavailable. Total alerts: ' + res.total + '</div>';
    }

    // ── Rule labels / categories ──────────────────────────────────────────
    if (res.rule_labels && Object.keys(res.rule_labels).length) {
      html += '<div class="section-title">Rule Label Categories</div><div class="breakdown-list">';
      const maxL = Math.max(...Object.values(res.rule_labels), 1);
      for (const [lbl, cnt] of Object.entries(res.rule_labels)) {
        const pct = Math.round(cnt / maxL * 100);
        html += '<div class="breakdown-row">' +
          '<span class="breakdown-label" style="color:var(--purple)">' + escHtml(lbl) + '</span>' +
          '<div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:' + pct + '%;background:var(--purple)"></div></div>' +
          '<span class="breakdown-count">' + cnt + '</span>' +
        '</div>';
      }
      html += '</div>';
    }

    // ── Exposed hosts ─────────────────────────────────────────────────────
    if (res.by_host && Object.keys(res.by_host).length) {
      html += '<div class="section-title">&#128187; Exposed Hosts (' + Object.keys(res.by_host).length + ' unique)</div><div class="breakdown-list">';
      const maxH = Math.max(...Object.values(res.by_host), 1);
      for (const [host, cnt] of Object.entries(res.by_host)) {
        const pct = Math.round(cnt / maxH * 100);
        const col = cnt === maxH ? 'var(--red)' : 'var(--text)';
        html += '<div class="breakdown-row">' +
          '<span class="breakdown-label" style="font-family:var(--mono);font-size:11px;color:' + col + '">' + escHtml(host) + '</span>' +
          '<div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:' + pct + '%;background:var(--purple)"></div></div>' +
          '<span class="breakdown-count">' + cnt + '</span>' +
        '</div>';
      }
      html += '</div>';
    }

    // ── Top rules table ───────────────────────────────────────────────────
    if (res.by_rule && Object.keys(res.by_rule).length) {
      html += '<div class="section-title">Top Triggering Rules (72h)</div>';
      html += '<table class="rules-table"><tr><th>Rule Name</th><th>Hits</th><th>Share</th></tr>';
      const totalHits = Object.values(res.by_rule).reduce((a,b)=>a+b,0);
      for (const [rule, cnt] of Object.entries(res.by_rule)) {
        const share = totalHits > 0 ? Math.round(cnt/totalHits*100) : 0;
        html += '<tr>' +
          '<td style="font-family:var(--mono);font-size:11px">' + escHtml(rule) + '</td>' +
          '<td style="color:var(--blue);font-weight:600;font-family:var(--mono)">' + cnt + '</td>' +
          '<td style="color:var(--muted);font-size:11px">' + share + '%</td>' +
        '</tr>';
      }
      html += '</table>';
    }

    // ── Priority breakdown ────────────────────────────────────────────────
    if (res.by_priority && Object.keys(res.by_priority).length) {
      html += '<div class="section-title">By Priority</div><div class="stat-row">';
      const prioColors = {HIGH:'var(--red)',CRITICAL:'var(--red)',MEDIUM:'var(--yellow)',LOW:'var(--green)',INFO:'var(--muted)'};
      for (const [p, cnt] of Object.entries(res.by_priority)) {
        const col = prioColors[p] || 'var(--muted)';
        html += '<div class="stat-card" style="border-color:' + col + '40">' +
          '<div class="stat-num" style="color:' + col + '">' + cnt + '</div>' +
          '<div class="stat-label">' + escHtml(p) + '</div>' +
        '</div>';
      }
      html += '</div>';
    }
  }

  if (type === 'intelligence') {
    const res = data.result;
    const covColor = res.coverage_score >= 80 ? 'var(--green)' : res.coverage_score >= 50 ? 'var(--yellow)' : 'var(--red)';
    const catCount = res.category_breakdown ? Object.keys(res.category_breakdown).length : 0;

    // ── Stat row ──────────────────────────────────────────────────────────────
    html += '<div class="stat-row">' +
      '<div class="stat-card"><div class="stat-num">' + res.total_rules + '</div><div class="stat-label" style="line-height:1.4">Detection Rules<br><span style="font-size:10px;opacity:.7">חוקי זיהוי</span></div></div>' +
      '<div class="stat-card"><div class="stat-num">' + res.total_ref_lists + '</div><div class="stat-label" style="line-height:1.4">Intel Feeds<br><span style="font-size:10px;opacity:.7">מודיעין איומים</span></div></div>' +
      '<div class="stat-card green"><div class="stat-num" style="color:var(--green)">' + res.live_rules_count + '</div><div class="stat-label" style="line-height:1.4">LIVE Rules<br><span style="font-size:10px;opacity:.7">זמן אמת</span></div></div>' +
      '<div class="stat-card"><div class="stat-num" style="color:var(--purple)">' + res.multi_event_count + '</div><div class="stat-label" style="line-height:1.4">Multi-Event<br><span style="font-size:10px;opacity:.7">מתאם אירועים</span></div></div>' +
      '<div class="stat-card" style="border-color:' + covColor + '40"><div class="stat-num" style="color:' + covColor + '">' + res.coverage_score + '%</div><div class="stat-label" style="line-height:1.4">Coverage<br><span style="font-size:10px;opacity:.7">ציון כיסוי</span></div></div>' +
    '</div>';

    // ── Coverage bar ──────────────────────────────────────────────────────────
    html += '<div style="margin-bottom:18px">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">' +
        '<span style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px">Security Coverage Score | ציון כיסוי אבטחה</span>' +
        '<span style="font-size:13px;font-weight:700;color:' + covColor + '">' + res.coverage_score + '% — ' + catCount + ' attack categories covered</span>' +
      '</div>' +
      '<div style="height:10px;background:var(--surface);border-radius:5px;border:1px solid var(--border);overflow:hidden">' +
        '<div style="height:100%;width:' + res.coverage_score + '%;background:linear-gradient(90deg,' + covColor + '99,' + covColor + ');border-radius:5px;transition:width .6s ease"></div>' +
      '</div>' +
    '</div>';

    // ── Hebrew/English executive summary ──────────────────────────────────────
    html += '<div class="insight-box" style="border-left-color:var(--blue);margin-bottom:18px">' +
      '<div style="font-weight:700;color:var(--text);margin-bottom:12px;font-size:14px">📋 Executive Summary | סיכום מנהלים</div>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:12px;line-height:1.6">' +
        '<div><span style="color:var(--green)">✓</span> <strong>' + res.total_rules + ' חוקי YARA-L</strong> פעילים במערכת<br><span style="color:var(--muted)">Active detection rules monitoring the environment</span></div>' +
        '<div><span style="color:var(--green)">✓</span> <strong>' + catCount + ' קטגוריות תקיפה</strong> מכוסות מתוך 11<br><span style="color:var(--muted)">Attack categories with dedicated detection rules</span></div>' +
        '<div><span style="color:var(--green)">✓</span> <strong>' + res.live_rules_count + ' חוקים בזמן אמת</strong> (LIVE streaming)<br><span style="color:var(--muted)">Rules that detect threats as events arrive</span></div>' +
        '<div><span style="color:var(--purple)">⚡</span> <strong>' + res.multi_event_count + ' חוקים מתאמים</strong> (Multi-Event)<br><span style="color:var(--muted)">Correlation rules detecting patterns over time</span></div>' +
        '<div><span style="color:var(--yellow)">🛡</span> <strong>' + res.total_ref_lists + ' רשימות מודיעין</strong> — IoC blocklists<br><span style="color:var(--muted)">Threat intelligence feeds (IPs, hashes, domains)</span></div>' +
        '<div><span style="color:' + covColor + '">📊</span> <strong>ציון כיסוי: ' + res.coverage_score + '%</strong><br><span style="color:var(--muted)">Overall security detection posture score</span></div>' +
      '</div>' +
    '</div>';

    // ── Attack category donut + breakdown ─────────────────────────────────────
    if (res.category_breakdown && Object.keys(res.category_breakdown).length) {
      const CAT_COLORS = ['#f85149','#ff9f43','#e3b341','#ffd93d','#6bcb77','#4d96ff','#bc8cff','#58a6ff','#39d353','#fd7272','#a29bfe','#74b9ff'];
      const donutSvg = svgDonut(res.category_breakdown, CAT_COLORS, 160);
      html += '<div class="section-title">Attack Category Coverage | כיסוי קטגוריות תקיפה</div>';
      html += '<div style="display:flex;flex-direction:column;gap:12px;margin-bottom:18px">' +
        '<div style="text-align:center">' + donutSvg + '</div>' +
        '<div>';
      const catTotal = Object.values(res.category_breakdown).reduce(function(a,b){return a+b;},0);
      let ci = 0;
      for (const cat in res.category_breakdown) {
        const cnt = res.category_breakdown[cat];
        const pct = Math.round(cnt / catTotal * 100);
        const col = CAT_COLORS[ci % CAT_COLORS.length];
        html += '<div class="breakdown-row">' +
          '<span class="breakdown-label" style="color:' + col + ';font-size:11px">' + escHtml(cat) + '</span>' +
          '<div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:' + pct + '%;background:' + col + '"></div></div>' +
          '<span class="breakdown-count">' + cnt + '</span>' +
        '</div>';
        ci++;
      }
      html += '</div></div>';
    }

    // ── Detection approach (Single vs Multi event) ────────────────────────────
    if (res.type_breakdown && Object.keys(res.type_breakdown).length) {
      const TYPE_COLORS = ['var(--blue)','var(--purple)','var(--muted)'];
      const TYPE_LABELS = {
        'SINGLE_EVENT': 'Single Event | חוק נקודתי — מזהה אירוע בודד חריג',
        'MULTI_EVENT':  'Multi Event | חוק מתאם — זיהוי דפוס על פני מספר אירועים',
        'UNKNOWN':      'Unknown'
      };
      html += '<div class="section-title">Detection Approach | גישת זיהוי</div>';
      html += '<div style="display:flex;flex-direction:column;gap:12px;margin-bottom:18px">' +
        '<div style="text-align:center">' + svgDonut(res.type_breakdown, TYPE_COLORS, 140) + '</div>' +
        '<div>';
      const typeTotal = Object.values(res.type_breakdown).reduce(function(a,b){return a+b;},0);
      let ti = 0;
      for (const t in res.type_breakdown) {
        const cnt = res.type_breakdown[t];
        const pct = Math.round(cnt / typeTotal * 100);
        const col = TYPE_COLORS[ti % TYPE_COLORS.length];
        html += '<div class="breakdown-row">' +
          '<span class="breakdown-label" style="color:' + col + ';font-size:11px;max-width:280px">' + escHtml(TYPE_LABELS[t] || t) + '</span>' +
          '<div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:' + pct + '%;background:' + col + '"></div></div>' +
          '<span class="breakdown-count">' + cnt + '</span>' +
        '</div>';
        ti++;
      }
      html += '</div></div>';
    }

    // ── Run frequency ─────────────────────────────────────────────────────────
    if (res.freq_breakdown && Object.keys(res.freq_breakdown).length) {
      const FREQ_COLORS = {LIVE:'var(--green)',HOURLY:'var(--blue)',DAILY:'var(--muted)',WEEKLY:'var(--yellow)'};
      const FREQ_HE = {LIVE:'LIVE — מזהה בזמן אמת כשהאירוע מגיע',HOURLY:'HOURLY — ריצה כל שעה על חלון של שעה',DAILY:'DAILY — ריצה יומית על חלון 24 שעות',WEEKLY:'WEEKLY — ריצה שבועית'};
      html += '<div class="section-title">Run Frequency | תדירות ריצה</div><div class="breakdown-list">';
      const freqTotal = Object.values(res.freq_breakdown).reduce(function(a,b){return a+b;},0);
      for (const f in res.freq_breakdown) {
        const cnt = res.freq_breakdown[f];
        const pct = Math.round(cnt / freqTotal * 100);
        const col = FREQ_COLORS[f] || 'var(--muted)';
        html += '<div class="breakdown-row">' +
          '<span class="breakdown-label" style="color:' + col + ';font-size:11px;max-width:280px">' + escHtml(FREQ_HE[f] || f) + '</span>' +
          '<div class="breakdown-bar-wrap"><div class="breakdown-bar" style="width:' + pct + '%;background:' + col + '"></div></div>' +
          '<span class="breakdown-count">' + cnt + '</span>' +
        '</div>';
      }
      html += '</div>';
    }

    // ── Threat intel reference lists ──────────────────────────────────────────
    if (res.ref_lists && res.ref_lists.length) {
      html += '<div class="section-title">Threat Intelligence Feeds | מודיעין איומים (' + res.ref_lists.length + ')</div>';
      if (res.ref_type_breakdown && Object.keys(res.ref_type_breakdown).length) {
        const RT_COLORS = {PLAIN_TEXT_STRING:'var(--blue)',PLAIN_TEXT:'var(--blue)',REGEX:'var(--purple)',CIDR:'var(--yellow)',UNKNOWN:'var(--muted)'};
        html += '<div class="stat-row" style="margin-bottom:12px">';
        for (const rt in res.ref_type_breakdown) {
          const col = RT_COLORS[rt] || 'var(--muted)';
          html += '<div class="stat-card" style="border-color:' + col + '40;min-width:80px">' +
            '<div class="stat-num" style="font-size:20px;color:' + col + '">' + res.ref_type_breakdown[rt] + '</div>' +
            '<div class="stat-label">' + escHtml(rt) + '</div>' +
          '</div>';
        }
        html += '</div>';
      }
      html += '<table class="rules-table"><tr><th>Feed Name</th><th>Description</th><th>Type</th><th>Updated</th></tr>';
      const RT_C2 = {PLAIN_TEXT_STRING:'var(--blue)',PLAIN_TEXT:'var(--blue)',REGEX:'var(--purple)',CIDR:'var(--yellow)',UNKNOWN:'var(--muted)'};
      for (const rl of res.ref_lists) {
        const tc = RT_C2[rl.type] || 'var(--muted)';
        html += '<tr>' +
          '<td style="font-family:var(--mono);font-size:11px;color:var(--blue)">' + escHtml(rl.displayName || rl.name) + '</td>' +
          '<td style="font-size:11px">' + escHtml(rl.description || '—') + '</td>' +
          '<td><span class="pill" style="background:' + tc + '18;color:' + tc + ';font-size:10px">' + escHtml(rl.type || '—') + '</span></td>' +
          '<td style="font-size:11px;color:var(--muted);font-family:var(--mono)">' + escHtml(rl.updated || '—') + '</td>' +
        '</tr>';
      }
      html += '</table>';
    }

    // ── LIVE rules sample ─────────────────────────────────────────────────────
    if (res.live_rules_sample && res.live_rules_sample.length) {
      html += '<div class="section-title">LIVE Detection Rules | חוקים פעילים בזמן אמת (' + res.live_rules_count + ' total)</div>';
      html += '<div class="insight-box" style="border-left-color:var(--green)">';
      for (const r of res.live_rules_sample) {
        html += '<div class="insight-item" style="font-family:var(--mono);font-size:11px">⚡ ' + escHtml(r) + '</div>';
      }
      if (res.live_rules_count > res.live_rules_sample.length) {
        html += '<div style="font-size:11px;color:var(--muted);margin-top:8px">... + ' + (res.live_rules_count - res.live_rules_sample.length) + ' more LIVE rules</div>';
      }
      html += '</div>';
    }

    // ── Multi-event rules sample ──────────────────────────────────────────────
    if (res.multi_event_rules_sample && res.multi_event_rules_sample.length) {
      html += '<div class="section-title">Multi-Event Correlation Rules | חוקי מתאם (' + res.multi_event_count + ' total)</div>';
      html += '<div class="insight-box" style="border-left-color:var(--purple)">';
      for (const r of res.multi_event_rules_sample) {
        html += '<div class="insight-item" style="font-family:var(--mono);font-size:11px">🔗 ' + escHtml(r) + '</div>';
      }
      if (res.multi_event_count > res.multi_event_rules_sample.length) {
        html += '<div style="font-size:11px;color:var(--muted);margin-top:8px">... + ' + (res.multi_event_count - res.multi_event_rules_sample.length) + ' more multi-event rules</div>';
      }
      html += '</div>';
    }

    // ── SOC key insights (Hebrew) ─────────────────────────────────────────────
    html += '<div class="insight-box" style="border-left-color:var(--yellow);margin-top:8px">' +
      '<div style="font-weight:700;color:var(--text);margin-bottom:10px">🧠 Key SOC Insights | תובנות עיקריות</div>' +
      '<div style="font-size:12px;line-height:1.8">' +
        '<div class="insight-item">🔴 <strong>כיסוי Malware:</strong> <span>חוקים ייעודיים לזיהוי תוכנות זדוניות, טרויאנים ו-Ransomware</span></div>' +
        '<div class="insight-item">🟡 <strong>הגנת זהויות:</strong> <span>חוקי Kerberos, NTLM, Brute Force וגניבת Credentials</span></div>' +
        '<div class="insight-item">🔵 <strong>איומי רשת:</strong> <span>זיהוי C2 Beaconing, DNS Tunneling ו-Lateral Movement</span></div>' +
        '<div class="insight-item">🟢 <strong>LIVE Detection:</strong> <span>' + res.live_rules_count + ' חוקים מגיבים בזמן אמת — ללא השהיה בין האירוע לזיהוי</span></div>' +
        '<div class="insight-item">🔗 <strong>קורלציה:</strong> <span>' + res.multi_event_count + ' חוקים מזהים דפוסי תקיפה על פני מספר אירועים (APT, Lateral Movement)</span></div>' +
        '<div class="insight-item">🛡 <strong>מודיעין IoC:</strong> <span>' + res.total_ref_lists + ' רשימות חסימה — כתובות IP זדוניות, hashim וממצאי AbuseIPDB</span></div>' +
      '</div>' +
    '</div>';
  }

  wrap.innerHTML = html;
}

// ── SVG Donut Chart ───────────────────────────────────────────────────────────
function svgDonut(dataObj, colorArr, size) {
  const sz = size || 180;
  const r = sz * 0.3;
  const cx = sz / 2, cy = sz / 2;
  const circ = 2 * Math.PI * r;
  const total = Object.values(dataObj).reduce(function(a,b){return a+b;}, 0);
  if (!total) return '';
  let cumLen = 0, i = 0, circles = '';
  for (const lbl in dataObj) {
    const val = dataObj[lbl];
    const segLen = (val / total) * circ;
    const col = colorArr[i % colorArr.length];
    const sw = Math.round(r * 0.46);
    circles += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r.toFixed(1) + '"' +
      ' fill="none" stroke="' + col + '" stroke-width="' + sw + '"' +
      ' stroke-dasharray="' + segLen.toFixed(2) + ' ' + (circ - segLen).toFixed(2) + '"' +
      ' stroke-dashoffset="' + (-cumLen).toFixed(2) + '"' +
      ' transform="rotate(-90 ' + cx + ' ' + cy + ')"/>';
    cumLen += segLen;
    i++;
  }
  return '<svg width="' + sz + '" height="' + sz + '" viewBox="0 0 ' + sz + ' ' + sz + '">' + circles + '</svg>';
}

// ── AI Bot ────────────────────────────────────────────────────────────────────
function openBot(btn) {
  document.querySelectorAll('.tool-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.getElementById('tool-mode').style.display = 'none';
  var bm = document.getElementById('bot-mode');
  bm.style.display = 'flex';
  document.getElementById('bot-input').focus();
}

function closeBot() {
  document.getElementById('bot-mode').style.display = 'none';
  document.getElementById('tool-mode').style.display = 'flex';
  document.querySelectorAll('.tool-btn').forEach(b => b.classList.remove('active'));
}

function sendBotMsg() {
  var input = document.getElementById('bot-input');
  var query = input.value.trim();
  if (!query) return;
  input.value = '';

  var msgs = document.getElementById('bot-messages');
  // User bubble
  msgs.innerHTML += '<div class="bot-msg bot-msg-user"><div class="bot-avatar bot-avatar-user">👤</div>' +
    '<div class="bot-bubble bot-bubble-user">' + escHtml(query) + '</div></div>';

  // Thinking
  var thinkId = 'think-' + Date.now();
  msgs.innerHTML += '<div class="bot-msg" id="' + thinkId + '"><div class="bot-avatar bot-avatar-bot">🧠</div>' +
    '<div class="bot-bubble bot-bubble-bot"><div class="bot-thinking"><div class="bot-dot"></div><div class="bot-dot"></div><div class="bot-dot"></div></div></div></div>';
  msgs.scrollTop = msgs.scrollHeight;

  document.getElementById('bot-send-btn').disabled = true;

  fetch('/api/bot', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({query:query})})
    .then(function(r){return r.json();})
    .then(function(data) {
      var el = document.getElementById(thinkId);
      if (!data.ok) {
        el.querySelector('.bot-bubble').innerHTML = '<span style="color:var(--red)">❌ ' + escHtml(data.error||'Error') + '</span>';
      } else {
        var stepsHtml = '';
        if (data.steps && data.steps.length) {
          stepsHtml = '<div class="bot-steps">' + data.steps.map(function(s){
            return '<span class="bot-step-chip">' + s.tool + '</span>';
          }).join('') + '</div>';
        }
        el.querySelector('.bot-bubble').innerHTML = (data.html||'') + stepsHtml;
      }
      msgs.scrollTop = msgs.scrollHeight;
      document.getElementById('bot-send-btn').disabled = false;
      document.getElementById('bot-input').focus();
    })
    .catch(function(err) {
      var el = document.getElementById(thinkId);
      if (el) el.querySelector('.bot-bubble').innerHTML = '<span style="color:var(--red)">❌ ' + err + '</span>';
      document.getElementById('bot-send-btn').disabled = false;
    });
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Init ──────────────────────────────────────────────────────────────────────
checkStatus();
setInterval(checkStatus, 30000);
loadHistory();
</script>
</body>
</html>"""


if __name__ == "__main__":
    import socket
    port = 5001
    # Try 5001 first, fall back to 5002 if in use
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(("127.0.0.1", port)) == 0:
            port = 5002
    print(f"\n=== Google SecOps Dashboard v2 ===")
    print(f"URL: http://127.0.0.1:{port}")
    print(f"Tools: 24 (10 original + 6 retrohunts/IOC + 8 cases)")
    print(f"AI Bot: /api/bot")
    print(f"Project: {_srv.PROJECT_ID or 'MISSING - set SECOPS_PROJECT_ID in .env (see INSTALL.md)'}")
    print(f"Instance: {_srv.INSTANCE_ID or 'MISSING - set SECOPS_INSTANCE_ID in .env (see INSTALL.md)'}\n")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
