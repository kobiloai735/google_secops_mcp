# 🛡️ Google SecOps MCP Dashboard

> **Web dashboard + MCP server** לניהול וחקירת Google SecOps (Chronicle) דרך Claude Code.
> A full-featured web dashboard and MCP server for Google SecOps (Chronicle) via Claude Code.

---

## 📋 תוכן עניינים | Table of Contents

1. [סקירה כללית | Overview](#-סקירה-כללית--overview)
2. [ארכיטקטורה | Architecture](#-ארכיטקטורה--architecture)
3. [קבצים | Files](#-קבצים--files)
4. [דרישות | Prerequisites](#-דרישות--prerequisites)
5. [התקנה ושחזור | Setup & Recovery](#-התקנה-ושחזור--setup--recovery)
6. [משתני סביבה | Environment Variables](#-משתני-סביבה--environment-variables)
7. [הפעלה | Running](#-הפעלה--running)
8. [יכולות הדאשבורד | Dashboard Features](#-יכולות-הדאשבורד--dashboard-features)
9. [MCP Tools Reference](#-mcp-tools-reference)
10. [UDM Field Reference](#-udm-field-reference)

---

## 🎯 סקירה כללית | Overview

**עברית:**
מערכת זו מאפשרת לצוות ה-SOC לתקשר עם Google SecOps (Chronicle) דרך שני ערוצים:
1. **MCP Server** (`server.py`) — מאפשר ל-Claude Code לקרוא לכל 10 פונקציות ה-API של Chronicle ישירות
2. **Web Dashboard** (`dashboard.py`) — ממשק ויזואלי מתקדם על פורט 5001 עם ניתוח, גרפים, ותיעוד

**English:**
This system enables SOC teams to interact with Google SecOps (Chronicle) through two channels:
1. **MCP Server** (`server.py`) — Exposes all 10 Chronicle API functions as Claude Code tools
2. **Web Dashboard** (`dashboard.py`) — Advanced visual interface on port 5001 with analysis, charts, and documentation

---

## 🏗️ ארכיטקטורה | Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Claude Code (AI)                      │
│                         │                               │
│              ┌──────────┴──────────┐                    │
│              │                     │                    │
│         MCP Protocol          HTTP Browser              │
│              │                     │                    │
│         server.py            dashboard.py               │
│         (FastMCP)            (Flask :5001)              │
│              │                     │                    │
│              └──────────┬──────────┘                    │
│                         │                               │
│              Google SecOps Chronicle API                 │
│         https://{region}-chronicle.googleapis.com        │
│              v1alpha/projects/{id}/instances/{id}/        │
└─────────────────────────────────────────────────────────┘
```

### Authentication Flow | תהליך אימות
```
1. GOOGLE_APPLICATION_CREDENTIALS → Service Account JSON (production)
2. Application Default Credentials (ADC) → gcloud auth application-default login (dev)
3. Bearer Token → injected in every API request: Authorization: Bearer {token}
```

---

## 📁 קבצים | Files

| קובץ | תיאור | Description |
|------|--------|-------------|
| `server.py` | MCP server עם 10 כלים לChronicle API | MCP server with 10 Chronicle API tools |
| `dashboard.py` | Flask web dashboard על פורט 5001 | Flask web dashboard on port 5001 |
| `requirements.txt` | תלויות Python | Python dependencies |
| `.env.example` | תבנית למשתני סביבה (העתק ל-.env) | Environment variables template (copy to .env) |
| `auth_server.py` | עזר לאימות OAuth2 | OAuth2 authentication helper |
| `oauth_login.py` | כלי להשגת OAuth tokens | OAuth token acquisition tool |
| `token_test.py` | בדיקת tokens | Token testing utility |
| `get_token.js` | JavaScript לקבלת token | JavaScript token helper |
| `.claude/launch.json` | הגדרות Claude Preview server | Claude Preview server configuration |

---

## ⚙️ דרישות | Prerequisites

### Software
- **Python 3.9+** — [python.org](https://python.org)
- **Google Cloud SDK (gcloud)** — [cloud.google.com/sdk](https://cloud.google.com/sdk)
- **Git** — [git-scm.com](https://git-scm.com)
- **Claude Code** (אופציונלי לשימוש כ-MCP) — [claude.ai/code](https://claude.ai/code)

### Google Cloud Permissions | הרשאות נדרשות
- Role: `Chronicle API Viewer` (לקריאה) / `Chronicle API Editor` (לכתיבה)
- OAuth Scope: `https://www.googleapis.com/auth/cloud-platform`
- לגישה להתראות: `chronicle-backstory` scope (דורש Workspace account)

---

## 🔧 התקנה ושחזור | Setup & Recovery

### שלב 1 — שיבוט המאגר | Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/google_secops_mcp.git
cd google_secops_mcp
```

### שלב 2 — התקנת תלויות | Install Dependencies
```bash
pip install -r requirements.txt
```

### שלב 3 — הגדרת קובץ .env | Configure Environment
```bash
# העתק את קובץ התבנית | Copy template file
cp .env.example .env

# ערוך את הקובץ עם הפרטים שלך | Edit with your details
notepad .env      # Windows
# or: nano .env  # Linux/Mac
```

מלא את הערכים הבאים | Fill in the following values:
```env
SECOPS_PROJECT_ID=your-gcp-project-id
SECOPS_INSTANCE_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
SECOPS_REGION=us
# GOOGLE_APPLICATION_CREDENTIALS=C:\path\to\service_account.json  # optional
```

**איפה למצוא את SECOPS_INSTANCE_ID | Where to find SECOPS_INSTANCE_ID:**
- Chronicle UI → Settings → SIEM Settings → Tenant Information

### שלב 4 — אימות Google Cloud | Google Cloud Authentication

**אפשרות א׳: Application Default Credentials (לפיתוח)**
```bash
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
```

**אפשרות ב׳: Service Account (לפרודקשן)**
```bash
# צור service account key ב-GCP Console ועדכן .env:
# GOOGLE_APPLICATION_CREDENTIALS=C:\path\to\key.json
```

### שלב 5 — הפעלה | Run
```bash
python dashboard.py
# פתח דפדפן | Open browser: http://127.0.0.1:5001
```

---

## 🔑 משתני סביבה | Environment Variables

| משתנה | חובה | ברירת מחדל | תיאור |
|--------|------|-----------|--------|
| `SECOPS_PROJECT_ID` | ✅ | — | GCP Project ID המקושר לטנאנט |
| `SECOPS_INSTANCE_ID` | ✅ | — | GUID של מופע Chronicle |
| `SECOPS_REGION` | ❌ | `us` | אזור API: `us`, `eu`, `asia-southeast1` |
| `GOOGLE_APPLICATION_CREDENTIALS` | ❌ | ADC | נתיב לקובץ Service Account JSON |

---

## ▶️ הפעלה | Running

### הפעלת ה-Dashboard
```bash
python dashboard.py
# → http://127.0.0.1:5001
```

### הפעלת MCP Server (לשימוש עם Claude Code)
```bash
python server.py
```

### Claude Preview (דרך Claude Code)
הגדרה ב-`.claude/launch.json`:
```json
{
  "name": "secops-dashboard",
  "runtimeExecutable": "python",
  "runtimeArgs": ["dashboard.py"],
  "port": 5001
}
```
הפעלה: `preview_start("secops-dashboard")`

### הוספת ל-Claude Code MCP (`~/.claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "google-secops": {
      "command": "python",
      "args": ["C:\\path\\to\\server.py"],
      "env": {
        "SECOPS_PROJECT_ID": "your-project",
        "SECOPS_INSTANCE_ID": "your-instance-guid",
        "SECOPS_REGION": "us"
      }
    }
  }
}
```

---

## 🎛️ יכולות הדאשבורד | Dashboard Features

### Connectivity
| כפתור | תיאור |
|--------|--------|
| 🔌 **Connection Test** | בדיקת חיבור עם תצוגת שלבים (5 שלבים) + טאב תיעוד מלא |

### Detection Rules
| כפתור | תיאור |
|--------|--------|
| 📋 **List Rules** | רשימת כל 78 חוקי YARA-L עם טבלה |
| 🔍 **Get Rule** | שליפת חוק בודד + קוד YARA-L מלא |
| ✏️ **Create Rule** | יצירת חוק YARA-L חדש |
| ✅ **Validate Rule** | בדיקת תחביר ללא שמירה |
| ⚡ **Toggle Rule** | הפעלה/כיבוי חוק |

### Detections & Alerts
| כפתור | תיאור |
|--------|--------|
| 🎯 **List Detections** | גילויים של חוק ספציפי |
| 🚨 **List Alerts** | התראות מה-feed |
| 📚 **Reference Lists** | רשימות IOC |
| 🔎 **UDM Search** | חיפוש אירועים |

### Analysis (ניתוח)
| כפתור | תיאור |
|--------|--------|
| 📊 **Analyze All Rules** | ניתוח כל החוקים עם breakdown לפי קטגוריה |
| 🔍 **48h Alert Analysis** | ניתוח 48 שעות של התראות |
| 📅 **Timeline & Trends** | גרפי זמן וטרנדים |
| 🔬 **Intelligence Report** | דוח מלא עם donut charts + SOC insights בעברית |

### Explorer
| כפתור | תיאור |
|--------|--------|
| 🤖 **MCP Explorer** | חקרן יכולות: 10 כלי MCP, שדות UDM, יכולות AI |

---

## 🛠️ MCP Tools Reference

| פונקציה | Method | Endpoint | פרמטרים |
|---------|--------|----------|---------|
| `secops_connection_test` | GET | `rules?pageSize=1` | — |
| `secops_list_rules` | GET | `rules` | `page_size` |
| `secops_get_rule` | GET | `rules/{id}` | `rule_id`* |
| `secops_create_rule` | POST | `rules` | `rule_text`* |
| `secops_validate_rule` | POST | `rules:verifyRule` | `rule_text`* |
| `secops_toggle_rule` | PATCH | `rules/{id}/deployment` | `rule_id`, `enabled`, `alerting` |
| `secops_list_detections` | GET | `rules/{id}/detections` | `rule_id`*, `hours_back` |
| `secops_list_alerts` | GET | `legacy:legacySearchDetections` | `hours_back`, `state_filter` |
| `secops_list_reference_lists` | GET | `referenceLists` | `page_size` |
| `secops_udm_search` | GET | `udmEvents` | `query`*, `hours_back` |

`*` = חובה | required

---

## 🗃️ UDM Field Reference

### שדות עיקריים לחיפוש | Key Search Fields

```
# Metadata
metadata.event_type = "USER_LOGIN"
metadata.event_type = "NETWORK_CONNECTION"
metadata.event_type = "PROCESS_LAUNCH"
metadata.event_type = "FILE_MODIFICATION"

# Source (Principal)
principal.ip = "10.0.0.1"
principal.hostname = "WORKSTATION-01"
principal.user.userid = "jsmith"
principal.process.command_line = /powershell/i

# Target
target.ip = "1.2.3.4"
target.port = 443
target.url = "https://example.com"
target.file.sha256 = "abc123..."

# Network
network.dns.question.name = "evil.com"
network.http.method = "POST"
network.direction = "OUTBOUND"

# Security Result
security_result.severity = "HIGH"
security_result.action = "BLOCK"
security_result.threat_name = "Trojan.Generic"
```

### דוגמאות שאילתה | Query Examples

```bash
# כניסות כושלות | Failed logins
metadata.event_type = "USER_LOGIN" AND security_result.action = "BLOCK"

# PowerShell חשוד | Suspicious PowerShell
metadata.event_type = "PROCESS_LAUNCH" AND target.process.command_line = /powershell/i

# חיבורים יוצאים ל-80 | Outbound HTTP port 80
metadata.event_type = "NETWORK_CONNECTION" AND target.port = 80 AND network.direction = "OUTBOUND"

# שאילתת DNS | DNS queries
metadata.event_type = "NETWORK_DNS" AND network.dns.question.name != ""

# כל פעילות משתמש | All user activity
principal.user.userid = "jsmith"
```

---

## 📊 מצב המערכת הנוכחי | Current System State

> עודכן לאחרונה | Last updated: April 2026

- **78** חוקי YARA-L פעילים | Active YARA-L rules
- **59** חוקי LIVE (real-time detection) | LIVE rules
- **27** רשימות reference | Reference lists
- **Coverage Score: 80%** | Security coverage score
- **10 קטגוריות** | Attack categories covered

---

## 🔄 שחזור מהיר | Quick Recovery Checklist

```
□ 1. git clone [repo-url]
□ 2. pip install -r requirements.txt
□ 3. cp .env.example .env && nano .env   # fill in credentials
□ 4. gcloud auth application-default login
□ 5. python dashboard.py
□ 6. פתח http://127.0.0.1:5001
□ 7. לחץ "Connection Test" → "Run Analysis" לאימות חיבור
```

---

## 🧑‍💻 פיתוח | Development

```bash
# הפעלת שרת בדיקה | Run dev server
python dashboard.py

# בדיקת חיבור API ישיר | Direct API connection test
python -c "from server import secops_connection_test; print(secops_connection_test())"

# בדיקת imports | Test imports
python -c "import server; print('server OK'); import dashboard; print('dashboard OK')"
```

---

## 📄 רישיון | License

פרטי — Internal use only | Private — Internal use only

---

*Built with ❤️ using Claude Code + FastMCP + Flask + Google SecOps Chronicle API*
