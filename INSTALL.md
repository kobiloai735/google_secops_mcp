# 🛠️ מדריך התקנה — Google SecOps MCP

המדריך הזה מיועד למי שמקבל את הפרויקט ורוצה להריץ אותו מול טנאנט Google SecOps (Chronicle).
בסוף ההתקנה יהיו לכם:

- **דאשבורד ווב** על `http://127.0.0.1:5001`
- **שרת MCP** עם 24 כלים, שאפשר לחבר ל-Claude Code ולשאול אותו בשפה חופשית על חוקים, התראות, IOC ותיקים

> ⏱️ זמן משוער: 15–20 דקות, כולל קבלת הרשאות.

---

## שלב 0 — מה צריך לפני שמתחילים

| רכיב | גרסה | הורדה |
|------|------|-------|
| Python | **3.10 ומעלה** | [python.org/downloads](https://www.python.org/downloads/) — ב-Windows סמנו "Add Python to PATH" |
| Git | כל גרסה | [git-scm.com](https://git-scm.com/downloads) |
| Google Cloud CLI (`gcloud`) | כל גרסה | [cloud.google.com/sdk/docs/install](https://cloud.google.com/sdk/docs/install) — נדרש לאפשרות א' בשלב 5 |
| Claude Code | לא חובה | [claude.com/claude-code](https://claude.com/claude-code) — רק אם רוצים את שרת ה-MCP |

בנוסף צריך **חשבון Google עם גישה לטנאנט SecOps**. אם אין לכם, בקשו ממנהל ה-SecOps / Google Cloud בארגון (ראו שלב 3).

---

## שלב 1 — הורדת הפרויקט

המאגר ב-GitHub **פרטי**. כדי לשבט אותו, בעל המאגר צריך להוסיף אתכם כ-Collaborator ותצטרכו לאשר את ההזמנה במייל.

```bash
git clone https://github.com/kobiloai735/google_secops_mcp.git
cd google_secops_mcp
```

קיבלתם קובץ ZIP במקום? חלצו אותו ופתחו טרמינל בתוך התיקייה `google_secops_mcp`.

---

## שלב 2 — התקנת תלויות

מומלץ סביבה וירטואלית, כדי לא להתנגש עם חבילות אחרות במחשב:

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## שלב 3 — הרשאות ב-Google Cloud (פעם אחת, אצל המנהל)

ה-API של SecOps עובד עם הרשאות IAM של Google Cloud, על **הפרויקט שמקושר לטנאנט**.
מנהל הפרויקט נותן לכם (לחשבון ה-Google שלכם, או ל-Service Account) אחד מהתפקידים האלה:

| תפקיד | Role ID | מתי |
|-------|---------|-----|
| Chronicle API Viewer | `roles/chronicle.viewer` | **מומלץ להתחלה** — קריאה בלבד: חוקים, גילויים, חיפוש UDM, רשימות |
| Chronicle API Editor | `roles/chronicle.editor` | גם כתיבה: יצירת חוקים, הפעלה/כיבוי, Retrohunt, עדכון רשימות |

איפה המנהל עושה את זה: Google Cloud Console ← בוחרים את הפרויקט ← **IAM & Admin** ← **IAM** ← **Grant access** ← מזינים את המייל ובוחרים את התפקיד.

> ⚠️ בפרויקט יש כלים שמשנים מידע בטנאנט: `create_rule`, `toggle_rule`, `delete_reference_list`, `bulk_close_cases` ועוד.
> עם תפקיד Viewer הם פשוט ייכשלו עם 403, ולכן זו נקודת פתיחה בטוחה.
> כלי ה-Cases עשויים לדרוש הרשאות SOAR נוספות. אם הם מחזירים 403, פנו למנהל.

---

## שלב 4 — שלושת הערכים של הטנאנט (`.env`)

מעתיקים את התבנית:

```powershell
copy .env.example .env      # Windows
```
```bash
cp .env.example .env        # macOS / Linux
```

ופותחים את `.env` בעורך. צריך למלא שלושה ערכים:

| משתנה | מה זה | איפה מוצאים |
|-------|-------|-------------|
| `SECOPS_PROJECT_ID` | מזהה הפרויקט ב-Google Cloud שמקושר ל-SecOps (טקסט, למשל `my-secops-project`) | Google Cloud Console ← בורר הפרויקטים בראש העמוד ← עמודת **ID** (לא ה-Name ולא ה-Number). אם לא ברור איזה פרויקט מקושר לטנאנט, שאלו את מנהל ה-SecOps |
| `SECOPS_INSTANCE_ID` | ה-Customer ID של הטנאנט (GUID בתבנית `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) | בממשק SecOps: **Settings** ← **SIEM Settings**, בעמוד הפרופיל / פרטי הטנאנט. מיקום השדה משתנה בין גרסאות ממשק, ואם לא מצאתם — מנהל ה-SecOps יודע |
| `SECOPS_REGION` | האזור של הטנאנט | ברוב הטנאנטים `us`. ערכים נוספים: `eu`, `europe`, `europe-west2`, `asia-southeast1`, `me-west1` ועוד. זו אותה קידומת שמופיעה בכתובת ה-API: `https://<region>-chronicle.googleapis.com` |

דוגמה ל-`.env` מלא:
```env
SECOPS_PROJECT_ID=my-secops-project
SECOPS_INSTANCE_ID=1a2b3c4d-1111-2222-3333-444455556666
SECOPS_REGION=us
```

> 🔒 הקובץ `.env` לא נכנס ל-Git (הוא ב-`.gitignore`). אל תשלחו אותו לאחרים. לכל משתמש יש `.env` משלו.

---

## שלב 5 — "המפתח": אימות מול Google

הפרויקט **לא** משתמש ב-API key רגיל. הוא מזדהה מול Google באחת משלוש הדרכים הבאות, ומספיקה אחת מהן.

### אפשרות א' — התחברות עם החשבון האישי (מומלץ)

מתאים לרוב המשתמשים. אין קובץ מפתח לשמור, ו-Google מנפיקה טוקן מתחדש.

```bash
gcloud auth application-default login
```

ייפתח דפדפן. התחברו עם החשבון **שקיבל את התפקיד בשלב 3** ואשרו.
הקובץ נשמר אוטומטית במקום ש-Google מחפשת:

- Windows: `%APPDATA%\gcloud\application_default_credentials.json`
- macOS / Linux: `~/.config/gcloud/application_default_credentials.json`

לביטול בעתיד: `gcloud auth application-default revoke`

### אפשרות ב' — קובץ מפתח של Service Account (JSON)

מתאים לשרת או לחשבון שירות משותף. **זה מפתח סודי**: כל מי שמחזיק בקובץ יכול לפעול בשם החשבון.

1. Google Cloud Console ← **IAM & Admin** ← **Service Accounts** ← בוחרים את הפרויקט.
2. לוחצים על המייל של ה-Service Account (או **Create service account**, ונותנים לו תפקיד משלב 3).
3. לשונית **Keys** ← **Add key** ← **Create new key** ← **JSON** ← **Create**. הקובץ יורד פעם אחת בלבד.
4. שומרים את הקובץ **מחוץ לתיקיית הפרויקט**, למשל `C:\keys\secops-key.json`.
5. מוסיפים ל-`.env`:
   ```env
   GOOGLE_APPLICATION_CREDENTIALS=C:\keys\secops-key.json
   ```

> ⚠️ אם הכפתור חסום או מופיעה שגיאה, כנראה שמדיניות הארגון `iam.disableServiceAccountKeyCreation` פעילה. בארגונים שנוצרו מאז מאי 2024 היא פעילה כברירת מחדל. במקרה כזה השתמשו באפשרות א'.
> יצירת מפתח דורשת את התפקיד Service Account Key Admin (`roles/iam.serviceAccountKeyAdmin`).

### אפשרות ג' — בלי להתקין gcloud

```bash
python oauth_login.py
```

הסקריפט פותח דפדפן ושומר את אותו קובץ כמו באפשרות א'. השתמשו בו רק אם אי אפשר להתקין gcloud.

---

## שלב 6 — בדיקת חיבור

```bash
python -c "from server import secops_connection_test; print(secops_connection_test())"
```

תוצאה תקינה:
```
{'status': 'ok', 'project_id': '...', 'instance_id': '...', 'region': 'us', 'rule_count': 1}
```

---

## שלב 7 — הפעלה

### דאשבורד
```bash
python dashboard.py
```
ופותחים בדפדפן את `http://127.0.0.1:5001`. אם הפורט תפוס, הדאשבורד יעלה על 5002.

### חיבור ל-Claude Code כשרת MCP

מריצים פעם אחת, עם **הנתיב המלא** ל-`server.py` אצלכם:

**Windows:**
```powershell
claude mcp add google_secops --scope user -- python "C:\path\to\google_secops_mcp\server.py"
```
**macOS / Linux:**
```bash
claude mcp add google_secops --scope user -- python3 /path/to/google_secops_mcp/server.py
```

השרת קורא את `.env` מהתיקייה שלו, כך שאין צורך להעביר את הערכים בפקודה.
אם התקנתם בסביבה וירטואלית (שלב 2), החליפו את `python` בנתיב המלא לפייתון שלה, למשל `C:\path\to\google_secops_mcp\.venv\Scripts\python.exe`.

אחרי הפעלה מחדש של Claude Code, בדקו עם `/mcp` שהשרת `google_secops` מחובר, ונסו למשל:
> "תריץ connection test ל-SecOps ותציג לי את 10 החוקים האחרונים"

---

## 🔧 פתרון תקלות

| שגיאה | סיבה | פתרון |
|-------|------|-------|
| `status: misconfigured` | חסר `SECOPS_PROJECT_ID` או `SECOPS_INSTANCE_ID` | בדקו שקובץ `.env` קיים **בתיקיית הפרויקט** ומלא (שלב 4) |
| `DefaultCredentialsError` / `Could not automatically determine credentials` | לא בוצע אימות | שלב 5 |
| `API error 403` / `PERMISSION_DENIED` | לחשבון אין תפקיד על הפרויקט, או שהתחברתם עם חשבון אחר | שלב 3. בדקו עם איזה חשבון התחברתם: `gcloud auth list` |
| `API error 404` | Project ID, Instance ID או Region שגויים | בדקו את שלושת הערכים בשלב 4. Region שגוי הוא הגורם הנפוץ |
| `list_alerts` נכשל | ה-endpoint דורש scope ‏`chronicle-backstory`, שלא זמין לחשבונות Gmail | ידוע. שאר הכלים עובדים |
| `ModuleNotFoundError` | התלויות לא הותקנו בפייתון שמריץ את הקוד | הפעילו את הסביבה הווירטואלית והריצו שוב `pip install -r requirements.txt` |

---

## 📁 מבנה הפרויקט

| קובץ | תפקיד |
|------|-------|
| `server.py` | שרת MCP — 24 כלים מול ה-Chronicle API |
| `dashboard.py` | דאשבורד Flask על פורט 5001 |
| `oauth_login.py` | התחברות ל-Google בלי gcloud (שלב 5, אפשרות ג') |
| `.env.example` | תבנית לקובץ `.env` |
| `requirements.txt` | תלויות Python |
| `dev_tools/` | כלי דיבאג ישנים של המפתח. **לא נדרשים להתקנה** |
| `README.md` | תיעוד מלא: ארכיטקטורה, רשימת כלים, שדות UDM |
