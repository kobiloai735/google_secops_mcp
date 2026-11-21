#!/usr/bin/env python3
"""
Google SecOps MCP Server
Connects Claude Code to Google SecOps (Chronicle) via the MCP protocol.

Authentication (in priority order):
  1. GOOGLE_APPLICATION_CREDENTIALS env var → service account JSON
  2. Application Default Credentials (ADC) via `gcloud auth application-default login`

Required env vars:
  SECOPS_PROJECT_ID   — GCP project ID
  SECOPS_INSTANCE_ID  — SecOps tenant/instance ID (GUID)
  SECOPS_REGION       — API region, default "us"
"""

import os
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

import requests
import google.auth
import google.auth.transport.requests
from google.oauth2 import service_account
from dotenv import load_dotenv
from fastmcp import FastMCP

# .env next to this file, whatever the working directory (e.g. when launched by Claude Code)
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# ── Configuration ────────────────────────────────────────────────────────────

CHRONICLE_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

PROJECT_ID  = os.environ.get("SECOPS_PROJECT_ID", "")
INSTANCE_ID = os.environ.get("SECOPS_INSTANCE_ID", "")
REGION      = os.environ.get("SECOPS_REGION", "us")

BASE_URL       = f"https://{REGION}-chronicle.googleapis.com"
INSTANCE_PATH  = f"projects/{PROJECT_ID}/locations/{REGION}/instances/{INSTANCE_ID}"

# ── Auth helper ──────────────────────────────────────────────────────────────

def _get_credentials():
    """Return refreshed Google credentials (SA file or ADC)."""
    sa_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if sa_file and os.path.exists(sa_file):
        creds = service_account.Credentials.from_service_account_file(
            sa_file, scopes=[CHRONICLE_SCOPE]
        )
    else:
        creds, _ = google.auth.default(scopes=[CHRONICLE_SCOPE])

    if not creds.valid:
        creds.refresh(google.auth.transport.requests.Request())
    return creds


def _headers() -> dict:
    creds = _get_credentials()
    return {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
    }


def _api_url(endpoint: str) -> str:
    """Build the API URL. An endpoint starting with ':' is a method on the instance itself."""
    sep = "" if endpoint.startswith(":") else "/"
    return f"{BASE_URL}/v1alpha/{INSTANCE_PATH}{sep}{endpoint}"


def _request(method: str, endpoint: str,
             payload: Optional[dict] = None,
             params: Optional[dict] = None) -> dict:
    """Execute an authenticated API call and return parsed JSON."""
    url = _api_url(endpoint)
    resp = requests.request(method, url,
                            headers=_headers(),
                            json=payload,
                            params=params,
                            timeout=30)
    try:
        resp.raise_for_status()
    except requests.HTTPError as exc:
        # Surface the API error body so Claude can understand what went wrong
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        raise RuntimeError(f"API error {resp.status_code}: {json.dumps(detail)}") from exc
    return resp.json() if resp.text else {}


# ── Utility ───────────────────────────────────────────────────────────────────

def _iso_ago(hours: int = 24) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── MCP Server ────────────────────────────────────────────────────────────────

mcp = FastMCP("google-secops")


@mcp.tool()
def secops_udm_search(
    query: str,
    hours_back: int = 24,
    start_time: str = "",
    end_time: str = "",
) -> dict:
    """
    Run a UDM (Unified Data Model) search query against Google SecOps.

    Args:
        query:      UDM filter expression, e.g.
                    'metadata.event_type = "USER_LOGIN"'
                    'principal.ip = "10.0.0.1"'
        hours_back: How many hours back to search (default 24).
                    Ignored when start_time/end_time are provided.
        start_time: ISO-8601 UTC start (e.g. "2024-01-01T00:00:00Z").
        end_time:   ISO-8601 UTC end   (e.g. "2024-01-02T00:00:00Z").

    Returns:
        Dict with 'events' list and 'totalCount'.
    """
    if not start_time:
        start_time = _iso_ago(hours_back)
    if not end_time:
        end_time = _iso_now()

    # Use the newer udmEvents endpoint (legacy endpoint not available on all tenants)
    return _request("GET", "udmEvents", params={
        "query": query,
        "timeRange.startTime": start_time,
        "timeRange.endTime": end_time,
    })


@mcp.tool()
def secops_list_rules(page_size: int = 100) -> dict:
    """
    List all YARA-L 2.0 detection rules in the SecOps instance.

    Args:
        page_size: Max rules to return (default 100).

    Returns:
        Dict with 'rules' list; each rule has id, displayName, text, etc.
    """
    return _request("GET", "rules", params={"pageSize": page_size})


@mcp.tool()
def secops_get_rule(rule_id: str) -> dict:
    """
    Retrieve a single YARA-L rule by its ID.

    Args:
        rule_id: Rule ID (e.g. "ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx").

    Returns:
        Full rule object including 'text' (YARA-L source).
    """
    return _request("GET", f"rules/{rule_id}")


@mcp.tool()
def secops_create_rule(rule_text: str) -> dict:
    """
    Create a new YARA-L 2.0 detection rule.

    Args:
        rule_text: Full YARA-L 2.0 rule source code, e.g.:
            rule detect_brute_force {
              meta:
                author = "soc@company.com"
                severity = "HIGH"
              events:
                $e.metadata.event_type = "USER_LOGIN"
                $e.security_result.action = "BLOCK"
              match:
                $e.principal.user.userid over 5m
              condition:
                #e > 10
            }

    Returns:
        Created rule object with assigned rule_id.
    """
    return _request("POST", "rules", {"text": rule_text})


@mcp.tool()
def secops_validate_rule(rule_text: str) -> dict:
    """
    Validate (compile) a YARA-L rule without saving it.
    Use this before create to check for syntax errors.

    Args:
        rule_text: YARA-L 2.0 rule source to validate.

    Returns:
        Dict with 'success': true if the rule compiles. On a compile error
        'success' is absent and 'compilationDiagnostics' lists message,
        position and severity.
    """
    return _request("POST", ":verifyRuleText", {"ruleText": rule_text})


@mcp.tool()
def secops_toggle_rule(
    rule_id: str,
    enabled: bool = True,
    alerting: bool = True,
) -> dict:
    """
    Enable or disable a detection rule (and its alerting).

    Args:
        rule_id:  Rule ID (e.g. "ru_xxxxxxxx-...").
        enabled:  True to enable, False to disable (default True).
        alerting: True to generate alerts when enabled (default True).

    Returns:
        Updated deployment object.
    """
    return _request("PATCH", f"rules/{rule_id}/deployment", {
        "enabled": enabled,
        "alerting": alerting and enabled,
    })


@mcp.tool()
def secops_list_detections(
    rule_id: str,
    hours_back: int = 48,
    start_time: str = "",
    end_time: str = "",
) -> dict:
    """
    List detections (rule matches) for a specific detection rule.

    Args:
        rule_id:    Rule ID to query detections for.
        hours_back: Lookback window in hours (default 48).
        start_time: Optional ISO-8601 start override.
        end_time:   Optional ISO-8601 end override.

    Returns:
        Dict with 'detections' list.
    """
    if not start_time:
        start_time = _iso_ago(hours_back)
    if not end_time:
        end_time = _iso_now()

    return _request("GET", f"rules/{rule_id}/detections", params={
        "startTime": start_time,
        "endTime": end_time,
        "pageSize": 1000,
    })


@mcp.tool()
def secops_list_alerts(
    hours_back: int = 24,
    start_time: str = "",
    end_time: str = "",
    state_filter: str = "",
) -> dict:
    """
    List alerts (aggregated detections) from the SecOps alert feed.

    Args:
        hours_back:   Lookback window in hours (default 24).
        start_time:   Optional ISO-8601 start override.
        end_time:     Optional ISO-8601 end override.
        state_filter: Filter by state: "NEW", "REVIEWED", "CLOSED", or "" for all.

    Returns:
        Dict with 'alerts' list.
    """
    if not start_time:
        start_time = _iso_ago(hours_back)
    if not end_time:
        end_time = _iso_now()

    params: dict = {
        "startTime": start_time,
        "endTime": end_time,
        "pageSize": 1000,
    }
    if state_filter:
        params["state"] = state_filter

    try:
        return _request("GET", "legacy:legacySearchDetections", params=params)
    except RuntimeError as exc:
        # Demo environments may restrict the alerts API to Workspace accounts
        # Return an informative empty result rather than crashing
        if "400" in str(exc) or "404" in str(exc):
            return {
                "alerts": [],
                "_api_note": (
                    "Alerts API (legacySearchDetections) returned "
                    + str(exc)[:120]
                    + " — this endpoint requires the chronicle-backstory OAuth scope "
                    "which is unavailable for Gmail accounts on demo instances."
                ),
            }
        raise


@mcp.tool()
def secops_list_reference_lists(page_size: int = 50) -> dict:
    """
    List all reference lists (allowlists / blocklists) in the instance.

    Args:
        page_size: Max lists to return (default 50).

    Returns:
        Dict with 'referenceLists' array.
    """
    return _request("GET", "referenceLists", params={"pageSize": page_size})


# ── Retrohunts ────────────────────────────────────────────────────────────────

@mcp.tool()
def secops_create_retrohunt(
    rule_id: str,
    start_time: str = "",
    end_time: str = "",
    hours_back: int = 168,
) -> dict:
    """
    Run an existing YARA-L rule against historical data (retrohunt).
    Use this to discover threats that were missed when the rule didn't exist yet.

    Args:
        rule_id:    Rule ID to retrohunt with (e.g. "ru_xxxxxxxx-...").
        start_time: ISO-8601 UTC start (e.g. "2024-01-01T00:00:00Z").
        end_time:   ISO-8601 UTC end   (e.g. "2024-01-08T00:00:00Z").
        hours_back: Lookback window if start/end not given (default 168 = 7 days).

    Returns:
        Created retrohunt object with id and state.
    """
    if not start_time:
        start_time = _iso_ago(hours_back)
    if not end_time:
        end_time = _iso_now()

    return _request("POST", f"rules/{rule_id}/retrohunts", {
        "retrohuntStartTime": start_time,
        "retrohuntEndTime": end_time,
    })


@mcp.tool()
def secops_get_retrohunt(rule_id: str, retrohunt_id: str) -> dict:
    """
    Get the status and results of a specific retrohunt.

    Args:
        rule_id:      Rule ID the retrohunt belongs to.
        retrohunt_id: Retrohunt ID (e.g. "oh_xxxxxxxx-...").

    Returns:
        Retrohunt object with state, progressPercentage, and retrohuntStartTime/EndTime.
    """
    return _request("GET", f"rules/{rule_id}/retrohunts/{retrohunt_id}")


@mcp.tool()
def secops_list_retrohunts(rule_id: str, page_size: int = 50) -> dict:
    """
    List all retrohunts for a given rule.

    Args:
        rule_id:   Rule ID to list retrohunts for.
        page_size: Max results to return (default 50).

    Returns:
        Dict with 'retrohunts' list.
    """
    return _request("GET", f"rules/{rule_id}/retrohunts",
                    params={"pageSize": page_size})


# ── Reference Lists CRUD ──────────────────────────────────────────────────────

@mcp.tool()
def secops_create_reference_list(
    name: str,
    lines: list,
    description: str = "",
    syntax_type: str = "PLAIN_TEXT_STRING",
) -> dict:
    """
    Create a new reference list (allowlist / blocklist / IOC list).

    Args:
        name:        Unique name for the list (e.g. "malicious_ips").
        lines:       List of string entries (e.g. ["1.2.3.4", "5.6.7.8"]).
        description: Human-readable description.
        syntax_type: "PLAIN_TEXT_STRING" (default), "CIDR", or "REGEX".

    Returns:
        Created reference list object with name and entry count.
    """
    return _request("POST", "referenceLists", {
        "name": name,
        "description": description,
        "lines": lines,
        "syntaxType": syntax_type,
    })


@mcp.tool()
def secops_update_reference_list(
    list_id: str,
    lines: list,
    description: str = "",
) -> dict:
    """
    Replace the entries of an existing reference list (full overwrite).

    Args:
        list_id:     Reference list ID or name.
        lines:       New list of string entries (replaces existing entries).
        description: Updated description (leave empty to keep existing).

    Returns:
        Updated reference list object.
    """
    body: dict = {"lines": lines}
    if description:
        body["description"] = description
    return _request("PATCH", f"referenceLists/{list_id}", body)


@mcp.tool()
def secops_delete_reference_list(list_id: str) -> dict:
    """
    Delete a reference list permanently.

    Args:
        list_id: Reference list ID or name.

    Returns:
        Empty dict on success.
    """
    return _request("DELETE", f"referenceLists/{list_id}")


# ── Cases (SOAR) ─────────────────────────────────────────────────────────────

@mcp.tool()
def secops_list_cases(
    page_size: int = 50,
    state_filter: str = "",
    priority_filter: str = "",
) -> dict:
    """
    List security cases (SOAR incidents) in the SecOps instance.

    Args:
        page_size:       Max cases to return (default 50).
        state_filter:    Filter by state: "OPEN", "CLOSED", or "" for all.
        priority_filter: Filter by priority: "LOW", "MEDIUM", "HIGH", "CRITICAL".

    Returns:
        Dict with 'cases' list; each case has id, displayId, name, priority, stage, etc.
    """
    params: dict = {"pageSize": page_size}
    filters = []
    if state_filter:
        filters.append(f"state = \"{state_filter}\"")
    if priority_filter:
        filters.append(f"priority = \"{priority_filter}\"")
    if filters:
        params["filter"] = " AND ".join(filters)
    return _request("GET", "cases", params=params)


@mcp.tool()
def secops_get_case(case_id: str) -> dict:
    """
    Retrieve full details of a specific security case.

    Args:
        case_id: Case ID (e.g. "cases/1234" or just "1234").

    Returns:
        Full case object with alerts, entities, comments, timeline, and SLA info.
    """
    cid = case_id.replace("cases/", "")
    return _request("GET", f"cases/{cid}")


@mcp.tool()
def secops_update_case(
    case_id: str,
    priority: str = "",
    stage: str = "",
    assignee: str = "",
    name: str = "",
) -> dict:
    """
    Update a case's priority, stage, assignee, or display name.

    Args:
        case_id:  Case ID.
        priority: "LOW", "MEDIUM", "HIGH", or "CRITICAL".
        stage:    Stage name (e.g. "Investigation", "Containment", "Eradication").
        assignee: Analyst email to assign the case to.
        name:     New display name for the case.

    Returns:
        Updated case object.
    """
    body: dict = {}
    update_mask = []
    if priority:
        body["priority"] = priority
        update_mask.append("priority")
    if stage:
        body["stage"] = stage
        update_mask.append("stage")
    if assignee:
        body["assignee"] = assignee
        update_mask.append("assignee")
    if name:
        body["displayName"] = name
        update_mask.append("displayName")

    cid = case_id.replace("cases/", "")
    return _request("PATCH", f"cases/{cid}",
                    payload=body,
                    params={"updateMask": ",".join(update_mask)})


@mcp.tool()
def secops_add_case_comment(case_id: str, comment: str) -> dict:
    """
    Add a comment (analyst note) to a security case.

    Args:
        case_id: Case ID.
        comment: Text of the comment to add.

    Returns:
        Created comment object with id and createTime.
    """
    cid = case_id.replace("cases/", "")
    return _request("POST", f"cases/{cid}/caseComments", {"comment": comment})


@mcp.tool()
def secops_list_case_alerts(case_id: str, page_size: int = 100) -> dict:
    """
    List all alerts associated with a specific case.

    Args:
        case_id:   Case ID.
        page_size: Max alerts to return (default 100).

    Returns:
        Dict with 'caseAlerts' list.
    """
    cid = case_id.replace("cases/", "")
    return _request("GET", f"cases/{cid}/caseAlerts",
                    params={"pageSize": page_size})


@mcp.tool()
def secops_generate_case_report(case_id: str) -> dict:
    """
    Generate a full incident report for a case (PDF-ready summary).

    Args:
        case_id: Case ID.

    Returns:
        Report content with timeline, entities, actions taken, and findings.
    """
    cid = case_id.replace("cases/", "")
    return _request("POST", f"cases/{cid}:generateReport", {})


@mcp.tool()
def secops_merge_cases(case_ids: list, target_case_id: str = "") -> dict:
    """
    Merge multiple cases into one (de-duplicate incidents).

    Args:
        case_ids:       List of case IDs to merge (e.g. ["1234", "5678"]).
        target_case_id: The case to merge everything INTO. If empty, uses first ID.

    Returns:
        Merged case object.
    """
    target = target_case_id or case_ids[0]
    source_ids = [cid for cid in case_ids if cid != target]
    target_clean = target.replace("cases/", "")
    return _request("POST", f"cases/{target_clean}:merge", {
        "caseIds": [f"cases/{cid.replace('cases/', '')}" for cid in source_ids]
    })


@mcp.tool()
def secops_bulk_close_cases(
    case_ids: list,
    reason: str = "Resolved",
    comment: str = "",
) -> dict:
    """
    Close multiple cases at once.

    Args:
        case_ids: List of case IDs to close.
        reason:   Closure reason: "Resolved", "False Positive", "Duplicate", etc.
        comment:  Optional closing comment added to all cases.

    Returns:
        Dict with 'closedCases' count and any errors.
    """
    return _request("POST", "cases:executeBulkClose", {
        "caseIds": [f"cases/{cid.replace('cases/', '')}" for cid in case_ids],
        "reason": reason,
        "comment": comment,
    })


# ── Connection Test ───────────────────────────────────────────────────────────

@mcp.tool()
def secops_connection_test() -> dict:
    """
    Test connectivity and authentication to the SecOps API.
    Call this first to verify the MCP server is correctly configured.

    Returns:
        Dict with 'status', 'project_id', 'instance_id', 'region',
        and either 'rule_count' (success) or 'error' (failure).
    """
    info: dict = {
        "status": "unknown",
        "project_id": PROJECT_ID,
        "instance_id": INSTANCE_ID,
        "region": REGION,
    }
    if not PROJECT_ID or not INSTANCE_ID:
        info["status"] = "misconfigured"
        info["error"] = (
            "SECOPS_PROJECT_ID and SECOPS_INSTANCE_ID env vars must be set. "
            "Find the Instance ID at: Settings → SIEM Settings → Tenant Information"
        )
        return info

    try:
        result = _request("GET", "rules", params={"pageSize": 1})
        info["status"] = "ok"
        info["rule_count"] = len(result.get("rules", []))
    except Exception as exc:
        info["status"] = "error"
        info["error"] = str(exc)

    return info


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
