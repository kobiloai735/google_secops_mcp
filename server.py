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

load_dotenv()

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


def _request(method: str, endpoint: str,
             payload: Optional[dict] = None,
             params: Optional[dict] = None) -> dict:
    """Execute an authenticated API call and return parsed JSON."""
    url = f"{BASE_URL}/v1alpha/{INSTANCE_PATH}/{endpoint}"
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
        Dict with 'success' bool and 'errors' list (if any).
    """
    return _request("POST", "rules:verifyRule", {"rule": {"text": rule_text}})


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
