"""PoC-to-Action parser — turn web search snippets into executable Vault calls.

Scans text for curl commands, Python requests calls, hvac usage, and Vault
CLI commands.  Converts each into a ``run_raw_vault_request`` parameter dict
that the agent can execute directly.

Used by the agent's web-search auto-trigger so that internet research
becomes immediate action, not just passive information.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Parsed action
# ---------------------------------------------------------------------------


@dataclass
class PoCAction:
    """A single executable action extracted from web search results."""

    method: str  # GET, POST, PUT, DELETE, LIST
    path: str  # Vault API path, e.g. "auth/token/create"
    body: dict | str | None = None
    headers: dict = field(default_factory=dict)
    source_url: str = ""
    source_snippet: str = ""
    description: str = ""
    confidence: str = "medium"  # high, medium, low

    def to_tool_params(self, vault_addr: str = "") -> dict[str, Any]:
        """Convert to ``run_raw_vault_request`` parameters."""
        params: dict[str, Any] = {
            "method": self.method,
            "path": self.path,
        }
        if vault_addr:
            params["vault_addr"] = vault_addr
        if self.body:
            params["body"] = json.dumps(self.body) if isinstance(self.body, dict) else str(self.body)
        return params

    def to_display(self) -> str:
        """Human-readable one-liner for the agent suggestion."""
        body_hint = ""
        if self.body:
            raw = json.dumps(self.body) if isinstance(self.body, dict) else str(self.body)
            body_hint = f" body={raw[:60]}"
        return (
            f"[{self.confidence}] {self.method} {self.path}{body_hint}"
            f"  — {self.description[:80]}"
        )


# ---------------------------------------------------------------------------
# Regex patterns for known PoC formats
# ---------------------------------------------------------------------------

# curl -X POST https://vault:8200/v1/auth/token/create -H 'X-Vault-Token: root' -d '{"policies": ["admin"]}'
_CURL_RE = re.compile(
    r'curl\s+'
    r'(?:-X\s+(?P<method>GET|POST|PUT|DELETE|LIST)\s+)?'
    r'(?:--request\s+(?P<method2>GET|POST|PUT|DELETE|LIST)\s+)?'
    r'(?P<url>https?://[^\s\'"]+/v1/(?P<path>[^\s\'"?]+))'
    r'(?:\s+-H\s+[\'\"](?P<header>[^\'\"]+)[\'\"])*'
    r'(?:\s+(?:-d|--data|--data-raw)\s+[\'\"](?P<body>\{[^\'\"]+\})[\'\"])?',
    re.IGNORECASE,
)

# requests.post("https://vault:8200/v1/...", headers={...}, json={...})
_REQUESTS_RE = re.compile(
    r'requests\.(?P<method>get|post|put|delete|patch|head)\s*\(\s*'
    r'[\'\"](?P<url>https?://[^\'\"]+/v1/(?P<path>[^\'\"]+))[\'\"]'
    r'(?:\s*,\s*(?P<args>.*?))?\s*\)',
    re.IGNORECASE | re.DOTALL,
)

# hvac.Client(url='https://vault:8200')
_HVAC_RE = re.compile(
    r'hvac\.Client\s*\(\s*'
    r'url\s*=\s*[\'\"](?P<url>https?://[^\'\"]+)[\'\"]'
    r'(?:\s*,\s*(?P<args>[^)]*?))?\s*\)',
    re.IGNORECASE,
)

# vault write auth/token/create policies=admin
# vault read secret/data/admin
_VAULT_CLI_RE = re.compile(
    r'vault\s+(?P<cmd>write|read|list|delete|patch)\s+'
    r'(?P<path>[^\s]+)'
    r'(?:\s+(?P<args>.+))?',
    re.IGNORECASE,
)

# http.client — Python stdlib: conn.request("GET", "/v1/sys/health")
_HTTP_CLIENT_RE = re.compile(
    r'conn\.request\s*\(\s*'
    r'[\'\"](?P<method>GET|POST|PUT|DELETE|PATCH)[\'\"]\s*,\s*'
    r'[\'\"](/v1/(?P<path>[^\'\"]+))[\'\"]'
    r'(?:\s*,\s*body\s*=\s*(?P<body>[^,)]+))?'
    r'(?:\s*,\s*headers\s*=\s*(?P<headers>\{[^}]*\}))?',
    re.IGNORECASE,
)

# urllib.request — Python stdlib
_URLLIB_RE = re.compile(
    r'urllib\.request\.(?:urlopen|Request)\s*\(\s*'
    r'[\'\"](?P<url>https?://[^\'\"]+/v1/(?P<path>[^\'\"]+))[\'\"]'
    r'(?:\s*,\s*data\s*=\s*(?P<body>[^,)]+))?',
    re.IGNORECASE,
)

# httpie — popular CLI: http POST https://vault:8200/v1/auth/token/create X-Vault-Token:root policies:=["admin"]
_HTTPIE_RE = re.compile(
    r'https?\s+(?P<method>GET|POST|PUT|DELETE|PATCH)\s+'
    r'(?P<url>https?://[^\s]+/v1/(?P<path>[^\s]+))'
    r'(?:\s+(?P<args>.+))?',
    re.IGNORECASE,
)

# vault write with field extraction: vault write -field=token auth/token/create policies=admin
_VAULT_CLI_FIELD_RE = re.compile(
    r'vault\s+(?P<cmd>write|read|list|delete|patch)\s+'
    r'(?:-[a-z-]+(?:=[a-z-]+)?\s+)*'  # optional flags like -field=token
    r'(?P<path>[^\s]+)'                 # path: auth/token/create
    r'(?:\s+(?P<args>.+))?',           # optional key=value args
    re.IGNORECASE,
)

# PowerShell Invoke-RestMethod — common in Windows pentest guides
_PS_INVOKE_RE = re.compile(
    r'Invoke-(?:RestMethod|WebRequest)\s+'
    r'-(?:Method|Uri)\s+(?P<method>GET|POST|PUT|DELETE)\s+'
    r'-Uri\s+[\'\"](?P<url>https?://[^\'\"]+/v1/(?P<path>[^\'\"]+))[\'\"]'
    r'(?:\s+-Body\s+[\'\"](?P<body>\{[^\']*\})[\'\"])?',
    re.IGNORECASE,
)

# Generic HTTP URL with Vault path: https://vault:8200/v1/sys/...
_GENERIC_VAULT_URL_RE = re.compile(
    r'(https?://[^\s\'\"<>]+/v1/(?P<path>(?:sys|auth|secret|identity|database|pki|transit|kv)[^\s\'\"<>]*))',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_poc_actions(
    text: str,
    source_url: str = "",
    vault_addr: str = "",
) -> list[PoCAction]:
    """Extract executable Vault actions from arbitrary text.

    Parameters
    ----------
    text:
        Raw text to scan (e.g. web search result snippet).
    source_url:
        URL where this text was found (for attribution).
    vault_addr:
        If set, actions targeting this address get higher confidence.

    Returns
    -------
    List of :class:`PoCAction` ready for execution via
    ``run_raw_vault_request``.
    """
    actions: list[PoCAction] = []

    # ── 1. curl commands ──────────────────────────────────────────────
    for match in _CURL_RE.finditer(text):
        method = (match.group("method") or match.group("method2") or "GET").upper()
        path = match.group("path")
        body_str = match.group("body")
        body = None
        if body_str:
            try:
                body = json.loads(body_str)
            except json.JSONDecodeError:
                body = body_str

        # Lower confidence for generic GETs to /sys/health
        confidence = "high" if method != "GET" or "health" not in path else "medium"

        actions.append(PoCAction(
            method=method,
            path=path,
            body=body,
            source_url=source_url,
            source_snippet=match.group(0)[:200],
            description=f"curl command from web search",
            confidence=confidence,
        ))

    # ── 2. Python requests calls ──────────────────────────────────────
    for match in _REQUESTS_RE.finditer(text):
        method = match.group("method").upper()
        path = match.group("path")
        args = match.group("args") or ""

        body = None
        headers = {}

        # Try to extract json=... or data=... from args
        json_match = re.search(r'json\s*=\s*(\{[^}]+\})', args)
        if json_match:
            try:
                body = json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        actions.append(PoCAction(
            method=method,
            path=path,
            body=body,
            headers=headers,
            source_url=source_url,
            source_snippet=match.group(0)[:200],
            description="Python requests call from web search",
            confidence="high" if body else "medium",
        ))

    # ── 3. http.client (Python stdlib) ─────────────────────────────────
    for match in _HTTP_CLIENT_RE.finditer(text):
        method = match.group("method").upper()
        path = match.group("path")
        actions.append(PoCAction(
            method=method, path=path,
            source_url=source_url, source_snippet=match.group(0)[:200],
            description="http.client call from web search",
            confidence="medium",
        ))

    # ── 4. urllib.request (Python stdlib) ──────────────────────────────
    for match in _URLLIB_RE.finditer(text):
        path = match.group("path")
        body = None
        body_str = match.group("body")
        if body_str:
            try:
                body = json.loads(body_str.strip())
            except json.JSONDecodeError:
                body = body_str.strip()
        actions.append(PoCAction(
            method="POST" if body else "GET", path=path, body=body,
            source_url=source_url, source_snippet=match.group(0)[:200],
            description="urllib.request call from web search",
            confidence="medium",
        ))

    # ── 5. httpie CLI ─────────────────────────────────────────────────
    for match in _HTTPIE_RE.finditer(text):
        method = match.group("method").upper()
        path = match.group("path")
        actions.append(PoCAction(
            method=method, path=path,
            source_url=source_url, source_snippet=match.group(0)[:200],
            description="httpie command from web search",
            confidence="high" if method != "GET" else "medium",
        ))

    # ── 6. PowerShell Invoke-RestMethod ───────────────────────────────
    for match in _PS_INVOKE_RE.finditer(text):
        method = match.group("method").upper()
        path = match.group("path")
        body_str = match.group("body")
        body = None
        if body_str:
            try:
                body = json.loads(body_str)
            except json.JSONDecodeError:
                body = body_str
        actions.append(PoCAction(
            method=method, path=path, body=body,
            source_url=source_url, source_snippet=match.group(0)[:200],
            description="PowerShell Invoke-RestMethod from web search",
            confidence="medium",
        ))

    # ── 7. Vault CLI commands (enhanced — with -field extraction) ──────
    for match in _VAULT_CLI_FIELD_RE.finditer(text):
        cmd = match.group("cmd").lower()
        path = match.group("path")
        args = match.group("args") or ""
        method_map = {"write": "POST", "read": "GET", "list": "LIST",
                       "delete": "DELETE", "patch": "PATCH"}
        method = method_map.get(cmd, "GET")

        # Parse key=value arguments into body dict for POST
        body = None
        if method == "POST" and args:
            body = {}
            for part in args.split():
                if "=" in part and not part.startswith("-"):
                    k, v = part.split("=", 1)
                    # Try to parse array values: policies=admin,root
                    vals = v.strip("'\"").split(",")
                    body[k] = vals[0] if len(vals) == 1 else vals
            if not body:
                body = None

        actions.append(PoCAction(
            method=method, path=path, body=body,
            source_url=source_url, source_snippet=match.group(0)[:200],
            description=f"Vault CLI '{cmd}' — {path}",
            confidence="high" if body else "medium",
        ))

    # ── 8. Generic Vault URLs ─────────────────────────────────────────
    seen_paths = {a.path for a in actions}
    for match in _GENERIC_VAULT_URL_RE.finditer(text):
        path = match.group("path")
        full_url = match.group(0)
        if path in seen_paths:
            continue

        actions.append(PoCAction(
            method="GET",
            path=path,
            source_url=source_url,
            source_snippet=full_url[:200],
            description="Vault API URL from web search",
            confidence="low",
        ))

    # ── 5. Deduplicate by (method, path) keeping highest confidence ───
    best: dict[tuple, PoCAction] = {}
    for action in actions:
        key = (action.method, action.path)
        if key not in best or _confidence_rank(action.confidence) > _confidence_rank(best[key].confidence):
            best[key] = action

    return list(best.values())


def parse_web_results(
    results: list[dict],
    vault_addr: str = "",
) -> list[PoCAction]:
    """Parse a batch of web search results for executable actions.

    Parameters
    ----------
    results:
        List of ``{"title", "url", "snippet"}`` dicts from web search.
    vault_addr:
        Current target for confidence boosting.

    Returns
    -------
    Combined deduplicated list of :class:`PoCAction`.
    """
    all_actions: list[PoCAction] = []
    for r in results:
        text = f"{r.get('title', '')} {r.get('snippet', '')}"
        # Include full_text when available (fetched page content)
        full = r.get("full_text")
        if full:
            text += f"\n{full}"
        actions = parse_poc_actions(
            text,
            source_url=r.get("url", ""),
            vault_addr=vault_addr,
        )
        all_actions.extend(actions)

    # Global dedup by (method, path)
    best: dict[tuple, PoCAction] = {}
    for action in all_actions:
        key = (action.method, action.path)
        if key not in best or _confidence_rank(action.confidence) > _confidence_rank(best[key].confidence):
            best[key] = action

    return list(best.values())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _confidence_rank(confidence: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)


def format_poc_for_agent(actions: list[PoCAction]) -> str:
    """Format parsed PoC actions as a prompt for the LLM agent."""
    if not actions:
        return ""

    lines = [
        f"\n[POC] {len(actions)} executable action(s) extracted from web search:",
    ]
    for i, action in enumerate(actions, 1):
        body_preview = ""
        if action.body:
            raw = json.dumps(action.body) if isinstance(action.body, dict) else str(action.body)
            body_preview = f" | body: {raw[:80]}"
        lines.append(
            f"  {i}. [{action.confidence}] {action.method} {action.path}{body_preview}"
        )
        if action.source_url:
            lines.append(f"     source: {action.source_url[:80]}")

    lines.append(
        "\nYou can execute these with run_raw_vault_request. "
        "Suggest the highest-confidence actions to the user, "
        "or if in auto-pilot mode, execute them directly."
    )
    return "\n".join(lines)
