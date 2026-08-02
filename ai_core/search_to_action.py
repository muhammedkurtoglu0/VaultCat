"""Bridge: web search results → active_execution module parameters.

Parses DuckDuckGo / Tavily search results for CVE exploits, PoC curl
commands, API paths, and JSON payloads, then produces parameter dicts
ready to be passed directly to ``active_execution`` modules.

Usage::

    from ai_core.search_to_action import SearchToActionBridge

    bridge = SearchToActionBridge(vault_addr="https://vault:8200", token="...")
    results = await search_web("CVE-2023-6337 Vault DoS exploit")
    params_list = bridge.to_module_params(results)

    for params in params_list:
        # Feed directly to active_execution modules
        result = await tool_executor(params["module"], params["params"])
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

# ── CVE / exploit search templates ──────────────────────────────────────────

CVE_SEARCH_TEMPLATES: dict[str, str] = {
    # CVE ID → optimized search query
    "CVE-2023-6337": "HashiCorp Vault CVE-2023-6337 memory exhaustion DoS large HTTP request exploit PoC",
    "CVE-2023-0620": "HashiCorp Vault CVE-2023-0620 Kubernetes auth bypass exploit",
    "CVE-2023-0665": "HashiCorp Vault CVE-2023-0665 improper certificate validation exploit",
    "CVE-2023-3462": "HashiCorp Vault CVE-2023-3462 LDAP auth method bypass exploit",
    "CVE-2023-3779": "HashiCorp Vault CVE-2023-3779 improper handling of large requests DoS",
    "CVE-2023-50711": "HashiCorp Vault CVE-2023-50711 raft storage DoS exploit",
    "CVE-2024-2048": "HashiCorp Vault CVE-2024-2048 insecure default policy TLS exploit",
    "CVE-2025-6203": "HashiCorp Vault CVE-2025-6203 crafted JSON DoS exploit PoC curl",
    "CVE-2020-10661": "HashiCorp Vault CVE-2020-10661 unauthorized access nested path policy bypass",
    "CVE-2020-12757": "HashiCorp Vault CVE-2020-12757 improper initialization seed RNG exploit",
    "CVE-2020-16250": "HashiCorp Vault CVE-2020-16250 AWS IAM auth method exploit",
}

EXPLOIT_TEMPLATES: dict[str, str] = {
    # Technique → optimized search query
    "approle_secret_id_bypass": "HashiCorp Vault AppRole bind_secret_id bypass exploit empty secret_id PoC",
    "token_privilege_escalation": "HashiCorp Vault token privilege escalation wildcard policy sudo create exploit",
    "database_root_rotate": "HashiCorp Vault database rotate-root exploit postgresql root password hijack",
    "transit_encrypt_bypass": "HashiCorp Vault transit engine encryption bypass exploit convergent encryption",
    "pki_cert_abuse": "HashiCorp Vault PKI engine certificate abuse exploit unauthorized role certificate",
    "raft_storage_access": "HashiCorp Vault raft storage exploit local file read unseal key extraction",
    "audit_log_bypass": "HashiCorp Vault audit log disable bypass exploit cover tracks",
    "cors_bypass": "HashiCorp Vault CORS misconfiguration exploit cross-origin token theft",
    "unauthenticated_enum": "HashiCorp Vault unauthenticated enumeration sys health seal-status auth methods info leak",
    "kv_enum": "HashiCorp Vault KV enumeration list secret paths token with list capability exploit",
    "policy_backdoor": "HashiCorp Vault policy backdoor root-equivalent wildcard exploit persistence",
    "seal_key_exfil": "HashiCorp Vault unseal key exfiltration Shamir share recovery exploit",
}


def get_search_query(cve_or_technique: str) -> str:
    """Return an optimized search query for *cve_or_technique*.

    If the input looks like a CVE ID (e.g. ``CVE-2023-6337``), returns a
    CVE-specific query.  Otherwise looks up the technique in
    :data:`EXPLOIT_TEMPLATES`.  Falls back to a generic Vault exploit query.
    """
    cve_id = cve_or_technique.strip().upper()
    if cve_id in CVE_SEARCH_TEMPLATES:
        return CVE_SEARCH_TEMPLATES[cve_id]

    key = cve_or_technique.strip().lower().replace(" ", "_")
    if key in EXPLOIT_TEMPLATES:
        return EXPLOIT_TEMPLATES[key]

    # Fuzzy match CVE pattern in the input
    m = re.search(r'CVE-\d{4}-\d{4,}', cve_or_technique, re.IGNORECASE)
    if m:
        cve = m.group(0).upper()
        return f"HashiCorp Vault {cve} exploit proof of concept PoC"

    # Generic fallback
    return f"HashiCorp Vault {cve_or_technique} exploit pentest PoC"


# ── PoC parser ───────────────────────────────────────────────────────────────


class SearchToActionBridge:
    """Parse search results and produce active_execution module parameters.

    Parameters
    ----------
    vault_addr:
        Target Vault URL (injected into every parameter dict).
    token:
        Vault token for authenticated operations (optional).
    """

    def __init__(self, vault_addr: str = "", token: Optional[str] = None):
        self.vault_addr = vault_addr
        self.token = token

    # ── public API ──────────────────────────────────────────────────────

    def to_module_params(self, search_results: list[dict]) -> list[dict]:
        """Parse *search_results* into ``{module, params, confidence}`` dicts.

        Each dict is ready to be passed to ``active_execution`` modules
        via the :class:`~ai_core.tool_executor.ToolExecutor`.

        Returns an empty list when no actionable data is extracted.
        """
        actions: list[dict] = []

        for result in search_results:
            snippet = result.get("snippet", "")
            full_text = result.get("full_text", "")
            url = result.get("url", "")
            all_text = f"{snippet}\n{full_text}" if full_text else snippet

            # ── 1. Parse curl / HTTP commands ──────────────────────────
            curl_actions = _parse_curl_commands(all_text)
            for ca in curl_actions:
                mapped = self._map_curl_to_module(ca)
                if mapped:
                    actions.append(mapped)

            # ── 2. Parse JSON payloads ─────────────────────────────────
            json_actions = _parse_json_payloads(all_text)
            for ja in json_actions:
                mapped = self._map_json_to_module(ja)
                if mapped:
                    actions.append(mapped)

            # ── 3. Parse vault CLI commands ────────────────────────────
            cli_actions = _parse_vault_cli_commands(all_text)
            for cli_a in cli_actions:
                mapped = self._map_cli_to_module(cli_a)
                if mapped:
                    actions.append(mapped)

            # ── 4. Parse explicit step lists ───────────────────────────
            step_actions = _parse_step_lists(all_text)
            for sa in step_actions:
                mapped = self._map_step_to_module(sa)
                if mapped:
                    actions.append(mapped)

        # Deduplicate by (module, method, path)
        seen: set[tuple[str, str, str]] = set()
        unique: list[dict] = []
        for action in actions:
            key = (
                action.get("module", ""),
                action.get("params", {}).get("method", ""),
                action.get("params", {}).get("path", ""),
            )
            if key not in seen:
                seen.add(key)
                unique.append(action)

        return unique

    # ── mappers ─────────────────────────────────────────────────────────

    def _map_curl_to_module(self, curl: dict) -> Optional[dict]:
        """Map a parsed curl command to an active_execution module."""
        method = curl.get("method", "GET")
        path = curl.get("path", "")
        body = curl.get("body")
        headers = curl.get("headers", {})

        # Use raw vault request for most curl commands — the LLM agent
        # can route to more specific modules based on context.
        params: dict[str, Any] = {
            "vault_addr": self.vault_addr,
            "method": method,
            "path": path.lstrip("/"),
        }
        if body:
            params["body"] = body
        if self.token:
            params["token"] = self.token

        module = self._classify_path_to_module(path, method)

        return {
            "module": module,
            "params": params,
            "confidence": curl.get("confidence", "medium"),
            "source": "curl_parse",
        }

    def _map_json_to_module(self, ja: dict) -> Optional[dict]:
        """Map a JSON payload snippet to a module."""
        body = ja.get("body", {})
        method = ja.get("method", "POST")

        params: dict[str, Any] = {
            "vault_addr": self.vault_addr,
            "method": method,
            "path": ja.get("path", ""),
            "body": body,
        }
        if self.token:
            params["token"] = self.token

        return {
            "module": "run_raw_vault_request",
            "params": params,
            "confidence": ja.get("confidence", "low"),
            "source": "json_parse",
        }

    def _map_cli_to_module(self, cli: dict) -> Optional[dict]:
        """Map a vault CLI command to a module."""
        cmd = cli.get("command", "")
        args = cli.get("args", {})

        if cmd.startswith("vault write "):
            path = cmd[len("vault write "):].strip().split()[0]
            return {
                "module": self._classify_path_to_module(path, "POST"),
                "params": {
                    "vault_addr": self.vault_addr,
                    "method": "POST",
                    "path": path,
                    "body": args,
                    "token": self.token,
                },
                "confidence": cli.get("confidence", "medium"),
                "source": "cli_parse",
            }
        if cmd.startswith("vault read "):
            path = cmd[len("vault read "):].strip().split()[0]
            return {
                "module": self._classify_path_to_module(path, "GET"),
                "params": {
                    "vault_addr": self.vault_addr,
                    "method": "GET",
                    "path": path,
                    "token": self.token,
                },
                "confidence": cli.get("confidence", "medium"),
                "source": "cli_parse",
            }

        return None

    def _map_step_to_module(self, step: dict) -> Optional[dict]:
        """Map a parsed step list entry to a module."""
        desc = step.get("description", "").lower()
        path = step.get("path", "")
        method = step.get("method", "GET")

        if not path:
            return None

        params: dict[str, Any] = {
            "vault_addr": self.vault_addr,
            "method": method,
            "path": path,
        }
        if self.token:
            params["token"] = self.token

        return {
            "module": self._classify_path_to_module(path, method),
            "params": params,
            "confidence": step.get("confidence", "low"),
            "source": "step_parse",
        }

    # ── path classifier ─────────────────────────────────────────────────

    @staticmethod
    def _classify_path_to_module(path: str, method: str) -> str:
        """Route a Vault API path to the most specific active_execution module."""
        p = path.lower().strip("/")

        if "database/creds" in p:
            return "run_database_credential_harvest"
        if "database/rotate-root" in p:
            return "run_database_pivot"
        if "auth/approle/login" in p:
            return "run_approle_exploit"
        if "auth/token/create" in p:
            return "run_privilege_escalation"
        if "sys/policies/acl" in p and method in ("PUT", "POST"):
            return "run_privilege_escalation"
        if "auth/userpass" in p:
            return "run_priv_esc_scan"
        if "secret" in p or "kv" in p:
            return "run_kv_enumeration"
        if "sys/mounts" in p:
            return "run_capability_audit"
        if "sys/auth" in p:
            return "run_auth_config_audit"
        if "pki" in p and "issue" in p:
            return "run_pki_exploit"
        if "transit" in p:
            return "run_transit_exploit"
        if "sys/seal" in p or "sys/unseal" in p:
            return "run_active_module"  # seal manipulation
        if "sys/audit" in p:
            return "run_audit_log_scan"

        return "run_raw_vault_request"


# ---------------------------------------------------------------------------
# Parsers — text → structured action dicts
# ---------------------------------------------------------------------------

_CURL_RE = re.compile(
    r"""\bcurl\s+                        # curl keyword (word boundary)
        (?:-X\s+(?P<method>GET|POST|PUT|DELETE|LIST|PATCH)\s+)?  # optional -X METHOD
        (?:"(?P<url_quoted>[^"]+)"|'(?P<url_single>[^']+)'|(?P<url_bare>[^\s]+://[^\s]+))  # URL (must contain ://)
        (?:\s+(?:-[A-Za-z-]+(?:[\s"'][^"']*["'])?))*           # other flags
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _parse_curl_commands(text: str) -> list[dict]:
    """Extract curl commands from search result text.

    Returns a list of dicts with keys: method, url, path, headers, body, confidence.
    """
    results: list[dict] = []
    found = _CURL_RE.findall(text)
    for match in found:
        url = match[1] or match[2] or match[3]
        if not url:
            continue
        method = match[0] or "GET"
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path
            if parsed.query:
                path += f"?{parsed.query}"
        except Exception:
            path = "/"
        results.append({
            "method": method.upper(),
            "url": url,
            "path": path or "/",
            "headers": {},
            "body": None,
            "confidence": "medium",
        })
    return results


_VAULT_CLI_RE = re.compile(
    r'\bvault\s+(read|write|list|delete|login|operator)\s+(\S+(?:\s+\S+)?)',
    re.IGNORECASE,
)

_JSON_PAYLOAD_RE = re.compile(
    r"""'\{[^']+\}'|\{[^{}]*"(?:role_id|secret_id|policies|token|password|username)"[^}]*\}""",
    re.IGNORECASE,
)


def _parse_json_payloads(text: str) -> list[dict]:
    """Extract JSON payloads that look like Vault API body content."""
    results: list[dict] = []
    for match in _JSON_PAYLOAD_RE.finditer(text):
        raw = match.group(0).strip("'")
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = _try_fix_json(raw)

        if body:
            # Try to guess the endpoint from surrounding text
            ctx_start = max(0, match.start() - 200)
            ctx = text[ctx_start:match.end() + 100]
            path = _guess_path_from_context(ctx) or ""

            results.append({
                "path": path,
                "method": "POST",
                "body": body,
                "confidence": "medium",
            })
    return results


def _parse_vault_cli_commands(text: str) -> list[dict]:
    """Extract vault CLI commands from text."""
    results: list[dict] = []
    for match in _VAULT_CLI_RE.finditer(text):
        verb = match.group(1).strip().lower()
        rest = match.group(2).strip()

        # Map verb to HTTP method
        method_map = {"read": "GET", "list": "LIST", "write": "POST",
                       "delete": "DELETE", "login": "POST", "operator": "PUT"}
        method = method_map.get(verb, "GET")

        # Parse path + optional key=value args
        parts = rest.split()
        path = parts[0] if parts else ""
        args = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                args[k] = v.strip("'\"")

        results.append({
            "command": f"vault {verb} {rest}",
            "method": method,
            "path": path,
            "args": args,
            "confidence": "high",
        })
    return results


_STEP_LIST_RE = re.compile(
    r'(?:Step|Adim|Phase)\s*(\d+)[:.)]\s*(.+?)(?=(?:Step|Adim|Phase)\s*\d+[:.)]|$)',
    re.IGNORECASE | re.DOTALL,
)


def _parse_step_lists(text: str) -> list[dict]:
    """Extract numbered step lists (exploit walkthroughs) from text."""
    results: list[dict] = []
    for match in _STEP_LIST_RE.finditer(text):
        step_text = match.group(2).strip()
        path = _guess_path_from_context(step_text)

        method = "GET"
        if any(w in step_text.lower() for w in ("post", "write", "create", "put", "enable")):
            method = "POST"
        elif "delete" in step_text.lower() or "disable" in step_text.lower():
            method = "DELETE"

        results.append({
            "description": step_text[:200],
            "path": path or "",
            "method": method,
            "confidence": "low",
        })
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _guess_path_from_context(text: str) -> Optional[str]:
    """Try to find a Vault API path in surrounding text."""
    # Match /v1/auth/..., /v1/sys/..., /v1/secret/..., etc.
    m = re.search(r'/v1/(?:auth|sys|secret|database|pki|transit|identity|cubbyhole)/[^\s"\']+', text)
    if m:
        return m.group(0).replace("/v1/", "")
    # Also match paths without /v1 prefix in known Vault contexts
    m = re.search(r'(?:auth|sys|secret|database|pki|transit)/[^\s"\']+', text)
    if m:
        return m.group(0)
    return None


def _try_fix_json(raw: str) -> Optional[dict]:
    """Attempt to fix common JSON quoting issues found in web snippets."""
    # Replace single quotes with double quotes (common in blog posts)
    try:
        fixed = raw.replace("'", '"')
        return json.loads(fixed)
    except (json.JSONDecodeError, TypeError):
        pass
    # Try adding missing closing brace
    try:
        return json.loads(raw + "}")
    except (json.JSONDecodeError, TypeError):
        pass
    return None
