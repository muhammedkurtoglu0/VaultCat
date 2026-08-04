"""Shared tool executor — token injection, MCP routing, credential parsing.

Extracted from ``chat_ui.py`` so both the terminal ChatUI and the
Chainlit web UI can reuse the same bridge without duplicating 80+
lines of critical logic.
"""

from __future__ import annotations

import inspect
import json
from typing import Any


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------


# ── Tools whose MCP handler functions do NOT accept a "token" parameter.
#    _inject_token skips these so the root/privileged token never leaks into
#    tool-call traces for unauthenticated / utility operations.
_TOOLS_WITHOUT_TOKEN: set[str] = {
    "run_unauthenticated_recon",
    "run_hijack_scan",
    "run_env_scan",
    "run_vault_agent_scan",
    "get_findings",
    "get_risk_score",
    "refresh_nvd_cache",
    "web_search",
    "list_active_modules",
    "run_network_probe",
    "get_threat_intel",
    "run_container_scan",
    "export_full_report",
    "send_notification",
    "generate_diff_report",
    "decode_generate_root_otp",
    "get_fix_commands",
    "search_to_actions",
    "set_evasion_profile",
    "run_aws_auth_login",
}


async def invoke_mcp_handler(handler, params: dict) -> str:
    """Invoke an MCP handler with the given params, filtering to valid kwargs.

    Handles both sync and async handlers transparently.
    """
    sig = inspect.signature(handler)
    valid_keys = set(sig.parameters.keys())
    filtered = {k: v for k, v in params.items() if k in valid_keys}

    result = handler(**filtered)
    if inspect.isawaitable(result):
        result = await result
    return result if isinstance(result, str) else str(result)


# ---------------------------------------------------------------------------
# ToolExecutor
# ---------------------------------------------------------------------------


class ToolExecutor:
    """Bridge between the agent's tool decisions and real MCP code execution.

    Handles:
    - vault_addr injection
    - dynamic token escalation (session best > LLM provided)
    - MCP handler routing (37 tools)
    - credential discovery parsing
    """

    def __init__(
        self,
        vault_addr: str | None = None,
        token: str | None = None,
        session: Any = None,
        memory: Any = None,
    ):
        self.vault_addr = vault_addr
        self.token = token
        self.memory = memory

        # Session: defaults to the global singleton
        if session is None:
            from ai_core.dynamic_session import global_store

            self.session = global_store
        else:
            self.session = session

        # Optional callback for credential discoveries.
        # Set by the UI layer to customise how alerts are displayed.
        self.on_discovery: Any = None  # callable(list[str]) | None

    # ── public API ──────────────────────────────────────────────────────

    async def execute_tool(self, tool_name: str, params: dict) -> str:
        """Execute a tool with token injection, routing, and credential parsing.

        Returns the tool result as a JSON string.
        """
        # ── Inject vault_addr ──────────────────────────────────────────
        if "vault_addr" not in params and self.vault_addr:
            params["vault_addr"] = self.vault_addr

        # ── Dynamic token injection ─────────────────────────────────────
        self._inject_token(params, tool_name)

        try:
            result = await self.call_mcp_tool(tool_name, params)

            # ── Parse result for new credentials ───────────────────────
            discoveries = self.session.parse_tool_result(tool_name, result)
            if discoveries:
                if self.on_discovery is not None:
                    self.on_discovery(discoveries)

            # Record execution
            if self.memory:
                self.memory.add_execution(
                    tool_name, "success", {"params": params}
                )
            return result
        except Exception as e:
            if self.memory:
                self.memory.add_execution(
                    tool_name, "error", {"error": str(e)}
                )
            return json.dumps(
                {"status": "error", "message": str(e)}, ensure_ascii=False
            )

    async def call_mcp_tool(self, tool_name: str, params: dict) -> str:
        """Route a tool call to the actual MCP handler function."""
        handler = _TOOL_MAP.get(tool_name)
        if not handler:
            return json.dumps(
                {"status": "error", "message": f"Unknown tool: {tool_name}"},
                ensure_ascii=False,
            )
        return await invoke_mcp_handler(handler, params)

    # ── internals ──────────────────────────────────────────────────────

    def _inject_token(self, params: dict, tool_name: str = "") -> None:
        """Overwrite the LLM's token with the session's best when appropriate.

        Skips tools whose MCP handlers don't accept a token parameter
        (e.g. ``run_unauthenticated_recon``, ``web_search``) so the
        privileged token never leaks into their call traces.
        """
        # ── Never inject a token into tools that don't accept one ───────
        if tool_name in _TOOLS_WITHOUT_TOKEN:
            params.pop("token", None)
            return

        best_token = self.session.get_best_token_value()
        if best_token:
            llm_token = params.get("token", "")
            override = False
            if not llm_token:
                override = True
            elif "..." in str(llm_token):
                override = True
            elif not isinstance(llm_token, str):
                override = True
            elif not (
                llm_token.startswith("hvs.") or llm_token.startswith("s.")
            ):
                override = True
            elif len(llm_token) < 20:
                override = True

            if override:
                params["token"] = best_token
            self.token = best_token
        elif "token" not in params and self.token:
            params["token"] = self.token


# ---------------------------------------------------------------------------
# Tool → handler mapping  (kept module-private; built once at import time)
# ---------------------------------------------------------------------------


def _build_tool_map() -> dict[str, Any]:
    """Lazily import all MCP handlers and build the routing dict."""
    # Deferred import so the module is importable even when some
    # dependencies of mcp_server are missing in lightweight contexts.
    from ai_core.mcp_server import (
        get_findings,
        get_risk_score,
        list_active_modules,
        refresh_nvd_cache,
        web_search,
        run_active_module,
        run_auth_config_audit,
        run_capability_audit,
        run_cloud_key_exfiltration,
        run_database_credential_harvest,
        run_env_scan,
        run_hijack_scan,
        run_kv_enumeration,
        read_single_policy,
        run_raw_vault_request,
        run_policy_auditor,
        run_priv_esc_scan,
        run_privilege_escalation,
        run_secret_exfiltration,
        run_ttl_audit,
        run_unauthenticated_recon,
        run_compliance_check,
        run_network_probe,
        export_full_report,
        send_notification,
        run_audit_log_scan,
        run_container_scan,
        get_threat_intel,
        generate_diff_report,
        decode_generate_root_otp,
        run_database_pivot,
        run_reverse_shell,
        run_approle_exploit,
        run_jwt_oidc_exploit,
        run_kubernetes_auth_exploit,
        run_raft_exploit,
        run_pki_exploit,
        run_transit_exploit,
        run_vault_agent_scan,
        run_aws_auth_login,
        get_fix_commands_tool,
        search_to_actions_tool,
        set_evasion_profile_tool,
    )

    return {
        "run_unauthenticated_recon": run_unauthenticated_recon,
        "run_hijack_scan": run_hijack_scan,
        "run_env_scan": run_env_scan,
        "run_capability_audit": run_capability_audit,
        "run_priv_esc_scan": run_priv_esc_scan,
        "run_kv_enumeration": run_kv_enumeration,
        "run_ttl_audit": run_ttl_audit,
        "run_auth_config_audit": run_auth_config_audit,
        "read_single_policy": read_single_policy,
        "run_raw_vault_request": run_raw_vault_request,
        "run_policy_auditor": run_policy_auditor,
        "run_privilege_escalation": run_privilege_escalation,
        "run_secret_exfiltration": run_secret_exfiltration,
        "run_database_credential_harvest": run_database_credential_harvest,
        "run_cloud_key_exfiltration": run_cloud_key_exfiltration,
        "list_active_modules": list_active_modules,
        "run_active_module": run_active_module,
        "run_aws_auth_login": run_aws_auth_login,
        "get_findings": get_findings,
        "get_risk_score": get_risk_score,
        "refresh_nvd_cache": refresh_nvd_cache,
        "web_search": web_search,
        "run_compliance_check": run_compliance_check,
        "run_network_probe": run_network_probe,
        "export_full_report": export_full_report,
        "send_notification": send_notification,
        "run_audit_log_scan": run_audit_log_scan,
        "run_container_scan": run_container_scan,
        "get_threat_intel": get_threat_intel,
        "generate_diff_report": generate_diff_report,
        "decode_generate_root_otp": decode_generate_root_otp,
        "run_database_pivot": run_database_pivot,
        "run_reverse_shell": run_reverse_shell,
        "run_approle_exploit": run_approle_exploit,
        "run_jwt_oidc_exploit": run_jwt_oidc_exploit,
        "run_kubernetes_auth_exploit": run_kubernetes_auth_exploit,
        "run_raft_exploit": run_raft_exploit,
        "run_pki_exploit": run_pki_exploit,
        "run_transit_exploit": run_transit_exploit,
        "run_vault_agent_scan": run_vault_agent_scan,
        "get_fix_commands": get_fix_commands_tool,
        "search_to_actions": search_to_actions_tool,
        "set_evasion_profile": set_evasion_profile_tool,
    }


_TOOL_MAP: dict[str, Any] = _build_tool_map()
