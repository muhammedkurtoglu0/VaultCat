import concurrent.futures
import os
import subprocess
import tarfile
import zipfile
from pathlib import Path

from core.report import add_finding
from credential_hijacking.patterns import FINDING_METADATA, PATTERNS
from core.logger import logger


MODULE_NAME = "file_secret_scanner"
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
MAX_GIT_COMMITS = 100
DEFAULT_WORKERS = min(8, (os.cpu_count() or 4))
CHUNK_SIZE = 512 * 1024  # 512 KB chunks for large files
CHUNK_THRESHOLD = 1 * 1024 * 1024  # files > 1 MB are scanned in chunks

# ── Keyword pre-filter: skip expensive regex when chunk has no hits ─────
# For each pattern, extract a short ASCII keyword that MUST appear in text
# for the regex to possibly match.  This is a 10-50× speedup for large
# binary/log files where most chunks contain zero credential material.
_KEYWORD_INDEX: dict[str, str] = {}
for _pn, _pat in PATTERNS.items():
    # Strip word-boundary escapes so '\b' is not mistaken for a literal
    # 'b' glued onto the following word (e.g. '\bhvs\.CAES' must yield
    # the keyword 'caes', not the never-present 'bhvs').
    _ps = _pat.pattern.replace("\\b", "").lower()
    # Extract the longest lowercase alpha substring as keyword
    _words = __import__('re').findall(r'[a-z_]{4,}', _ps)
    if _words:
        _KEYWORD_INDEX[_pn] = max(_words, key=len)
# Explicit keywords for patterns whose auto-extracted keyword (the longest
# alpha substring) is NOT guaranteed to appear in every possible match —
# typically alternations where no single alternative is required.  The
# pre-filter must never suppress a real detection, so these are pinned to a
# substring every match is guaranteed to contain ("" disables the filter).
_KEYWORD_INDEX.update({
    "vault_response_wrapped_token": "caes",   # \bhvs\.CAES...
    "vault_token_value": "hvs.",              # hvs.X / hvc.X
    "vault_8200_url": "8200",                 # ...:8200
    "vault_api_path": "/v1/",                 # /v1/secret|sys|auth|kv/...
    "vault_role_id": "role",                  # VAULT_ROLE_ID|role_id|role-id|roleId
    "vault_secret_id": "secret",              # VAULT_SECRET_ID|secret_id|secret-id|secretId
    "vault_database_plugin": "database-plugin",
    "vault_database_connection_url": "://",   # postgresql://, jdbc:mysql://, ...
    "database_static_username": "user",
    "database_static_password": "pass",
    "vault_aws_auth_reference": "auth_method",
    "aws_role_arn": "role_arn",
    # Alternations with no single required substring — always scan.
    "vault_database_broad_privilege_statement": "",
    "vault_database_destructive_statement": "",
})
DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".terraform",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "node_modules",
}
ALLOWED_FILENAMES = {
    ".env",
    ".gitlab-ci.yml",
    "Dockerfile",
    "Jenkinsfile",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    "docker-compose.yml",
    "application.yml",
    "application.yaml",
    "README.md",
}
ALLOWED_SUFFIXES = {
    ".cfg",
    ".cs",
    ".env",
    ".go",
    ".java",
    ".js",
    ".txt",
    ".log",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".yaml",
    ".yml",
    ".json",
    ".conf",
    ".hcl",
    ".ini",
    ".properties",
    ".ps1",
    ".sh",
    ".ts",
    ".tf",
    ".tfvars",
    ".toml",
    ".xml",
}
ARCHIVE_SUFFIXES = {
    ".zip",
    ".tar",
    ".tgz",
    ".gz",
}


def scan_files(
    root_path,
    include_git_history=True,
    max_file_size_bytes=MAX_FILE_SIZE_BYTES,
    excluded_dirs=None,
    max_workers=DEFAULT_WORKERS,
):
    """Scan *root_path* for Vault credential material.

    File reading and regex matching are distributed across *max_workers*
    threads.  Files larger than ``CHUNK_THRESHOLD`` are read and scanned
    in ``CHUNK_SIZE`` byte windows to bound memory usage.
    """
    matches = []
    root = Path(root_path)
    excluded_dirs = DEFAULT_EXCLUDED_DIRS | set(excluded_dirs or [])

    logger.info("\n======================================")
    logger.info("Vault Credential Hijacking Scan")
    logger.info("======================================")

    if not root.exists():
        add_finding(
            "HIGH",
            "Hijack scan path does not exist",
            "The requested credential hijacking scan path does not exist.",
            recommendation="Provide an existing file or directory path.",
            evidence=f"path: {root}",
            module=MODULE_NAME,
            target=str(root),
        )
        return matches

    # Collect scan-eligible files (walking is I/O-bound but fast enough)
    if root.is_file():
        candidates = [root]
    else:
        candidates = [
            p for p in _iter_files(root, excluded_dirs) if p.is_file()
        ]

    if not candidates:
        return matches

    if max_workers is None or max_workers == 0:
        max_workers = DEFAULT_WORKERS
    logger.info(f"[*] Found {len(candidates)} files — scanning with {max_workers} workers...")

    # Parallel scan: each worker handles one file (or chunked file)
    _completed = 0
    _last_report = 0

    def _progress_callback(_fut):
        nonlocal _completed, _last_report
        _completed += 1
        # Print progress every 500 files or 5%
        if _completed - _last_report >= 500 or (_completed > 0 and _completed % max(1, len(futures) // 20) == 0):
            _pct = _completed * 100 // len(futures)
            logger.info(f"\r[*] Progress: {_completed}/{len(futures)} ({_pct}%)", end="", flush=True)
            _last_report = _completed

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}  # future -> file_path for error reporting
        for file_path in candidates:
            if _is_archive(file_path):
                future = pool.submit(_scan_archive, file_path, max_file_size_bytes)
                futures[future] = file_path
            elif _should_scan_file(file_path, max_file_size_bytes):
                future = pool.submit(_scan_single_file, file_path)
                futures[future] = file_path
            else:
                continue
            future.add_done_callback(_progress_callback)

        for future in concurrent.futures.as_completed(futures):
            try:
                file_matches = future.result()
                if file_matches:
                    matches.extend(file_matches)
            except Exception as exc:
                file_path = futures[future]
                logger.warning(f"[-] Error scanning {file_path}: {exc}")

        logger.info(f"\r[*] Scan complete: {len(matches)} findings from {_completed} files.          ")

    # Git history scan remains sync (already subprocess-based)
    if root.is_dir() and include_git_history:
        matches.extend(_scan_git_history(root))

    return matches


def _scan_single_file(file_path: Path) -> list[dict]:
    """Read and scan a single file.  Large files are processed in chunks.

    Skips files that cannot be read due to permissions — no point wasting
    CPU on regex when the OS will deny the read anyway.
    """
    # Permission pre-check: don't waste time on unreadable files
    if not os.access(file_path, os.R_OK):
        return []

    size = file_path.stat().st_size
    if size <= CHUNK_THRESHOLD:
        text = _read_text_file(file_path)
        if text is None:
            return []
        return _scan_text(file_path, text)

    # Chunked scan for large files
    return _scan_file_chunked(file_path, size)


def _scan_file_chunked(file_path: Path, file_size: int) -> list[dict]:
    """Scan a large file in fixed-size chunks with overlap.

    Each chunk overlaps the previous by 256 bytes so that patterns
    spanning chunk boundaries are not missed.
    """
    OVERLAP = 256
    matches = []
    seen = set()

    try:
        with file_path.open("rb") as fh:
            carry = b""
            base_line = 0  # newline count in file bytes before the current chunk
            while True:
                raw = fh.read(CHUNK_SIZE)
                if not raw:
                    break

                # Prepend overlap from previous chunk
                chunk = carry + raw

                # Decode
                if b"\x00" in chunk[:4096]:
                    text = None
                else:
                    try:
                        text = chunk.decode("utf-8")
                    except UnicodeDecodeError:
                        text = chunk.decode("utf-8", errors="ignore")

                if text is not None:
                    for m in _scan_text(file_path, text, line_offset=base_line):
                        key = (m["pattern"], m["value"], m["line"])
                        if key not in seen:
                            seen.add(key)
                            matches.append(m)

                # Carry overlap to next chunk and advance the line base past
                # the bytes that will not be re-scanned.  Byte-level counting
                # is exact for UTF-8 (0x0A never appears inside a multi-byte
                # sequence).
                carry = raw[-OVERLAP:] if len(raw) > OVERLAP else raw
                base_line += chunk[: len(chunk) - len(carry)].count(b"\n")

    except OSError:
        return matches

    return matches


def _iter_files(root, excluded_dirs):
    for file_path in root.rglob("*"):
        if any(part in excluded_dirs for part in file_path.parts):
            continue
        yield file_path


def _should_scan_file(file_path, max_file_size_bytes=MAX_FILE_SIZE_BYTES):
    if file_path.stat().st_size > max_file_size_bytes:
        return False

    if file_path.name in ALLOWED_FILENAMES:
        return True

    if file_path.name.startswith("config."):
        return True

    return file_path.suffix in ALLOWED_SUFFIXES


def _is_archive(file_path):
    name = file_path.name.lower()
    return (
        any(name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)
        or name.endswith(".tar.gz")
    )


def _read_text_file(file_path):
    try:
        raw_data = file_path.read_bytes()
    except OSError:
        return None

    if b"\x00" in raw_data[:4096]:
        return None

    try:
        return raw_data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw_data.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return None


def _scan_text(file_path, text, line_offset=0):
    matches = []
    seen_findings = set()
    text_lower = text.lower()

    for pattern_name, pattern in PATTERNS.items():
        # ── Keyword pre-filter: skip regex if chunk has no matching keyword ──
        keyword = _KEYWORD_INDEX.get(pattern_name)
        if keyword and keyword not in text_lower:
            continue  # 10-50× speedup for irrelevant chunks

        for match in pattern.finditer(text):
            value = _matched_value(match)
            if _should_skip_generic_match(pattern_name, value):
                continue
            line_number = line_offset + text.count("\n", 0, match.start()) + 1
            line_text = _line_for_match(text, match.start())
            if _should_skip_context_match(pattern_name, file_path, line_text):
                continue
            masked_value = mask_value(value)
            confidence = _confidence_for_match(pattern_name, file_path, line_text)
            is_material = _is_material_value(pattern_name, value)

            metadata = FINDING_METADATA[pattern_name]
            severity = metadata["severity"]
            title = metadata["title"]
            description = metadata["description"]
            recommendation = metadata["recommendation"]

            if _is_sensitive_material_pattern(pattern_name) and not is_material:
                severity = "INFO"
                title = "Vault credential variable or placeholder observed"
                description = (
                    "A Vault credential variable, placeholder, or command substitution "
                    "was observed, but no concrete credential value was exposed."
                )
                recommendation = (
                    "Use this as context for the authentication flow and search related "
                    "artifacts for concrete credential values."
                )

            finding_key = (title, str(file_path), line_number, value)
            if finding_key in seen_findings:
                continue
            seen_findings.add(finding_key)

            evidence = (
                f"file: {file_path}, line: {line_number}, "
                f"pattern: {pattern_name}, confidence: {confidence}, value: {masked_value}"
            )

            add_finding(
                severity,
                title,
                description,
                recommendation=recommendation,
                evidence=evidence,
                module=MODULE_NAME,
                target=str(file_path),
            )

            matches.append({
                "file": str(file_path),
                "line": line_number,
                "pattern": pattern_name,
                "value": value,
                "masked_value": masked_value,
                "confidence": confidence,
                "material": is_material,
            })

    return matches


def _scan_archive(file_path, max_file_size_bytes=MAX_FILE_SIZE_BYTES):
    if file_path.stat().st_size > max_file_size_bytes:
        return []

    if zipfile.is_zipfile(file_path):
        return _scan_zip_archive(file_path, max_file_size_bytes)

    if tarfile.is_tarfile(file_path):
        return _scan_tar_archive(file_path, max_file_size_bytes)

    return []


def _scan_zip_archive(file_path, max_file_size_bytes=MAX_FILE_SIZE_BYTES):
    matches = []
    try:
        with zipfile.ZipFile(file_path) as archive:
            for member in archive.infolist():
                if member.is_dir() or member.file_size > max_file_size_bytes:
                    continue
                member_path = Path(member.filename)
                if not _should_scan_virtual_file(member_path):
                    continue
                with archive.open(member) as member_file:
                    text = _decode_bytes(member_file.read())
                if text is None:
                    continue
                matches.extend(_scan_text(f"archive:{file_path}::{member.filename}", text))
    except (OSError, zipfile.BadZipFile):
        return matches

    return matches


def _scan_tar_archive(file_path, max_file_size_bytes=MAX_FILE_SIZE_BYTES):
    matches = []
    try:
        with tarfile.open(file_path) as archive:
            for member in archive.getmembers():
                if not member.isfile() or member.size > max_file_size_bytes:
                    continue
                member_path = Path(member.name)
                if not _should_scan_virtual_file(member_path):
                    continue
                member_file = archive.extractfile(member)
                if member_file is None:
                    continue
                text = _decode_bytes(member_file.read())
                if text is None:
                    continue
                matches.extend(_scan_text(f"archive:{file_path}::{member.name}", text))
    except (OSError, tarfile.TarError):
        return matches

    return matches


def _should_scan_virtual_file(file_path):
    if file_path.name in ALLOWED_FILENAMES:
        return True
    if file_path.name.startswith("config."):
        return True
    return file_path.suffix in ALLOWED_SUFFIXES


def _decode_bytes(raw_data):
    if b"\x00" in raw_data[:4096]:
        return None
    try:
        return raw_data.decode("utf-8")
    except UnicodeDecodeError:
        return raw_data.decode("utf-8", errors="ignore")


def _scan_git_history(root):
    if not (root / ".git").exists():
        return []

    matches = []
    commits = _git_command(root, ["rev-list", "--all", f"--max-count={MAX_GIT_COMMITS}"])
    if not commits:
        return matches

    grep_pattern = (
        r"VAULT_TOKEN|vault_token|hvs\.|hvc\.|VAULT_ROLE_ID|VAULT_SECRET_ID|"
        r"role_id|roleId|secret_id|secret-id|secretId|VAULT_ADDR|vault_addr|"
        r"auth/approle/login|auth/aws/login|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|"
        r"AWS_SESSION_TOKEN|AWS_ROLE_ARN|X-Vault-AWS-IAM-Server-ID|"
        r"bound_iam_principal_arn|auto_auth|VAULT_NAMESPACE|VAULT_SKIP_VERIFY|"
        r"database/creds|database/config|database/roles|database/static-roles|"
        r"creation_statements|revocation_statements|default_ttl|max_ttl|"
        r"connection_url|database-plugin|GRANT ALL|ALL PRIVILEGES|SUPERUSER|"
        r"CREATEDB|CREATEROLE|DB_PASSWORD|DB_PASS|DATABASE_PASSWORD|"
        r"DATABASE_PASS|POSTGRES_PASSWORD|POSTGRES_PASS|MYSQL_PASSWORD|"
        r"MYSQL_PASS|PGPASSWORD|PG_PASSWORD|PG_PASS|db_password|db_pass|"
        r"database_password|database_pass|pg_password|mysql_password|:8200"
    )

    for commit in commits.splitlines():
        output = _git_command(
            root,
            ["grep", "-I", "-n", "-E", grep_pattern, commit, "--", "."],
        )
        if not output:
            continue

        for line in output.splitlines():
            parsed = _parse_git_grep_line(line)
            if not parsed:
                continue

            commit_id, file_name, line_number, content = parsed
            virtual_path = f"git:{commit_id[:12]}:{file_name}"
            file_matches = _scan_text(virtual_path, content, line_offset=line_number - 1)
            matches.extend(file_matches)

    return matches


def _git_command(root, args):
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        timeout=10,
        check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""

    return result.stdout


def _parse_git_grep_line(line):
    parts = line.split(":", 3)
    if len(parts) != 4:
        return None

    commit_id, file_name, line_number, content = parts
    try:
        line_number = int(line_number)
    except ValueError:
        line_number = 1

    return commit_id, file_name, line_number, content


def _matched_value(match):
    if match.groups():
        return match.group(1).strip().strip("\"'")

    return match.group(0).strip().strip("\"'")


def _should_skip_generic_match(pattern_name, value):
    if pattern_name in ("vault_token_value", "vault_token_assignment") and value.startswith("hvs.CAES"):
        return True
    if pattern_name == "vault_api_path" and "auth/approle/login" in value.lower():
        return True
    if pattern_name == "vault_api_path" and "auth/aws/login" in value.lower():
        return True
    if pattern_name == "vault_api_path" and "/role-id" in value.lower():
        return True
    if pattern_name == "vault_api_path" and "/secret-id" in value.lower():
        return True
    if pattern_name == "database_static_username" and value.lower() in {
        "username",
        "user",
        "root",
    }:
        return True
    if pattern_name == "database_static_password" and value.lower() in {
        "password",
        "pass",
    }:
        return True

    return False


def _should_skip_context_match(pattern_name, file_path, line_text):
    if not _is_sensitive_material_pattern(pattern_name):
        return False

    if not _is_code_file_path(file_path):
        return False

    lowered_line = line_text.lower()
    validation_markers = (
        "joi.",
        "validator.",
        "schema",
        "z.string(",
        "zod.",
    )
    return any(marker in lowered_line for marker in validation_markers)


def _is_code_file_path(file_path):
    path_text = str(file_path).lower()
    if path_text.startswith("archive:"):
        path_text = path_text.rsplit("::", 1)[-1]
    if path_text.startswith("git:"):
        path_text = path_text.split(":", 2)[-1]

    return any(path_text.endswith(suffix) for suffix in (".js", ".ts", ".py"))


def _line_for_match(text, position):
    line_start = text.rfind("\n", 0, position) + 1
    line_end = text.find("\n", position)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end]


def _confidence_for_match(pattern_name, file_path, line_text):
    lowered_file = str(file_path).lower()
    lowered_line = line_text.lower()

    if pattern_name in (
        "vault_token_assignment",
        "vault_role_id",
        "vault_secret_id",
        "vault_addr_assignment",
        "vault_aws_auth_reference",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "aws_role_arn",
        "vault_aws_iam_server_id",
        "database_static_username",
        "database_static_password",
    ):
        if "vault_" in lowered_line or "approle" in lowered_line:
            return "HIGH"
        if "aws" in lowered_line or "iam" in lowered_line:
            return "HIGH"
        if any(term in lowered_line for term in ("database", "postgres", "mysql", "mssql", "mongodb", "pgpassword", "db_")):
            return "HIGH"
        return "MEDIUM"

    if pattern_name == "vault_response_wrapped_token":
        return "HIGH"

    if pattern_name == "vault_token_value":
        if "vault" in lowered_line or "token" in lowered_line:
            return "HIGH"
        return "MEDIUM"

    if pattern_name in ("approle_login", "aws_iam_login", "vault_api_path"):
        return "HIGH"

    if pattern_name in (
        "approle_cli_login",
        "approle_role_id_path",
        "approle_secret_id_path",
        "aws_cli_login",
        "aws_auth_role_config",
        "aws_bound_iam_principal",
        "vault_namespace",
        "vault_skip_verify",
        "vault_agent_auto_auth",
        "vault_agent_file_sink",
        "vault_database_creds_path",
        "vault_database_config_path",
        "vault_database_role_path",
        "vault_database_plugin",
        "vault_database_connection_url",
        "vault_database_creation_statements",
        "vault_database_broad_privilege_statement",
        "vault_database_revocation_statements",
        "vault_database_default_ttl",
        "vault_database_max_ttl",
        "dynamic_database_username",
    ):
        if any(term in lowered_line for term in ("vault", "auth", "database", "postgres", "mysql", "mssql", "mongodb")):
            return "HIGH"
        return "MEDIUM"

    if pattern_name == "vault_8200_url":
        if any(name in lowered_file for name in ("vault", "docker-compose", "application", "config", ".env")):
            return "HIGH"
        return "MEDIUM"

    return "MEDIUM"


def _is_sensitive_material_pattern(pattern_name):
    return pattern_name in {
        "vault_response_wrapped_token",
        "vault_token_value",
        "vault_token_assignment",
        "vault_role_id",
        "vault_secret_id",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "database_static_username",
        "database_static_password",
    }


def _is_material_value(pattern_name, value):
    if not _is_sensitive_material_pattern(pattern_name):
        return False

    normalized = value.strip().strip("\"'")
    lowered = normalized.lower()
    if not normalized:
        return False

    placeholder_markers = (
        "$",
        "${",
        "$(",
        "<",
        ">",
        "(",
        ")",
        "[",
        "]",
        ";",
        "your-",
        "replace-",
        "replace_",
        "changeme",
        "change-me",
        "example-",
        "-example",
        "fake-",
        "test-",
        "demo-",
        "sample-",
        "placeholder",
        "description:",
        "{{",
        "}}",
    )

    if any(marker in lowered for marker in placeholder_markers):
        return False

    if lowered in {
        "=",
        "roleid",
        "secretid",
        "role_id",
        "secret_id",
        "token",
        "vaulttoken",
        "vault_token",
    }:
        return False

    if lowered.startswith((
        "vaultconfig.",
        "config.",
        "settings.",
        "os.",
        "environment.",
        "var.",
        "local.",
        "each.",
    )):
        return False

    if lowered in {
        "vaultroleid",
        "vaultsecretid",
        "testroleid",
        "testsecretid",
        "fakeroleid",
        "fakesecretid",
        "dbuser",
        "dbpassword",
    }:
        return False

    if not any(character.isalnum() for character in normalized):
        return False

    return True


def mask_value(value):
    if not value:
        return "<empty>"

    return value
