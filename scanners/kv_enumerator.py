import asyncio

from core.report import add_finding
from core.tls_config import get_verify


MODULE = "kv_enumerator"
DEFAULT_MAX_DEPTH = 10
DEFAULT_CONCURRENCY = 5

# Common secret path names for blind enumeration when LIST is denied (403)
BLIND_WORDLIST = [
    "app_config", "appconfig", "app-config",
    "db_password", "dbpassword", "db-password", "database_password",
    "db_username", "db_user", "database_user",
    "aws_keys", "aws_access", "aws_secret", "aws_config",
    "api_key", "apikey", "api-key", "api_secret", "api-token",
    "prod_db", "staging_db", "dev_db", "prod-db",
    "redis_password", "redis_config",
    "postgresql", "postgres_config", "pg_password",
    "mysql_config", "mssql_config",
    "mongodb_uri", "mongo_uri",
    "jwt_secret", "jwt_private", "jwt_public",
    "encryption_key", "signing_key", "master_key",
    "tls_cert", "tls_key", "ssl_cert", "ssl_key",
    "smtp_password", "smtp_config",
    "ldap_password", "ldap_config",
    "oauth_client_id", "oauth_secret", "oidc_secret",
    "root_password", "admin_password", "backup_password",
    "secret", "password", "credentials", "config",
    "web_config", "app_secret", "service_password",
    "storage_key", "backup_key",
    "monitoring_token", "alert_token",
    "pagerduty_key", "slack_webhook", "datadog_api_key",
    "splunk_token", "grafana_token",
    "vault_token", "vault_unseal", "vault_root_token",
]


async def enumerate_kv_tree(
    vault_addr,
    token,
    start_path,
    kv_version=None,
    namespace=None,
    max_depth=DEFAULT_MAX_DEPTH,
    concurrency=DEFAULT_CONCURRENCY,
    read_leaves=True,
    blind_brute=False,
):
    """Recursively map accessible KV paths without printing secret values."""
    try:
        import hvac
    except ImportError as error:
        raise RuntimeError("hvac is required for KV enumeration") from error

    mount_point, initial_path = _split_mount_path(start_path)
    client = hvac.Client(
        url=vault_addr.rstrip("/"),
        token=token,
        namespace=namespace,
        verify=get_verify(),
    )
    resolved_version = kv_version or await _detect_kv_version(client, mount_point)
    tree = {
        "mount": mount_point,
        "kv_version": resolved_version,
        "start_path": initial_path,
        "directories": [],
        "secrets": [],
        "errors": [],
    }

    queue = asyncio.Queue()
    await queue.put((initial_path, 0))
    seen_directories = set()
    seen_secrets = set()
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def worker():
        while True:
            try:
                current_path, depth = await queue.get()
            except asyncio.CancelledError:
                break

            try:
                if depth > max_depth:
                    tree["errors"].append({
                        "path": _display_path(mount_point, current_path),
                        "error": "max depth reached",
                    })
                    continue

                async with semaphore:
                    keys, error = await _list_path(
                        client,
                        mount_point,
                        current_path,
                        resolved_version,
                    )

                if error:
                    # Blind enumeration: LIST failed but we can try common names
                    is_403 = "403" in str(error).lower() or "denied" in str(error).lower()
                    if blind_brute and is_403 and depth < max_depth:
                        await _blind_brute_path(
                            client, mount_point, current_path,
                            resolved_version, tree, seen_secrets,
                            semaphore, queue, depth,
                        )

                    if read_leaves:
                        await _record_leaf_if_readable(
                            client,
                            mount_point,
                            current_path,
                            resolved_version,
                            tree,
                            seen_secrets,
                            semaphore,
                            source_error=error,
                        )
                    else:
                        tree["errors"].append({
                            "path": _display_path(mount_point, current_path),
                            "error": error,
                        })
                    continue

                directory_path = _display_path(mount_point, current_path)
                if directory_path not in seen_directories:
                    seen_directories.add(directory_path)
                    tree["directories"].append(directory_path)

                for key in keys:
                    if key.endswith("/"):
                        child_path = _join_kv_path(current_path, key.rstrip("/"))
                        await queue.put((child_path, depth + 1))
                    elif read_leaves:
                        leaf_path = _join_kv_path(current_path, key)
                        await _record_leaf_if_readable(
                            client,
                            mount_point,
                            leaf_path,
                            resolved_version,
                            tree,
                            seen_secrets,
                            semaphore,
                        )
                    else:
                        leaf_display = _display_path(mount_point, _join_kv_path(current_path, key))
                        if leaf_display not in seen_secrets:
                            seen_secrets.add(leaf_display)
                            tree["secrets"].append({
                                "path": leaf_display,
                                "readable": None,
                                "key_count": None,
                                "keys": [],
                            })
            finally:
                queue.task_done()

    workers = [
        asyncio.create_task(worker())
        for _ in range(max(1, concurrency))
    ]
    await queue.join()
    for worker_task in workers:
        worker_task.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

    tree["tree"] = _build_nested_tree(tree)
    return tree


def scan_kv_tree(
    vault_addr,
    token,
    start_path,
    kv_version=None,
    namespace=None,
    max_depth=DEFAULT_MAX_DEPTH,
    concurrency=DEFAULT_CONCURRENCY,
    read_leaves=True,
    blind_brute=False,
):
    print("\n[+] Enumerating accessible KV secret paths...")

    if not vault_addr or not token or not start_path:
        add_finding(
            "INFO",
            "KV enumeration skipped",
            "KV enumeration requires --target, --token, and --kv-path.",
            recommendation="Provide an authorized Vault target, token, and KV start path.",
            evidence="missing required argument",
            module=MODULE,
            target=vault_addr or "kv-enumeration",
        )
        return None

    try:
        tree = asyncio.run(enumerate_kv_tree(
            vault_addr,
            token,
            start_path,
            kv_version=kv_version,
            namespace=namespace,
            max_depth=max_depth,
            concurrency=concurrency,
            read_leaves=read_leaves,
            blind_brute=blind_brute,
        ))
    except Exception as error:
        add_finding(
            "LOW",
            "KV enumeration failed",
            "The tool could not complete KV path enumeration.",
            recommendation="Confirm the token has list capability on the KV metadata path and that the KV version is correct.",
            evidence=f"path: {start_path}, error: {error}",
            module=MODULE,
            target=vault_addr,
        )
        return None

    _print_tree(tree)
    _add_tree_findings(tree, vault_addr)
    return tree


async def _detect_kv_version(client, mount_point):
    try:
        response = await asyncio.to_thread(client.sys.list_mounted_secrets_engines)
        mount_data = response.get("data", {}) if isinstance(response, dict) else {}
        mount = mount_data.get(f"{mount_point}/") or mount_data.get(mount_point)
        options = mount.get("options", {}) if isinstance(mount, dict) else {}
        if options.get("version") == "2":
            return 2
    except Exception:
        pass
    return 2


async def _list_path(client, mount_point, path, kv_version):
    try:
        if kv_version == 1:
            response = await asyncio.to_thread(
                client.secrets.kv.v1.list_secrets,
                path=path,
                mount_point=mount_point,
            )
        else:
            response = await asyncio.to_thread(
                client.secrets.kv.v2.list_secrets,
                path=path,
                mount_point=mount_point,
            )
        data = response.get("data", {}) if isinstance(response, dict) else {}
        return data.get("keys", []) or [], None
    except Exception as error:
        return [], str(error)


async def _record_leaf_if_readable(
    client,
    mount_point,
    path,
    kv_version,
    tree,
    seen_secrets,
    semaphore,
    source_error=None,
):
    display_path = _display_path(mount_point, path)
    if display_path in seen_secrets:
        return

    async with semaphore:
        readable, keys, error = await _read_leaf_metadata(
            client,
            mount_point,
            path,
            kv_version,
        )

    if not readable and source_error:
        error = source_error

    seen_secrets.add(display_path)
    tree["secrets"].append({
        "path": display_path,
        "readable": readable,
        "key_count": len(keys),
        "keys": keys,
    })

    if error and not readable:
        tree["errors"].append({
            "path": display_path,
            "error": error,
        })


async def _read_leaf_metadata(client, mount_point, path, kv_version):
    try:
        if kv_version == 1:
            response = await asyncio.to_thread(
                client.secrets.kv.v1.read_secret,
                path=path,
                mount_point=mount_point,
            )
            data = response.get("data", {}) if isinstance(response, dict) else {}
            return True, sorted([str(key) for key in data.keys()]), None

        if hasattr(client.secrets.kv.v2, "read_secret_metadata"):
            response = await asyncio.to_thread(
                client.secrets.kv.v2.read_secret_metadata,
                path=path,
                mount_point=mount_point,
            )
            data = response.get("data", {}) if isinstance(response, dict) else {}
            metadata_keys = sorted([str(key) for key in data.keys()])
            return True, metadata_keys, None

        response = await asyncio.to_thread(
            client.secrets.kv.v2.read_secret_version,
            path=path,
            mount_point=mount_point,
            raise_on_deleted_version=False,
        )
        data = response.get("data", {}).get("data", {}) if isinstance(response, dict) else {}
        return True, sorted([str(key) for key in data.keys()]), None
    except Exception as error:
        return False, [], str(error)


async def _blind_read_secret(client, mount_point, path, kv_version):
    """Read secret DATA directly — tries BOTH KV v1 and v2 path formats.

    During blind enumeration we cannot trust auto-detected KV version.
    A ``secret-v1`` mount may actually be KV v1 (no /data/ subpath) or
    KV v2 (with /data/).  We try both and return the first success.
    """
    from hvac.exceptions import VaultError

    v1_attempt = None
    v2_attempt = None

    # ---- KV v1 path (direct) ----
    try:
        response = await asyncio.to_thread(
            client.secrets.kv.v1.read_secret,
            path=path,
            mount_point=mount_point,
        )
        data = response.get("data", {}) if isinstance(response, dict) else {}
        if data:
            v1_attempt = sorted([str(k) for k in data.keys()])
    except VaultError:
        pass
    except Exception:
        pass

    # ---- KV v2 path (/data/ subpath) ----
    try:
        response = await asyncio.to_thread(
            client.secrets.kv.v2.read_secret_version,
            path=path,
            mount_point=mount_point,
            raise_on_deleted_version=False,
        )
        data = response.get("data", {}).get("data", {}) if isinstance(response, dict) else {}
        if data:
            v2_attempt = sorted([str(k) for k in data.keys()])
    except VaultError:
        pass
    except Exception:
        pass

    if v1_attempt is not None:
        return True, v1_attempt, None
    if v2_attempt is not None:
        return True, v2_attempt, None

    return False, [], "blind read: both v1 and v2 attempts failed"


async def _blind_brute_path(
    client, mount_point, current_path, kv_version,
    tree, seen_secrets, semaphore, queue, depth,
):
    """When LIST is denied (403), try common secret names via direct GET.

    For each wordlist entry, attempt:
    1. <current_path>/<name> as a leaf secret (direct read)
    2. <current_path>/<name>/ as a subdirectory (enqueue for recursion)

    Successful hits are recorded as readable secrets or queued directories.
    """
    from asyncio import as_completed

    display_dir = _display_path(mount_point, current_path)

    async def try_one(name: str):
        results = {}

        # Try as leaf: read DATA directly (not metadata — we're blind).
        # Policy may grant "read" on secret path without "read" on metadata/.
        leaf_path = _join_kv_path(current_path, name)
        display = _display_path(mount_point, leaf_path)

        async with semaphore:
            readable, keys, _err = await _blind_read_secret(
                client, mount_point, leaf_path, kv_version,
            )
        if readable and display not in seen_secrets:
            seen_secrets.add(display)
            tree["secrets"].append({
                "path": display,
                "readable": True,
                "key_count": len(keys),
                "keys": keys,
            })
            results["leaf"] = display

        # Try as subdirectory: LIST mount_point/metadata/<current_path>/<name>/
        subdir_path = _join_kv_path(current_path, name) + "/"
        async with semaphore:
            sub_keys, sub_err = await _list_path(
                client, mount_point, subdir_path.rstrip("/"), kv_version,
            )
        if not sub_err and sub_keys:
            await queue.put((subdir_path.rstrip("/"), depth + 1))
            results["subdir"] = _display_path(mount_point, subdir_path)

        return name, results

    tasks = [try_one(name) for name in BLIND_WORDLIST]
    hit_count = 0
    for coro in as_completed(tasks):
        name, results = await coro
        if results:
            hit_count += 1
            if "leaf" in results:
                tree.setdefault("blind_hits", []).append(results["leaf"])
            if "subdir" in results:
                tree.setdefault("blind_hits", []).append(results["subdir"] + " [dir]")

    if hit_count > 0:
        tree.setdefault("blind_hits_note", []).append(
            f"{display_dir}: {hit_count} hit(s) via blind enumeration "
            f"({len(BLIND_WORDLIST)} names tried)"
        )


def _print_tree(tree):
    print(f"Mount      : {tree['mount']}")
    print(f"KV Version : {tree['kv_version']}")
    print(f"Start Path : {_display_path(tree['mount'], tree['start_path'])}")
    print("\nAccessible KV Tree")
    print("------------------")
    _print_nested_tree(tree["mount"], tree.get("tree", {}))

    if tree.get("blind_hits"):
        print("\nBlind Enumeration Hits (LIST denied, brute-forced common names)")
        print("---------------------------------------------------------------")
        for hit in tree["blind_hits"]:
            print(f"  {hit}")
    if tree.get("blind_hits_note"):
        for note in tree["blind_hits_note"]:
            print(f"  [{note}]")

    if tree["errors"]:
        print("\nEnumeration Notes")
        print("-----------------")
        for error in tree["errors"]:
            print(f"{error['path']} -> {error['error']}")


def _build_nested_tree(tree):
    root = {}
    mount = tree["mount"].rstrip("/")

    for directory in sorted(tree["directories"]):
        relative = _relative_display_path(directory, mount)
        node = _ensure_nested_node(root, relative)
        node["_type"] = "directory"

    for secret in sorted(tree["secrets"], key=lambda item: item["path"]):
        relative = _relative_display_path(secret["path"], mount)
        node = _ensure_nested_node(root, relative)
        node["_type"] = "secret"
        node["readable"] = secret["readable"]
        node["key_count"] = secret["key_count"]
        node["keys"] = secret["keys"]

    return root


def _print_nested_tree(mount, nested_tree):
    print(f"{mount.rstrip('/')}/")
    _print_nested_children(nested_tree, indent="  ")


def _print_nested_children(node, indent):
    metadata_keys = {"_type", "readable", "key_count", "keys"}
    for name in sorted(key for key in node.keys() if key not in metadata_keys):
        child = node[name]
        child_type = child.get("_type")
        if child_type == "secret":
            readable = "readable" if child.get("readable") else "not-readable"
            print(f"{indent}{name} ({readable}, keys: {child.get('key_count')})")
        else:
            print(f"{indent}{name}/")
            _print_nested_children(child, indent + "  ")


def _ensure_nested_node(root, relative_path):
    current = root
    if not relative_path:
        current["_type"] = "directory"
        return current

    for part in relative_path.split("/"):
        if not part:
            continue
        current = current.setdefault(part, {})
    return current


def _relative_display_path(display_path, mount):
    clean = display_path.strip("/")
    prefix = mount.strip("/")
    if clean == prefix:
        return ""
    if clean.startswith(prefix + "/"):
        return clean[len(prefix) + 1:]
    return clean


def _add_tree_findings(tree, target):
    add_finding(
        "INFO",
        "Accessible KV path tree enumerated",
        "The supplied token could list one or more KV paths from the requested starting point.",
        recommendation="Review whether the token requires list/read access to every enumerated path.",
        evidence=(
            f"mount: {tree['mount']}, kv_version: {tree['kv_version']}, "
            f"directories: {len(tree['directories'])}, secrets: {len(tree['secrets'])}"
        ),
        module=MODULE,
        target=target,
    )

    readable_count = len([secret for secret in tree["secrets"] if secret["readable"]])
    if readable_count:
        add_finding(
            "LOW",
            "Token can read KV secret metadata or keys",
            "The supplied token could read metadata or key names for enumerated KV secrets.",
            recommendation="Confirm that read access is required and scoped to the smallest necessary KV paths.",
            evidence=f"readable_secret_paths: {readable_count}",
            module=MODULE,
            target=target,
        )

    blind_hits = tree.get("blind_hits", [])
    if blind_hits:
        add_finding(
            "MEDIUM",
            "Blind enumeration discovered readable secrets without list permission",
            (
                "The token could not LIST directory contents, but direct GET requests "
                "for common secret names succeeded. This is a classic Vault policy gap: "
                "read without list allows blind brute-force discovery."
            ),
            recommendation=(
                "Either grant list permission alongside read, or use unpredictable "
                "secret path names that cannot be guessed."
            ),
            evidence=f"blind_hits: {len(blind_hits)}, paths: {', '.join(blind_hits[:10])}",
            module=MODULE,
            target=target,
        )


def _split_mount_path(start_path):
    clean_path = start_path.strip().strip("/")
    if not clean_path:
        raise ValueError("KV start path must include a mount, for example secret/ or kv/app")

    parts = clean_path.split("/", 1)
    mount_point = parts[0]
    relative_path = parts[1] if len(parts) > 1 else ""
    return mount_point, relative_path.strip("/")


def _join_kv_path(parent, child):
    if not parent:
        return child.strip("/")
    return f"{parent.strip('/')}/{child.strip('/')}"


def _display_path(mount_point, path):
    if not path:
        return f"{mount_point}/"
    return f"{mount_point}/{path.strip('/')}"
