import asyncio
import concurrent.futures

from core.report import add_finding
from core.tls_config import get_verify
from core.logger import logger


MODULE = "privilege_escalation_scanner"
TIMEOUT = 5
RISKY_CAPABILITIES = {"sudo", "create", "update", "delete", "patch"}
TOKEN_CREATE_PATHS = (
    "auth/token/create",
    "auth/token/create/*",
    "auth/token/create-orphan",
)


def _run_async(coro):
    """Run a coroutine safely regardless of whether an event loop is already running.

    When called from a sync context (CLI) no loop is running and
    ``asyncio.run()`` works directly.  When called from an async context
    (MCP server / chat session) a loop is already running so we execute
    the coroutine on a short-lived thread to avoid the ``asyncio.run()
    cannot be called from a running event loop`` error.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No running loop — the simple path.
        return asyncio.run(coro)

    # Running inside an asyncio event loop — offload to a thread.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, coro).result()


async def analyze_token_privilege_escalation(
    vault_addr,
    token,
    policy_names=None,
    namespace=None,
    timeout=TIMEOUT,
):
    """Safely simulate Vault token privilege escalation risk with capabilities-self."""
    try:
        import aiohttp
    except ImportError as error:
        raise RuntimeError("aiohttp is required for async privilege escalation analysis") from error

    base_url = vault_addr.rstrip("/")
    headers = {"X-Vault-Token": token}
    if namespace:
        headers["X-Vault-Namespace"] = namespace

    client_timeout = aiohttp.ClientTimeout(total=timeout)

    # Respect the global --skip-tls-verify flag
    connector = None
    if not get_verify():
        connector = aiohttp.TCPConnector(ssl=False)

    async with aiohttp.ClientSession(
        timeout=client_timeout, headers=headers, connector=connector
    ) as session:
        resolved_policies = list(policy_names or [])
        if not resolved_policies:
            resolved_policies = await _lookup_self_policies(session, base_url, aiohttp)

        paths = _build_privilege_escalation_paths(resolved_policies)
        capability_response = await _capabilities_self(session, base_url, paths, aiohttp)

    results = _extract_capability_results(capability_response, paths)
    _report_privilege_escalation_findings(results, vault_addr, resolved_policies)
    return {
        "policies": resolved_policies,
        "paths": paths,
        "results": results,
        "capabilities_response": capability_response,
    }


def scan_privilege_escalation(
    vault_addr,
    token,
    policy_names=None,
    namespace=None,
    timeout=TIMEOUT,
):
    logger.info("\n[+] Simulating Vault token privilege escalation risk...")

    if not vault_addr or not token:
        add_finding(
            "INFO",
            "Privilege escalation audit skipped",
            "Privilege escalation analysis requires both --target and --token.",
            recommendation="Provide an authorized Vault address and token.",
            evidence="missing target or token",
            module=MODULE,
            target=vault_addr or "privilege-escalation-audit",
        )
        return None

    try:
        result = _run_async(analyze_token_privilege_escalation(
            vault_addr,
            token,
            policy_names=policy_names,
            namespace=namespace,
            timeout=timeout,
        ))
    except Exception as error:
        add_finding(
            "LOW",
            "Privilege escalation audit failed",
            "The tool could not complete the safe privilege escalation capability simulation.",
            recommendation="Confirm token validity, Vault reachability, namespace, and dependency installation.",
            evidence=f"error: {error}",
            module=MODULE,
            target=vault_addr,
        )
        return None

    _print_privilege_escalation_summary(result)
    return result


async def _lookup_self_policies(session, base_url, aiohttp):
    url = f"{base_url}/v1/auth/token/lookup-self"
    try:
        async with session.get(url) as response:
            data = await _safe_json(response)
            if response.status != 200:
                return []
    except (asyncio.TimeoutError, aiohttp.ClientError, ValueError):
        return []

    token_data = data.get("data", {}) if isinstance(data, dict) else {}
    policies = token_data.get("policies") or []
    identity_policies = token_data.get("identity_policies") or []
    return sorted({str(policy) for policy in [*policies, *identity_policies] if policy})


async def _capabilities_self(session, base_url, paths, aiohttp):
    url = f"{base_url}/v1/sys/capabilities-self"
    try:
        async with session.post(url, json={"paths": paths}) as response:
            data = await _safe_json(response)
            if response.status >= 400:
                return {
                    "error": f"status_code: {response.status}",
                    "data": data,
                }
            return data
    except (asyncio.TimeoutError, aiohttp.ClientError, ValueError) as error:
        return {"error": str(error), "data": {}}


async def _safe_json(response):
    try:
        return await response.json()
    except ValueError:
        text = await response.text()
        raise ValueError(f"invalid json response: {text[:200]}")


def _build_privilege_escalation_paths(policy_names):
    paths = list(TOKEN_CREATE_PATHS)
    for policy_name in policy_names:
        if not policy_name:
            continue
        paths.append(f"sys/policies/acl/{policy_name}")
    return _dedupe(paths)


def _extract_capability_results(response, requested_paths):
    data = response.get("data") if isinstance(response, dict) else {}
    if not isinstance(data, dict):
        data = response if isinstance(response, dict) else {}

    results = []
    for path in requested_paths:
        capabilities = data.get(path) or data.get(path.lstrip("/")) or []
        results.append({
            "path": path,
            "capabilities": sorted({str(capability).lower() for capability in capabilities}),
        })
    return results


def _report_privilege_escalation_findings(results, vault_addr, policy_names):
    risky_results = [
        result for result in results
        if set(result["capabilities"]).intersection(RISKY_CAPABILITIES)
    ]

    for result in risky_results:
        path = result["path"]
        capabilities = set(result["capabilities"])
        risky = sorted(capabilities.intersection(RISKY_CAPABILITIES))
        is_policy_self_modify = path.startswith("sys/policies/acl/")
        is_token_creation = path.startswith("auth/token/create")

        if not (is_policy_self_modify or is_token_creation):
            continue

        add_finding(
            "CRITICAL",
            "Kritik Yetki Yükseltme Riski",
            (
                "The active token appears able to modify policy definitions or create new tokens "
                "with powerful capabilities, based on sys/capabilities-self simulation."
            ),
            recommendation=(
                "Remove sudo/write capabilities from token creation and ACL policy paths unless "
                "strictly required by controlled administrative workflows."
            ),
            evidence=(
                f"endpoint: /v1/sys/capabilities-self, simulated_path: {path}, "
                f"risky_capabilities: {', '.join(risky)}, policies: {', '.join(policy_names) or '<not-resolved>'}"
            ),
            module=MODULE,
            target=vault_addr,
        )

    if not risky_results:
        add_finding(
            "PASS",
            "No token privilege escalation capability observed",
            "The audited token did not return sudo or write-like capabilities on policy or token creation paths.",
            recommendation="Keep policy and token creation capabilities restricted and periodically re-run this audit.",
            evidence=f"paths_checked: {len(results)}, policies: {', '.join(policy_names) or '<not-resolved>'}",
            module=MODULE,
            target=vault_addr,
        )


def _print_privilege_escalation_summary(result):
    logger.info(f"Policies checked : {', '.join(result['policies']) or '<not-resolved>'}")
    for item in result["results"]:
        logger.info(f"{item['path']} -> {', '.join(item['capabilities']) or '<none>'}")


def _dedupe(items):
    deduped = []
    for item in items:
        if item not in deduped:
            deduped.append(item)
    return deduped
