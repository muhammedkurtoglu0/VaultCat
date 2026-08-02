import asyncio

from core.report import add_finding
from reconnaissance.version_cve_matcher import match_vault_version_cves
from core.logger import logger


MODULE_NAME = "vault_recon"
DEFAULT_TIMEOUT = 5

ENDPOINTS = {
    "health": "/v1/sys/health",
    "seal_status": "/v1/sys/seal-status",
    "leader": "/v1/sys/leader",
}


async def vault_recon(vault_addr, timeout=DEFAULT_TIMEOUT):
    """Collect unauthenticated Vault health, seal, and leader metadata."""
    try:
        import aiohttp
    except ImportError as error:
        raise RuntimeError("aiohttp is required for async Vault recon") from error

    base_url = vault_addr.rstrip("/")
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    # Respect the global TLS setting (--skip-tls-verify) — otherwise the
    # async collector fails against self-signed lab/internal Vaults.
    from core.tls_config import get_verify
    connector = None if get_verify() else aiohttp.TCPConnector(ssl=False)

    async with aiohttp.ClientSession(timeout=client_timeout, connector=connector) as session:
        tasks = {
            name: _fetch_json(session, base_url + path, aiohttp)
            for name, path in ENDPOINTS.items()
        }
        responses = await asyncio.gather(*tasks.values())

    raw = dict(zip(tasks.keys(), responses))
    health_data = _response_data(raw.get("health"))
    seal_data = _response_data(raw.get("seal_status"))
    leader_data = _response_data(raw.get("leader"))

    return {
        "target": base_url,
        "sealed": _first_present(
            health_data.get("sealed"),
            seal_data.get("sealed"),
        ),
        "initialized": _first_present(
            health_data.get("initialized"),
            seal_data.get("initialized"),
        ),
        "cluster_name": _first_present(
            health_data.get("cluster_name"),
            seal_data.get("cluster_name"),
        ),
        "cluster_id": _first_present(
            health_data.get("cluster_id"),
            seal_data.get("cluster_id"),
        ),
        "version": _first_present(
            health_data.get("version"),
            seal_data.get("version"),
        ),
        "leader": {
            "ha_enabled": leader_data.get("ha_enabled"),
            "is_self": leader_data.get("is_self"),
            "leader_address": leader_data.get("leader_address"),
            "leader_cluster_address": leader_data.get("leader_cluster_address"),
        },
        "endpoints": raw,
    }


def scan_vault_recon(target, timeout=DEFAULT_TIMEOUT):
    logger.info("\n[+] Running async Vault recon collector...")

    try:
        result = asyncio.run(vault_recon(target, timeout=timeout))
    except RuntimeError as error:
        add_finding(
            "LOW",
            "Async Vault recon dependency missing",
            "The async Vault recon collector could not run because a Python dependency is missing.",
            recommendation="Install project dependencies with pip install -r requirements.txt.",
            evidence=str(error),
            module=MODULE_NAME,
            target=target,
        )
        return None

    _print_recon_result(result)
    _add_recon_findings(result)
    if result.get("version"):
        match_vault_version_cves(result["version"], target=result["target"])
    return result


async def _fetch_json(session, url, aiohttp):
    try:
        async with session.get(url) as response:
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    data = await response.json()
                except ValueError:
                    text = await response.text()
                    return {
                        "ok": False,
                        "status_code": response.status,
                        "data": {"raw_body": text[:500]},
                        "error": "invalid json response",
                        "url": url,
                    }
            else:
                text = await response.text()
                data = {"raw_body": text[:500]}

            return {
                "ok": response.status < 500,
                "status_code": response.status,
                "data": data,
                "error": None,
                "url": url,
            }
    except asyncio.TimeoutError:
        return {
            "ok": False,
            "status_code": None,
            "data": None,
            "error": "request timeout",
            "url": url,
        }
    except aiohttp.ClientError as error:
        return {
            "ok": False,
            "status_code": None,
            "data": None,
            "error": str(error),
            "url": url,
        }


def _print_recon_result(result):
    logger.info(f"Target       : {result['target']}")
    logger.info(f"Initialized  : {result['initialized']}")
    logger.info(f"Sealed       : {result['sealed']}")
    logger.info(f"Cluster Name : {result['cluster_name']}")
    logger.info(f"Cluster ID   : {result['cluster_id']}")
    logger.info(f"Version      : {result['version']}")
    logger.info(f"Leader       : {result['leader']}")


def _add_recon_findings(result):
    target = result["target"]
    endpoint_evidence = _endpoint_evidence(result)

    add_finding(
        "INFO",
        "Async Vault recon metadata collected",
        "Unauthenticated Vault health, seal-status, and leader endpoints were queried asynchronously.",
        recommendation="Use this metadata for authorized vulnerability management and version tracking.",
        evidence=endpoint_evidence,
        module=MODULE_NAME,
        target=target,
    )

    if result.get("sealed") is True:
        add_finding(
            "INFO",
            "Vault sealed state observed",
            "The unauthenticated recon collector observed that Vault reports sealed=true.",
            recommendation="Confirm this state is expected for the assessed environment.",
            evidence="sealed: true",
            module=MODULE_NAME,
            target=target,
        )

    if result.get("version"):
        add_finding(
            "INFO",
            "Vault version captured for tracking",
            "The unauthenticated recon collector captured a Vault version value for vulnerability management.",
            recommendation="Compare the observed version with the organization's approved Vault baseline and HashiCorp advisories.",
            evidence=f"version: {result['version']}",
            module=MODULE_NAME,
            target=target,
        )

    if result.get("cluster_name"):
        add_finding(
            "INFO",
            "Vault cluster name captured for inventory",
            "The unauthenticated recon collector captured the Vault cluster name.",
            recommendation="Confirm whether unauthenticated cluster metadata exposure is acceptable for this deployment.",
            evidence=f"cluster_name: {result['cluster_name']}",
            module=MODULE_NAME,
            target=target,
        )


def _endpoint_evidence(result):
    parts = []
    for name, response in result.get("endpoints", {}).items():
        status_code = response.get("status_code")
        error = response.get("error")
        if error:
            parts.append(f"{name}: error={error}")
        else:
            parts.append(f"{name}: status_code={status_code}")
    return "; ".join(parts)


def _response_data(response):
    if not response:
        return {}
    data = response.get("data")
    return data if isinstance(data, dict) else {}


def _first_present(*values):
    for value in values:
        if value is not None:
            return value
    return None
