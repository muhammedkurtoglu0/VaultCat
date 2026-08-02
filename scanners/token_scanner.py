from core.report import add_finding
from core.logger import logger


def check_token(client):
    logger.info("\n[+] Checking token validity...")

    response = client.request("GET", "auth/token/lookup-self")

    if response is None:
        return None

    if response.status_code == 200:
        logger.info("[+] Token is valid.")
        return response.json()

    elif response.status_code == 403:
        logger.warning("[-] Token is invalid or permission denied.")
        return None

    else:
        logger.warning(f"[-] Unexpected status code: {response.status_code}")
        logger.info(response.text)
        return None


def analyze_token(token_data):
    logger.info("\n[+] Analyzing token...")

    data = token_data.get("data", {})

    policies = data.get("policies", [])
    ttl = data.get("ttl")
    renewable = data.get("renewable")
    orphan = data.get("orphan")
    display_name = data.get("display_name")

    logger.info(f"Display Name : {display_name}")
    logger.info(f"Policies     : {policies}")
    logger.info(f"TTL          : {ttl}")
    logger.info(f"Renewable    : {renewable}")
    logger.info(f"Orphan       : {orphan}")

    logger.info("\n[+] Risk Analysis:")

    if "root" in policies:
        msg = "Token has root policy. Full Vault compromise possible."
        logger.info(f"[CRITICAL] {msg}")
        add_finding("CRITICAL", "Root token detected", msg)

    if ttl == 0:
        msg = "Token has no TTL. It may be long-lived or non-expiring."
        logger.info(f"[HIGH] {msg}")
        add_finding("HIGH", "Non-expiring token", msg)

    elif ttl and ttl > 86400:
        msg = f"Token TTL is longer than 24 hours: {ttl} seconds."
        logger.info(f"[MEDIUM] {msg}")
        add_finding("MEDIUM", "Long-lived token", msg)

    if renewable:
        msg = "Token is renewable. Check renewal policy and max TTL limits."
        logger.info(f"[INFO] {msg}")
        add_finding("INFO", "Renewable token", msg)

    if len(policies) > 3:
        msg = "Token has many policies. Possible privilege creep."
        logger.info(f"[MEDIUM] {msg}")
        add_finding("MEDIUM", "Many policies attached", msg)

    logger.info("[+] Token analysis completed.")
