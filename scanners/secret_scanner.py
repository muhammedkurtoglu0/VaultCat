from core.report import add_finding
from core.logger import logger


def test_secret_read(client, path):
    logger.info(f"\n[+] Testing secret read access: {path}")

    response = client.request("GET", path)

    if response is None:
        return

    if response.status_code == 200:
        logger.info("[+] Secret read successful.")
        logger.warning("[!] This token can access the given secret path.")

        add_finding(
            "INFO",
            "Secret read access confirmed",
            f"Token can read secret path: {path}"
        )

        logger.info(response.json())

    elif response.status_code == 403:
        logger.warning("[-] Permission denied. Token cannot read this path.")

        add_finding(
            "PASS",
            "Least privilege check",
            f"Token cannot read unauthorized path: {path}"
        )

    elif response.status_code == 404:
        logger.warning("[-] Secret path not found.")

    else:
        logger.warning(f"[-] Status code: {response.status_code}")
        logger.info(response.text)
