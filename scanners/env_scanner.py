import os
from pathlib import Path
from core.report import add_finding
from core.logger import logger


def mask_secret(value):
    return value


def scan_environment():
    logger.info("\n[+] Scanning environment variables...")

    vault_vars = [
        "VAULT_TOKEN",
        "VAULT_ADDR",
        "VAULT_NAMESPACE"
    ]

    found_any = False

    for var in vault_vars:
        value = os.getenv(var)

        if value:
            found_any = True
            masked_value = mask_secret(value)

            logger.warning(f"[!] {var} found: {masked_value}")

            if var == "VAULT_TOKEN":
                add_finding(
                    "HIGH",
                    "VAULT_TOKEN found in environment",
                    "Vault token is exposed as an environment variable."
                )

            else:
                add_finding(
                    "INFO",
                    f"{var} found",
                    f"{var} is configured in environment variables."
                )

    if not found_any:
        logger.info("[PASS] No Vault-related environment variables found.")

        add_finding(
            "PASS",
            "No Vault environment variables",
            "No VAULT_TOKEN, VAULT_ADDR or VAULT_NAMESPACE found in environment."
        )

def scan_vault_token_file():
    logger.info("\n[+] Scanning for .vault-token file...")

    token_file = Path.home() / ".vault-token"

    if token_file.exists():
        try:
            token_value = token_file.read_text().strip()
            masked_value = mask_secret(token_value)

            logger.warning(f"[!] .vault-token file found: {token_file}")
            logger.warning(f"[!] Token preview: {masked_value}")

            add_finding(
                "HIGH",
                ".vault-token file found",
                f"Vault token file exists at: {token_file}"
            )

        except Exception as error:
            logger.warning(f"[!] Could not read .vault-token file: {error}")

            add_finding(
                "MEDIUM",
                ".vault-token file unreadable",
                f".vault-token exists but could not be read: {token_file}"
            )

    else:
        logger.info("[PASS] .vault-token file not found.")

        add_finding(
            "PASS",
            ".vault-token file not found",
            "No .vault-token file found in user home directory."
        )
