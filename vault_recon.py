import requests
import argparse

findings = []


def request_vault(method, url, token):
    headers = {
        "X-Vault-Token": token
    }

    try:
        response = requests.request(method, url, headers=headers, timeout=5)
        return response
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}")
        return None


def add_finding(severity, title, description):
    findings.append({
        "severity": severity,
        "title": title,
        "description": description
    })


def print_report():
    print("\n===============================")
    print("Vault Pentest Findings Report")
    print("===============================")

    if not findings:
        print("[PASS] No major findings detected.")
        return

    for finding in findings:
        print(f"\n[{finding['severity']}] {finding['title']}")
        print(f"Description: {finding['description']}")


def check_token(vault_addr, token):
    print("\n[+] Checking token validity...")

    url = f"{vault_addr}/v1/auth/token/lookup-self"
    response = request_vault("GET", url, token)

    if response is None:
        return None

    if response.status_code == 200:
        print("[+] Token is valid.")
        return response.json()

    elif response.status_code == 403:
        print("[-] Token is invalid or permission denied.")
        return None

    else:
        print(f"[-] Unexpected status code: {response.status_code}")
        print(response.text)
        return None


def analyze_token(token_data):
    print("\n[+] Analyzing token...")

    data = token_data.get("data", {})

    policies = data.get("policies", [])
    ttl = data.get("ttl")
    renewable = data.get("renewable")
    orphan = data.get("orphan")
    display_name = data.get("display_name")

    print(f"Display Name : {display_name}")
    print(f"Policies     : {policies}")
    print(f"TTL          : {ttl}")
    print(f"Renewable    : {renewable}")
    print(f"Orphan       : {orphan}")

    print("\n[+] Risk Analysis:")

    if "root" in policies:
        msg = "Token has root policy. Full Vault compromise possible."
        print(f"[CRITICAL] {msg}")
        add_finding("CRITICAL", "Root token detected", msg)

    if ttl == 0:
        msg = "Token has no TTL. It may be long-lived or non-expiring."
        print(f"[HIGH] {msg}")
        add_finding("HIGH", "Non-expiring token", msg)

    elif ttl and ttl > 86400:
        msg = f"Token TTL is longer than 24 hours: {ttl} seconds."
        print(f"[MEDIUM] {msg}")
        add_finding("MEDIUM", "Long-lived token", msg)

    if renewable:
        msg = "Token is renewable. Check renewal policy and max TTL limits."
        print(f"[INFO] {msg}")
        add_finding("INFO", "Renewable token", msg)

    if len(policies) > 3:
        msg = "Token has many policies. Possible privilege creep."
        print(f"[MEDIUM] {msg}")
        add_finding("MEDIUM", "Many policies attached", msg)

    if policies == ["default"]:
        print("[LOW] Token only has default policy.")
        add_finding(
            "LOW",
            "Default-only token",
            "Token only has default policy."
        )

    print("[+] Token analysis completed.")


def test_secret_read(vault_addr, token, path):
    print(f"\n[+] Testing secret read access: {path}")

    url = f"{vault_addr}/v1/{path}"
    response = request_vault("GET", url, token)

    if response is None:
        return

    if response.status_code == 200:
        print("[+] Secret read successful.")
        print("[!] This token can access the given secret path.")

        add_finding(
            "INFO",
            "Secret read access confirmed",
            f"Token can read secret path: {path}"
        )

        print(response.json())

    elif response.status_code == 403:
        print("[-] Permission denied. Token cannot read this path.")

        add_finding(
            "PASS",
            "Least privilege check",
            f"Token cannot read unauthorized path: {path}"
        )

    elif response.status_code == 404:
        print("[-] Secret path not found.")

    else:
        print(f"[-] Status code: {response.status_code}")
        print(response.text)


def read_policy(vault_addr, token, policy_name):
    print(f"\n[+] Reading policy: {policy_name}")

    url = f"{vault_addr}/v1/sys/policies/acl/{policy_name}"
    response = request_vault("GET", url, token)

    if response is None:
        return None

    if response.status_code == 200:
        print("[+] Policy read successful.")
        policy_data = response.json()
        policy_text = policy_data.get("data", {}).get("policy", "")

        print("\n--- Policy Content ---")
        print(policy_text)
        print("----------------------")

        return policy_text

    elif response.status_code == 403:
        print("[-] Permission denied. Token cannot read policy.")

        add_finding(
            "INFO",
            "Policy read denied",
            f"Token cannot read policy: {policy_name}"
        )

        return None

    elif response.status_code == 404:
        print("[-] Policy not found.")

        add_finding(
            "LOW",
            "Policy not found",
            f"Policy does not exist: {policy_name}"
        )

        return None

    else:
        print(f"[-] Status code: {response.status_code}")
        print(response.text)
        return None


def analyze_policy(policy_name, policy_text):
    print(f"\n[+] Analyzing policy: {policy_name}")

    if not policy_text:
        print("[-] Empty policy text.")
        return

    risky_keywords = {
        'path "*"': (
            "CRITICAL",
            "Wildcard path detected",
            "Policy grants access to all Vault paths."
        ),
        '"sudo"': (
            "CRITICAL",
            "Sudo capability detected",
            "Policy contains sudo capability."
        ),
        '"delete"': (
            "HIGH",
            "Delete capability detected",
            "Policy can delete secrets or Vault data."
        ),
        '"update"': (
            "MEDIUM",
            "Update capability detected",
            "Policy can modify existing data."
        ),
        '"create"': (
            "MEDIUM",
            "Create capability detected",
            "Policy can create new data."
        ),
        '"list"': (
            "LOW",
            "List capability detected",
            "Policy can enumerate paths."
        ),
    }

    for keyword, finding in risky_keywords.items():
        if keyword in policy_text:
            severity, title, description = finding
            print(f"[{severity}] {title}")

            add_finding(
                severity,
                title,
                f"{description} Policy: {policy_name}"
            )

    if 'capabilities = ["read"]' in policy_text:
        print("[PASS] Read-only policy detected.")

        add_finding(
            "PASS",
            "Read-only policy",
            f"Policy appears to be read-only: {policy_name}"
        )

    print("[+] Policy analysis completed.")


def main():
    parser = argparse.ArgumentParser(
        description="Basic Vault Token Recon and Policy Scanner"
    )

    parser.add_argument(
        "--addr",
        required=True,
        help="Vault address, example: http://localhost:8200"
    )

    parser.add_argument(
        "--token",
        required=True,
        help="Vault token"
    )

    parser.add_argument(
        "--secret-path",
        default="secret/data/myapp",
        help="Secret path to test"
    )

    parser.add_argument(
        "--policy",
        help="Policy name to analyze"
    )

    args = parser.parse_args()

    vault_addr = args.addr.rstrip("/")
    token = args.token

    token_data = check_token(vault_addr, token)

    if token_data:
        analyze_token(token_data)
        test_secret_read(vault_addr, token, args.secret_path)

        if args.policy:
            policy_text = read_policy(vault_addr, token, args.policy)

            if policy_text:
                analyze_policy(args.policy, policy_text)

        print_report()


if __name__ == "__main__":
    main()