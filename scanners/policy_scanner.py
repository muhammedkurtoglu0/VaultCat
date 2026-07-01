from core.report import add_finding


def read_policy(client, policy_name):
    print(f"\n[+] Reading policy: {policy_name}")

    response = client.request("GET", f"sys/policies/acl/{policy_name}")

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