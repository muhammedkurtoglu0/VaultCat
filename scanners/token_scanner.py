from core.report import add_finding


def check_token(client):
    print("\n[+] Checking token validity...")

    response = client.request("GET", "auth/token/lookup-self")

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

    print("[+] Token analysis completed.")