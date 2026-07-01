from core.report import add_finding


def test_secret_read(client, path):
    print(f"\n[+] Testing secret read access: {path}")

    response = client.request("GET", path)

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