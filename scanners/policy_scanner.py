import io

from core.report import add_finding


MODULE_NAME = "policy_scanner"
CRITICAL_PREFIXES = ("sys/", "auth/", "identity/")
HIGH_RISK_CAPABILITIES = {"write", "delete", "sudo"}


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

    hcl_analysis = analyze_hcl_policy(policy_text, policy_name=policy_name)
    if hcl_analysis.get("parsed"):
        print("[+] HCL policy analysis completed.")
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


def parse_hcl_policy(policy_text):
    try:
        import hcl2
    except ImportError as error:
        raise RuntimeError("python-hcl2 is required to parse Vault HCL policies") from error

    if not isinstance(policy_text, str) or not policy_text.strip():
        return {}

    return hcl2.load(io.StringIO(policy_text))


def analyze_hcl_policy(policy_text, policy_name="inline-policy", target=None):
    findings = []

    try:
        parsed_policy = parse_hcl_policy(policy_text)
    except RuntimeError as error:
        findings.append(add_finding(
            "LOW",
            "HCL policy parser dependency missing",
            "The HCL policy analyzer could not run because python-hcl2 is not installed.",
            recommendation="Install project dependencies with pip install -r requirements.txt.",
            evidence=str(error),
            module=MODULE_NAME,
            target=target or policy_name,
        ))
        return {"parsed": False, "policy": {}, "rules": [], "findings": findings}
    except Exception as error:
        findings.append(add_finding(
            "LOW",
            "HCL policy parse failed",
            "The supplied Vault ACL policy could not be parsed as HCL2.",
            recommendation="Validate policy syntax and rerun the analyzer.",
            evidence=f"policy: {policy_name}, error: {error}",
            module=MODULE_NAME,
            target=target or policy_name,
        ))
        return {"parsed": False, "policy": {}, "rules": [], "findings": findings}

    rules = extract_policy_rules(parsed_policy)
    for rule in rules:
        findings.extend(_analyze_policy_rule(rule, policy_name, target))

    if rules and not findings:
        findings.append(add_finding(
            "PASS",
            "HCL policy parsed without high-risk ACL findings",
            "The parsed policy did not contain broad wildcard paths or critical-path write/delete/sudo capabilities.",
            recommendation="Continue reviewing policy scope against business need and least privilege.",
            evidence=f"policy: {policy_name}, paths_analyzed: {len(rules)}",
            module=MODULE_NAME,
            target=target or policy_name,
        ))

    return {
        "parsed": True,
        "policy": parsed_policy,
        "rules": rules,
        "findings": findings,
    }


def extract_policy_rules(parsed_policy):
    rules = []
    for path_block in parsed_policy.get("path", []):
        if not isinstance(path_block, dict):
            continue

        for path, body in path_block.items():
            body_data = _first_body(body)
            capabilities = _normalize_capabilities(body_data.get("capabilities", []))
            rules.append({
                "path": path,
                "capabilities": capabilities,
                "raw": body_data,
            })

    return rules


def _analyze_policy_rule(rule, policy_name, target):
    findings = []
    path = rule["path"]
    capabilities = set(rule["capabilities"])
    evidence = (
        f"policy: {policy_name}, path: {path}, "
        f"capabilities: {', '.join(sorted(capabilities)) or '<none>'}"
    )

    if _is_broad_wildcard_path(path):
        findings.append(add_finding(
            "HIGH",
            "Broad wildcard path in Vault ACL policy",
            "The policy contains a broad wildcard path that may grant access beyond least privilege.",
            recommendation="Replace broad wildcard paths with the smallest required Vault paths.",
            evidence=evidence,
            module=MODULE_NAME,
            target=target or policy_name,
        ))

    critical_capabilities = capabilities.intersection(HIGH_RISK_CAPABILITIES)
    if _is_critical_path(path) and critical_capabilities:
        findings.append(add_finding(
            "HIGH",
            "High-risk capability on critical Vault ACL path",
            "The policy grants write, delete, or sudo capability under sys/, auth/, or identity/.",
            recommendation="Restrict critical-path administrative capabilities to tightly controlled administrative policies.",
            evidence=evidence,
            module=MODULE_NAME,
            target=target or policy_name,
        ))

    return findings


def _first_body(body):
    if isinstance(body, list) and body:
        first = body[0]
        return first if isinstance(first, dict) else {}
    if isinstance(body, dict):
        return body
    return {}


def _normalize_capabilities(capabilities):
    if isinstance(capabilities, str):
        capabilities = [capabilities]
    if not isinstance(capabilities, list):
        return []
    return sorted({str(capability).lower() for capability in capabilities})


def _is_broad_wildcard_path(path):
    normalized_path = str(path).strip().strip('"').lower()
    return normalized_path in {"*", "secret/*", "kv/*"} or normalized_path.endswith("/*")


def _is_critical_path(path):
    normalized_path = str(path).strip().strip('"').lower()
    return normalized_path.startswith(CRITICAL_PREFIXES)
