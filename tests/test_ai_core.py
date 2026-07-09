from ai_core.helper import VaultPentestHelper


def test_helper_explains_root_token_creation_error():
    helper = VaultPentestHelper()

    analysis = helper.analyze_error(
        400,
        "root tokens may not be created without parent token being root",
        "privilege_escalation",
    )

    assert analysis["status_code"] == 400
    assert "root olmayan" in analysis["explanation"]
    assert any("admin-policy" in step for step in analysis["next_steps"])


def test_helper_explains_permission_denied():
    helper = VaultPentestHelper()

    analysis = helper.analyze_error(403, "permission denied", "secret_exfiltration")

    assert analysis["module"] == "secret_exfiltration"
    assert "Yetkilendirme" in analysis["explanation"]
    assert any("--capability-audit" in step for step in analysis["next_steps"])


def test_helper_chat_rule_for_exfiltration():
    helper = VaultPentestHelper()

    response = helper.generate_chat_response("secret exfil nasil yapilir?")

    assert "sys/mounts" in response
    assert "LIST" in response
