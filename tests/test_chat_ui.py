from ai_core.chat_ui import (
    _claude_tool_from_mcp_tool,
    _message_content,
    _message_tool_calls,
    _analysis_context_from_result,
    _compact_tool_preview,
    _contains_cjk,
    _certificate_domain_from_result,
    _domain_retry_target_from_result,
    _extract_certificate_domains,
    _fallback_analysis_from_result,
    _mentions_internal_tool,
    _local_cve_assessment,
    _auth_methods_from_findings,
    _capability_operator_answer,
    _active_chain_operator_answer,
    _captured_token_follow_up_answer,
    _direct_captured_token_follow_up,
    _direct_token_chain_request,
    _kv_enumeration_summary,
    _last_vault_token_from_messages,
    _policy_audit_summary,
    _normalize_tool_args,
    _recon_operator_answer,
    _response_message,
    _summarize_recon_findings,
    _tool_calls_from_content,
    _tool_result_text,
    _tool_schema,
)


def test_claude_tool_from_mcp_tool_uses_input_schema():
    class FakeTool:
        name = "run_privilege_escalation"
        description = "Run the module"
        inputSchema = {
            "type": "object",
            "properties": {"vault_addr": {"type": "string"}},
            "required": ["vault_addr"],
        }

    converted = _claude_tool_from_mcp_tool(FakeTool())

    assert converted["name"] == "run_privilege_escalation"
    assert converted["description"] == "Run the module"
    assert converted["input_schema"]["required"] == ["vault_addr"]
    assert converted["input_schema"]["properties"]["vault_addr"] == {"type": "string"}


def test_claude_tool_from_mcp_tool_handles_missing_fields():
    class BareTool:
        name = "get_findings"

    converted = _claude_tool_from_mcp_tool(BareTool())

    assert converted["name"] == "get_findings"
    assert converted["description"] == ""
    assert converted["input_schema"] == {"type": "object", "properties": {}, "required": []}


def test_tool_schema_returns_object_schema():
    class FakeTool:
        inputSchema = {
            "type": "object",
            "properties": {"token": {"type": "string"}},
            "required": ["token"],
        }

    schema = _tool_schema(FakeTool())

    assert schema["type"] == "object"
    assert schema["required"] == ["token"]


def test_tool_schema_falls_back_for_non_object_schema():
    class FakeTool:
        inputSchema = {"type": "string"}

    schema = _tool_schema(FakeTool())

    assert schema == {"type": "object", "properties": {}, "required": []}


def test_response_message_handles_ollama_message_object():
    class ToolCall:
        pass

    class Message:
        role = "assistant"
        content = "Use recon"
        tool_calls = [ToolCall()]

    class Response:
        message = Message()

    message = _response_message(Response())

    assert message["role"] == "assistant"
    assert _message_content(message) == "Use recon"
    assert len(_message_tool_calls(message)) == 1


def test_normalize_tool_args_strips_vault_ui_path_from_target_url():
    normalized = _normalize_tool_args({
        "vault_addr": "https://167.99.238.186/ui/vault/authCwith=token",
        "namespace": {},
    })

    assert normalized == {"vault_addr": "https://167.99.238.186"}


def test_extract_certificate_domains_prefers_san_dns_names():
    domains = _extract_certificate_domains(
        "subject: commonName=vault.venturenox.net, issuer: commonName=E8, san: DNS:vault.venturenox.net"
    )

    assert domains == ["vault.venturenox.net"]


def test_certificate_domain_from_result_reads_tls_evidence():
    domain = _certificate_domain_from_result(
        '{"findings":[{"severity":"PASS","title":"HTTPS enabled",'
        '"evidence":"subject: commonName=vault.venturenox.net, issuer: commonName=E8, san: DNS:vault.venturenox.net"}]}'
    )

    assert domain == "vault.venturenox.net"


def test_domain_retry_target_from_ip_result_uses_certificate_domain():
    retry_target = _domain_retry_target_from_result(
        "https://167.99.238.186/ui/vault/authCwith=token",
        '{"findings":[{"evidence":"san: DNS:vault.venturenox.net"}]}',
    )

    assert retry_target == "https://vault.venturenox.net"


def test_tool_calls_from_content_accepts_local_model_json_tool_call():
    calls = _tool_calls_from_content(
        '{"name": "run_unauthenticated_recon", "arguments": {"vault_addr": "https://vault.test/ui/"}}',
        {"run_unauthenticated_recon"},
    )

    assert calls == [{
        "function": {
            "name": "run_unauthenticated_recon",
            "arguments": {"vault_addr": "https://vault.test/ui/"},
        }
    }]


def test_tool_calls_from_content_ignores_unknown_tool_name():
    calls = _tool_calls_from_content(
        '{"name": "delete_everything", "arguments": {}}',
        {"run_unauthenticated_recon"},
    )

    assert calls == []


def test_compact_tool_preview_summarizes_findings_without_full_evidence():
    preview = _compact_tool_preview(
        '{"status":"completed","target":"https://vault.test","findings_count":2,'
        '"findings":[{"severity":"PASS","title":"HTTPS enabled","module":"tls_scanner",'
        '"evidence":"very long certificate evidence"},'
        '{"severity":"MEDIUM","title":"TLS certificate expires soon","module":"tls_scanner"}]}'
    )

    assert '"findings_count": 2' in preview
    assert "HTTPS enabled" in preview
    assert "TLS certificate expires soon" in preview
    assert "very long certificate evidence" not in preview


def test_analysis_context_prioritizes_actionable_findings():
    context = _analysis_context_from_result(
        '{"status":"completed","target":"https://vault.test","findings_count":3,'
        '"findings":[{"severity":"PASS","title":"HTTPS enabled","module":"tls_scanner"},'
        '{"severity":"HIGH","title":"Vault health endpoint unreachable","module":"health_scanner","evidence":"tls mismatch"},'
        '{"severity":"MEDIUM","title":"TLS certificate expires soon","module":"tls_scanner"}]}'
    )

    assert "Hedef: https://vault.test" in context
    assert context.index("HIGH: Vault health endpoint unreachable") < context.index("MEDIUM: TLS certificate expires soon")
    assert "tls mismatch" in context


def test_contains_cjk_detects_mixed_language_output():
    assert _contains_cjk("Hedef网站")
    assert not _contains_cjk("Hedef pasif kesif tamamlandi")


def test_mentions_internal_tool_detects_debug_tool_names():
    assert _mentions_internal_tool("run_env_scan aracini calistir")
    assert _mentions_internal_tool("get_risk_score sonucu")
    assert not _mentions_internal_tool("Hedefe pasif kesif yapildi")


def test_fallback_analysis_is_plain_operator_text():
    answer = _fallback_analysis_from_result(
        '{"target":"https://vault.test","findings":[{"severity":"HIGH",'
        '"title":"Vault health endpoint unreachable","evidence":"TLS mismatch"},'
        '{"severity":"MEDIUM","title":"TLS certificate expires soon"}]}'
    )

    assert "https://vault.test" in answer
    assert "Vault health endpoint unreachable" in answer
    assert "Token" in answer or "token" in answer
    assert "{" not in answer


def test_recon_operator_answer_reports_done_work_not_suggestions():
    answer = _recon_operator_answer(
        '{"target":"https://vault.venturenox.net","original_target":"https://167.99.238.186",'
        '"findings":[{"severity":"HIGH","title":"Vault health endpoint unreachable","evidence":"TLS mismatch"},'
        '{"severity":"MEDIUM","title":"TLS certificate expires soon"}]}'
    )

    assert "otomatik olarak https://vault.venturenox.net" in answer
    assert "Elde ettigim sonuclarin anlami su" in answer
    assert "Bu prompttan kendi basima" not in answer
    assert "dusunebilirsiniz" not in answer
    assert "onerebilirim" not in answer


def test_recon_operator_answer_no_findings_is_not_repetitive_blocker_text():
    answer = _recon_operator_answer(
        '{"target":"http://188.245.93.253:8200","findings":[]}'
    )

    assert "Token gerektirmeyen pasif yuzeyde" in answer
    assert "authenticated veya aktif asamaya" not in answer
    assert "AppRole cifti" not in answer


def test_recon_operator_answer_explains_high_findings_instead_of_dumping_exceptions():
    answer = _recon_operator_answer(
        '{"target":"https://vault.venturenox.net","findings":['
        '{"severity":"HIGH","title":"Vault health endpoint unreachable",'
        '"evidence":"HTTPSConnectionPool(host=\'167.99.238.186\', port=443): Max retries exceeded with url: /v1/sys/health (Caused by SSLError(SSLCertVerificationError: IP address mismatch))"},'
        '{"severity":"HIGH","title":"Vault health endpoint unreachable",'
        '"evidence":"HTTPSConnectionPool(host=\'167.99.238.186\', port=443): Max retries exceeded with url: /v1/sys/health (Caused by SSLError(SSLCertVerificationError: IP address mismatch))"},'
        '{"severity":"HIGH","title":"TLS handshake failed","evidence":"[Errno 11001] getaddrinfo failed"}]}'
    )

    assert "TLS dogrulamasi" in answer
    assert "DNS cozumlemesi" in answer
    assert answer.count("Vault health endpoint unreachable") == 0
    assert "HTTPSConnectionPool" not in answer
    assert "Max retries exceeded" not in answer


def test_recon_operator_answer_explains_vault_specific_findings_as_plain_text():
    answer = _recon_operator_answer(
        '{"target":"http://20.191.147.244:8200","findings":['
        '{"severity":"HIGH","title":"Vault served over HTTP","evidence":"scheme: http"},'
        '{"severity":"MEDIUM","title":"Vault version below recommended baseline",'
        '"evidence":"endpoint: /v1/sys/health, version: 1.13.2, minimum_recommended_version: 1.15.0"},'
        '{"severity":"INFO","title":"Vault version disclosed","evidence":"version: 1.13.2"},'
        '{"severity":"INFO","title":"Vault cluster name disclosed","evidence":"cluster_name: vault-cluster-17f7d2f7"}]}'
    )

    assert "HTTP uzerinden cevap veriyor" in answer
    assert "Vault surumu 1.13.2" in answer
    assert "CVE-2024-2048" in answer
    assert "cert auth mount'u tespit edilmedi" in answer
    assert "cluster adi `vault-cluster-17f7d2f7`" in answer
    assert "Vault served over HTTP" not in answer
    assert "Vault version below recommended baseline" not in answer
    assert answer.count("CVE-2024-2048") == 1
    assert "- " not in answer
    assert "Bu prompttan kendi basima" not in answer


def test_recon_operator_answer_reports_no_local_cve_match_for_newer_version():
    answer = _recon_operator_answer(
        '{"target":"http://20.191.147.244:8200","findings":['
        '{"severity":"INFO","title":"Vault version disclosed","evidence":"version: 1.19.1"},'
        '{"severity":"INFO","title":"Vault cluster ID disclosed","evidence":"cluster_id: 267cd27b-f071-9cf4-7bce-b834e4e97212"}]}'
    )

    assert "Yerel advisory tablomda bu surum icin dogrudan CVE eslesmesi cikmadi" in answer
    assert "cluster ID `267cd27b-f071-9cf4-7bce-b834e4e97212`" in answer
    assert "Bu prompttan kendi basima" not in answer


def test_capability_operator_answer_explains_privilege_path():
    answer = _capability_operator_answer(
        '{"target":"http://localhost:8200","findings":['
        '{"severity":"CRITICAL","title":"Token has sudo capability on Vault path",'
        '"evidence":"path: auth/token/create; capabilities: create, sudo, update"},'
        '{"severity":"HIGH","title":"Token has write capability on Vault path",'
        '"evidence":"path: auth/token/create; capabilities: create, sudo, update"}]}'
    )

    assert "Token calisiyor" in answer
    assert "`auth/token/create`" in answer
    assert "create, sudo, update" in answer
    assert "privilege escalation" in answer
    assert "token yok" not in answer.lower()


def test_capability_operator_answer_permission_denied_is_not_token_missing():
    answer = _capability_operator_answer(
        '{"target":"http://localhost:8200","findings":['
        '{"severity":"LOW","title":"Token capability audit failed",'
        '"evidence":"error: permission denied, on post http://localhost:8200/v1/sys/capabilities-self"}]}'
    )

    assert "Token girdisi alindi" in answer
    assert "sys/capabilities-self" in answer
    assert "token yok demek degil" in answer
    assert "Su an token olmadigi" not in answer


def test_direct_token_chain_request_extracts_wrapped_token_and_target():
    request = _direct_token_chain_request(
        "Hedef http://localhost:8200. Elimizde token var: "
        "hvs.example-token-line-one\n"
        "line-two-for-unit-test. "
        "Tokenla mumkun olan analiz ve saldiri zincirini calistir."
    )

    assert request == {
        "vault_addr": "http://localhost:8200",
        "token": "hvs.example-token-line-oneline-two-for-unit-test",
    }


def test_direct_token_chain_request_stops_before_explanatory_words_and_uses_fallback_target():
    request = _direct_token_chain_request(
        "hvs.example-token-line-oneline-two-for-unit-test    token bu",
        fallback_vault_addr="http://localhost:8200",
    )

    assert request == {
        "vault_addr": "http://localhost:8200",
        "token": "hvs.example-token-line-oneline-two-for-unit-test",
    }


def test_direct_token_chain_request_ignores_plain_recon_request():
    assert _direct_token_chain_request("Hedef http://localhost:8200 icin pasif bak") is None


def test_captured_token_follow_up_uses_last_token_from_history():
    messages = [
        {"role": "user", "content": "Hedef http://localhost:8200. Token hvs.lowtoken1234567890"},
        {
            "role": "assistant",
            "content": (
                "Yukseltilmis token: `hvs.admin-token-example`\n"
                "Okunan secret ciktilari:\nsecret/app/db: password=x"
            ),
        },
    ]

    assert _last_vault_token_from_messages(messages) == "hvs.admin-token-example"
    assert _direct_captured_token_follow_up("tamam ilerleyim o zaman yeni token ile", messages) == {
        "vault_addr": "http://localhost:8200",
        "token": "hvs.admin-token-example",
    }


def test_captured_token_follow_up_answer_summarizes_post_exploitation():
    answer = _captured_token_follow_up_answer(
        '{"status":"completed","policies_analyzed":2,"findings_count":1,"findings":[]}',
        '{"status":"completed","findings_count":1,"findings":[{"severity":"INFO","title":"KV secret read",'
        '"evidence":"path: secret/app/db; password: x"}]}',
        '{"status":"failed","message":"No database secrets mounts found."}',
        '{"status":"failed","message":"No cloud secrets mounts found."}',
    )

    assert "Yeni tokenla devam ettim" in answer
    assert "2 policy analiz edildi" in answer
    assert "secret/app/db" in answer
    assert "Database secrets engine" in answer
    assert "Cloud secrets engine" in answer


def test_policy_audit_summary_explains_zero_analyzed_policies():
    answer = _policy_audit_summary({
        "status": "completed",
        "policies_analyzed": 0,
        "policies_read_denied": 0,
        "findings_count": 1,
    })

    assert "policy icerigi analiz edilemedi" in answer
    assert "sys/policies/acl" in answer


def test_kv_enumeration_summary_reports_skipped_path_bug_plainly():
    answer = _kv_enumeration_summary({}, [
        {"severity": "INFO", "title": "KV enumeration skipped", "evidence": "missing required argument"}
    ])

    assert answer == ["KV enumeration sonucu: calismadi; KV baslangic path'i verilmedigi icin modul atlandi."]


def test_active_chain_operator_answer_summarizes_success_without_raw_json():
    answer = _active_chain_operator_answer(
        '{"findings":[{"title":"Token has sudo capability on Vault path",'
        '"evidence":"path: auth/token/create; capabilities: create, sudo, update"}]}',
        '{"status":"success","message":"ok","captured_token":"hvs.admin",'
        '"evidence":{"selected_policy":"admin-policy","added_policies":["admin-policy"],'
        '"captured_token":"hvs.admin"}}',
        '{"status":"success","message":"ok","evidence":{"total_leaked_secrets":2,'
        '"leaked_payloads":{"secret/app/config":{"env":"lab"},"secret/app/db":{"password":"x"}}}}',
    )

    assert "Zincir calisti" in answer
    assert "`admin-policy`" in answer
    assert "2 secret" in answer
    assert "`secret/app/db`" in answer
    assert "Yukseltilmis token: `hvs.admin`" in answer
    assert "secret/app/db: password=x" in answer
    assert "policy audit" in answer
    assert "{" not in answer


def test_local_cve_assessment_distinguishes_matches_and_non_matches():
    assert "cert auth mount'u tespit edilmedi" in _local_cve_assessment("1.14.9")
    assert "oncelikli dogrulama hatti" in _local_cve_assessment("1.14.9", {"cert"})
    assert "dogrudan CVE eslesmesi cikmadi" in _local_cve_assessment("1.19.1")


def test_auth_methods_from_findings_extracts_cert_mount():
    methods = _auth_methods_from_findings([
        {"title": "Detected auth mount: cert", "evidence": "endpoint: /v1/sys/internal/ui/mounts, auth_path: cert/, mount_type: cert"}
    ])

    assert methods == {"cert"}


def test_summarize_recon_findings_deduplicates_similar_errors():
    summaries = _summarize_recon_findings([
        {"title": "Vault health endpoint unreachable", "evidence": "certificate verify failed: IP address mismatch"},
        {"title": "Vault health endpoint unreachable", "evidence": "certificate verify failed: IP address mismatch"},
    ])

    assert len(summaries) == 1
    assert "TLS dogrulamasi" in summaries[0]


def test_tool_result_text_extracts_text_content():
    class TextItem:
        text = "module output"

    class ToolResult:
        content = [TextItem()]

    assert _tool_result_text(ToolResult()) == "module output"


def test_tool_result_text_joins_multiple_blocks():
    class TextItem:
        def __init__(self, text):
            self.text = text

    class ToolResult:
        content = [TextItem("first"), TextItem("second")]

    assert _tool_result_text(ToolResult()) == "first\nsecond"


def test_tool_result_text_falls_back_to_str_when_no_text():
    class ToolResult:
        content = []

        def __str__(self):
            return "raw-result"

    assert _tool_result_text(ToolResult()) == "raw-result"
