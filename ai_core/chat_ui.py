import asyncio
import ipaddress
import json
import logging
import os
import re
import sys
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import ollama
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from prompt_toolkit import PromptSession
from reconnaissance.version_cve_matcher import match_vault_version_cves


DEFAULT_MCP_URL = "http://127.0.0.1:8000/mcp"
DEFAULT_MODEL = "qwen2.5:7b"
MAX_AGENT_STEPS = 6
DEFAULT_TOOL_TIMEOUT_SECONDS = 90
MAX_TOOL_RESULT_PREVIEW = 900
MAX_TOOL_RESULT_FOR_ANALYSIS = 6000

SYSTEM_PROMPT = """Sen yetkili Vault guvenlik degerlendirmesi yapan yerel bir AI ajansin.
Yalnizca kullanicinin sahip oldugu veya acikca yetkili oldugu Vault lab/hedeflerinde calisirsin.

Karar kurallari:
1. Kullanici sadece hedef URL verirse ve token yoksa aktif token gerektiren araclari cagirma.
2. Token yokken ilk tercih run_unauthenticated_recon veya yerel token aramak icin run_env_scan olmalidir.
3. Token yokken run_privilege_escalation, run_secret_exfiltration, run_database_credential_harvest veya run_cloud_key_exfiltration cagirma.
4. Kullanici yerel proje/dizin taramasi isterse run_hijack_scan kullan.
5. Token verildiyse once read-only analiz araclarini sec: run_capability_audit, run_policy_auditor, run_priv_esc_scan, run_kv_enumeration.
6. Aktif/state-changing araclari sadece token varsa ve kullanici bunu acikca istediyse sec.
7. Ayni basarisiz tool call'u ayni argumanlarla tekrar etme; baska modulu sec veya kullanicidan eksik bilgiyi iste.
8. Emin degilsen list_active_modules ile aktif modulleri incele.
9. Kullaniciya ham JSON, tool call semasi veya debug logu gosterme; normal bir insan gibi net ve kanita dayali cevap ver.
"""


async def main_chat_loop(mcp_url: str = DEFAULT_MCP_URL):
    _configure_quiet_logging()
    model = os.getenv("LOCAL_AI_MODEL", os.getenv("OLLAMA_MODEL", DEFAULT_MODEL))
    prompt_session = PromptSession()

    print("====================================================")
    print("    Vault Pentest Tool - Local Ollama Agent")
    print("====================================================")
    print(f"[*] Model        : {model}")
    print(f"[*] MCP endpoint : {mcp_url}")
    print("[*] Araclar yukleniyor...\n")

    try:
        async with streamablehttp_client(mcp_url) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                available_tools = await session.list_tools()
                ollama_tools = [
                    _ollama_tool_from_mcp_tool(tool)
                    for tool in available_tools.tools
                    if getattr(tool, "name", None)
                ]

                print(f"[+] Ajan hazir. {len(ollama_tools)} arac bagli. Cikis icin 'exit' yaz.\n")

                messages: list[dict[str, Any]] = [
                    {"role": "system", "content": SYSTEM_PROMPT}
                ]

                while True:
                    try:
                        user_input = await prompt_session.prompt_async("Pentest-AI > ")
                        if user_input.strip().lower() in {"exit", "quit"}:
                            break
                        if not user_input.strip():
                            continue

                        messages.append({"role": "user", "content": user_input})
                        if await _maybe_run_direct_user_intent(session, messages, user_input):
                            continue
                        await _run_agent_loop(session, model, messages, ollama_tools)

                    except KeyboardInterrupt:
                        break
    except Exception as error:
        if _looks_like_mcp_connect_error(error):
            print(f"[!] MCP server'a baglanilamadi: {mcp_url}")
            print("[!] Once ayri bir terminalde su komutu calistir:")
            print("    python .\\main.py mcp")
            print("[!] MCP server acildiktan sonra bu terminalde tekrar:")
            print("    python .\\main.py chat")
            return
        raise

    print("\n[*] Oturum sonlandirildi.")


async def _run_agent_loop(
    session: ClientSession,
    model: str,
    messages: list[dict[str, Any]],
    ollama_tools: list[dict[str, Any]],
) -> None:
    seen_calls: set[str] = set()

    for _ in range(MAX_AGENT_STEPS):
        try:
            response = await asyncio.to_thread(
                ollama.chat,
                model=model,
                messages=messages,
                tools=ollama_tools,
            )
        except Exception as error:
            print(f"\n[!] Ollama baglanti/model hatasi: {error}")
            print("[!] Ollama servisinin calistigindan ve modelin indirildiginden emin ol.\n")
            return

        response_message = _response_message(response)
        known_tool_names = _known_tool_names(ollama_tools)

        content = _message_content(response_message)
        tool_calls = _message_tool_calls(response_message)
        if not tool_calls:
            tool_calls = _tool_calls_from_content(content, known_tool_names)
        if not tool_calls:
            messages.append(response_message)
            if content:
                print(f"\n{_strip_chat_noise(content)}\n")
            return

        messages.append({"role": "assistant", "content": ""})

        for tool_call in tool_calls:
            tool_name, tool_args = _tool_call_name_args(tool_call)
            tool_args = _normalize_tool_args(tool_args)
            call_key = json.dumps(
                {"name": tool_name, "arguments": tool_args},
                sort_keys=True,
                ensure_ascii=False,
            )
            if call_key in seen_calls:
                repeated = (
                    f"Ayni tool call tekrarlandi ve calistirilmadi: {tool_name}. "
                    "Baska bir modul sec veya kullanicidan eksik bilgiyi iste."
                )
                messages.append({"role": "tool", "name": tool_name or "unknown_tool", "content": repeated})
                print(f"\n[!] {repeated}\n")
                return
            seen_calls.add(call_key)

            if _verbose_chat():
                print(f"\n[AI Karari] -> '{tool_name}'", flush=True)
                if tool_args:
                    print(f"   Args: {json.dumps(tool_args, indent=2, ensure_ascii=False)}", flush=True)

            try:
                timeout_seconds = _tool_timeout_seconds()
                tool_result = await asyncio.wait_for(
                    session.call_tool(tool_name, arguments=tool_args),
                    timeout=timeout_seconds,
                )
                result_text = _tool_result_text(tool_result)
            except asyncio.TimeoutError:
                result_text = json.dumps(
                    {
                        "status": "error",
                        "message": (
                            f"Tool call timed out after {_tool_timeout_seconds()} seconds: "
                            f"{tool_name}"
                        ),
                    },
                    ensure_ascii=False,
                )
            except Exception as error:
                result_text = json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)

            result_text = await _maybe_retry_recon_with_certificate_domain(
                session,
                tool_name,
                tool_args,
                result_text,
            )

            if _verbose_chat():
                preview = _compact_tool_preview(result_text)
                print(f"\n[Sonuc] -> {preview}\n")
                print("-" * 60)

            messages.append({"role": "tool", "name": tool_name, "content": result_text})
            answer = _deterministic_tool_answer(tool_name, result_text)
            if not answer:
                answer = await _ai_tool_analysis(model, messages, tool_name, result_text)
            if answer:
                messages.append({"role": "assistant", "content": answer})
                print(f"\n{answer}\n")
            return

    print(f"\n[!] Agent adim limiti doldu ({MAX_AGENT_STEPS}). Yeni komut bekleniyor.\n")


async def _maybe_run_direct_user_intent(
    session: ClientSession,
    messages: list[dict[str, Any]],
    user_input: str,
) -> bool:
    follow_up = _direct_captured_token_follow_up(user_input, messages)
    if follow_up:
        await _run_captured_token_follow_up(session, messages, follow_up["vault_addr"], follow_up["token"])
        return True

    request = _direct_token_chain_request(user_input, fallback_vault_addr=_last_vault_addr_from_messages(messages))
    if not request:
        return False

    vault_addr = request["vault_addr"]
    token = request["token"]
    print("\n[*] Tokenli zincir istegi algilandi; pasif kesfe sapmadan capability audit ve aktif lab zinciri calistiriliyor.\n")

    capability_result = await _call_mcp_tool_text(
        session,
        "run_capability_audit",
        {
            "vault_addr": vault_addr,
            "token": token,
            "paths": [
                "auth/token/create",
                "sys/capabilities-self",
                "secret/data/app/db",
                "secret/metadata/app",
                "secret/data/*",
                "secret/metadata/*",
            ],
        },
    )
    messages.append({"role": "tool", "name": "run_capability_audit", "content": capability_result})

    capability_answer = _capability_operator_answer(capability_result)

    if not _capability_result_has_progress_path(capability_result):
        messages.append({"role": "assistant", "content": capability_answer})
        print(f"{capability_answer}\n")
        return True

    escalation_result = await _call_mcp_tool_text(
        session,
        "run_privilege_escalation",
        {
            "vault_addr": vault_addr,
            "token": token,
            "policies": ["admin-policy"],
            "ttl": "30m",
        },
    )
    messages.append({"role": "tool", "name": "run_privilege_escalation", "content": escalation_result})

    exfil_result = await _call_mcp_tool_text(
        session,
        "run_secret_exfiltration",
        {"vault_addr": vault_addr, "max_depth": 3},
    )
    messages.append({"role": "tool", "name": "run_secret_exfiltration", "content": exfil_result})

    chain_answer = _active_chain_operator_answer(capability_result, escalation_result, exfil_result)
    messages.append({"role": "assistant", "content": chain_answer})
    print(f"{chain_answer}\n")
    return True


async def _run_captured_token_follow_up(
    session: ClientSession,
    messages: list[dict[str, Any]],
    vault_addr: str,
    token: str,
) -> None:
    print("\n[*] Ele gecen yuksek yetkili token ile post-exploitation kontrolleri calistiriliyor.\n")

    policy_result = await _call_mcp_tool_text(
        session,
        "run_policy_auditor",
        {"vault_addr": vault_addr, "token": token},
    )
    messages.append({"role": "tool", "name": "run_policy_auditor", "content": policy_result})

    kv_result = await _call_mcp_tool_text(
        session,
        "run_kv_enumeration",
        {"vault_addr": vault_addr, "token": token, "kv_path": "secret/", "max_depth": 5, "read_leaves": True},
    )
    messages.append({"role": "tool", "name": "run_kv_enumeration", "content": kv_result})

    database_result = await _call_mcp_tool_text(
        session,
        "run_database_credential_harvest",
        {"vault_addr": vault_addr, "token": token},
    )
    messages.append({"role": "tool", "name": "run_database_credential_harvest", "content": database_result})

    cloud_result = await _call_mcp_tool_text(
        session,
        "run_cloud_key_exfiltration",
        {"vault_addr": vault_addr, "token": token},
    )
    messages.append({"role": "tool", "name": "run_cloud_key_exfiltration", "content": cloud_result})

    answer = _captured_token_follow_up_answer(policy_result, kv_result, database_result, cloud_result)
    messages.append({"role": "assistant", "content": answer})
    print(f"{answer}\n")


async def _call_mcp_tool_text(
    session: ClientSession,
    tool_name: str,
    arguments: dict[str, Any],
) -> str:
    try:
        tool_result = await asyncio.wait_for(
            session.call_tool(tool_name, arguments=_normalize_tool_args(arguments)),
            timeout=_tool_timeout_seconds(),
        )
        return _tool_result_text(tool_result)
    except asyncio.TimeoutError:
        return json.dumps(
            {"status": "error", "message": f"Tool call timed out after {_tool_timeout_seconds()} seconds: {tool_name}"},
            ensure_ascii=False,
        )
    except Exception as error:
        return json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False)


def start_chat_session() -> None:
    try:
        asyncio.run(main_chat_loop())
    except KeyboardInterrupt:
        print("\n[*] Oturum sonlandirildi.")
        sys.exit(0)


def _ollama_tool_from_mcp_tool(tool: Any) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": getattr(tool, "name", "") or "",
            "description": getattr(tool, "description", "") or "",
            "parameters": _tool_schema(tool),
        },
    }


def _claude_tool_from_mcp_tool(tool: Any) -> dict[str, Any]:
    return {
        "name": getattr(tool, "name", "") or "",
        "description": getattr(tool, "description", "") or "",
        "input_schema": _tool_schema(tool),
    }


def _tool_schema(tool: Any) -> dict[str, Any]:
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None)
    if isinstance(schema, dict) and schema.get("type") == "object":
        return schema
    return {"type": "object", "properties": {}, "required": []}


def _response_message(response: Any) -> dict[str, Any]:
    if isinstance(response, dict):
        return response.get("message") or {}
    message = getattr(response, "message", None)
    if isinstance(message, dict):
        return message
    if message is None:
        return {}
    return {
        "role": getattr(message, "role", "assistant") or "assistant",
        "content": getattr(message, "content", "") or "",
        "tool_calls": getattr(message, "tool_calls", None) or [],
    }


def _message_tool_calls(message: dict[str, Any]) -> list[Any]:
    if isinstance(message, dict):
        return message.get("tool_calls") or []
    return getattr(message, "tool_calls", None) or []


def _message_content(message: dict[str, Any]) -> str:
    if isinstance(message, dict):
        return message.get("content") or ""
    return getattr(message, "content", None) or ""


def _known_tool_names(ollama_tools: list[dict[str, Any]]) -> set[str]:
    names = set()
    for tool in ollama_tools:
        function = tool.get("function") if isinstance(tool, dict) else None
        if isinstance(function, dict) and function.get("name"):
            names.add(function["name"])
    return names


def _tool_calls_from_content(content: str, known_tool_names: set[str]) -> list[dict[str, Any]]:
    if not content:
        return []

    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`").strip()
        if text.lower().startswith("json"):
            text = text[4:].strip()

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []

    if not isinstance(payload, dict):
        return []

    if isinstance(payload.get("function"), dict):
        name = payload["function"].get("name", "")
        args = payload["function"].get("arguments") or {}
    else:
        name = payload.get("name") or payload.get("tool") or ""
        args = payload.get("arguments") or payload.get("args") or payload.get("params") or {}

    if name not in known_tool_names:
        return []
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    if not isinstance(args, dict):
        args = {}

    return [{"function": {"name": name, "arguments": args}}]


def _tool_call_name_args(tool_call: Any) -> tuple[str, dict[str, Any]]:
    function = tool_call.get("function", {}) if isinstance(tool_call, dict) else getattr(tool_call, "function", {})
    if isinstance(function, dict):
        name = function.get("name", "")
        args = function.get("arguments") or {}
    else:
        name = getattr(function, "name", "")
        args = getattr(function, "arguments", {}) or {}

    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    if not isinstance(args, dict):
        args = {}
    return name, args


def _normalize_tool_args(tool_args: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in tool_args.items():
        if value is None:
            continue
        if value == {} and key in {"namespace", "token", "provider", "mount_path"}:
            continue
        if key in {"vault_addr", "target"} and isinstance(value, str):
            value = _normalize_vault_base_url(value)
        normalized[key] = value
    return normalized


def _normalize_vault_base_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if not parsed.scheme or not parsed.netloc:
        return value
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _direct_token_chain_request(user_input: str, fallback_vault_addr: str | None = None) -> dict[str, str] | None:
    lowered = user_input.lower()
    active_markers = (
        "saldiri",
        "saldiri",
        "zincir",
        "aktif",
        "calistir",
        "calistir",
        "tokenla mumkun",
        "tokenla mumkun",
        "dusuk yetkili token",
        "token var",
        "token bu",
    )
    if not any(marker in lowered for marker in active_markers):
        return None

    vault_addr = _extract_vault_addr_from_text(user_input) or fallback_vault_addr
    token = _extract_vault_token_from_text(user_input)
    if not vault_addr or not token:
        return None

    return {"vault_addr": vault_addr, "token": token}


def _extract_vault_addr_from_text(text: str) -> str | None:
    match = re.search(r"https?://[^\s,;]+", text)
    if not match:
        return None
    return _normalize_vault_base_url(match.group(0).rstrip("."))


def _extract_vault_token_from_text(text: str) -> str | None:
    match = re.search(r"hvs\.", text)
    if not match:
        return None

    token = "hvs."
    index = match.end()
    while index < len(text):
        char = text[index]
        if re.match(r"[A-Za-z0-9_-]", char):
            token += char
            index += 1
            continue
        if char.isspace():
            next_match = re.match(r"\s+([A-Za-z0-9_-]+)", text[index:])
            if not next_match:
                break
            next_chunk = next_match.group(1)
            if len(next_chunk) == 1 and len(token) > 80:
                token += next_chunk
                index += len(next_match.group(0))
                continue
            if len(next_chunk) >= 8:
                index += len(next_match.group(0)) - len(next_chunk)
                continue
            break
        break

    return token if len(token) > 20 else None


def _direct_captured_token_follow_up(user_input: str, messages: list[dict[str, Any]]) -> dict[str, str] | None:
    lowered = user_input.lower()
    markers = (
        "yeni token",
        "ele gecen token",
        "yukseltilmis token",
        "devam",
        "ilerleyim",
        "ilerleyelim",
    )
    if not any(marker in lowered for marker in markers):
        return None

    vault_addr = _last_vault_addr_from_messages(messages)
    token = _last_vault_token_from_messages(messages)
    if not vault_addr or not token:
        return None
    return {"vault_addr": vault_addr, "token": token}


def _last_vault_token_from_messages(messages: list[dict[str, Any]]) -> str | None:
    for message in reversed(messages):
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            continue
        tokens = _extract_all_vault_tokens_from_text(content)
        if tokens:
            return tokens[-1]
    return None


def _extract_all_vault_tokens_from_text(text: str) -> list[str]:
    tokens = []
    start = 0
    while True:
        match = re.search(r"hvs\.", text[start:])
        if not match:
            break
        absolute_start = start + match.start()
        token = _extract_vault_token_from_text(text[absolute_start:])
        if token:
            tokens.append(token)
        start = absolute_start + 4
    return tokens


def _last_vault_addr_from_messages(messages: list[dict[str, Any]]) -> str | None:
    for message in reversed(messages):
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            continue
        vault_addr = _extract_vault_addr_from_text(content)
        if vault_addr:
            return vault_addr
    return None


def _looks_like_mcp_connect_error(error: BaseException) -> bool:
    text = str(error)
    if "All connection attempts failed" in text or "ConnectError" in text:
        return True
    for nested in getattr(error, "exceptions", []) or []:
        if _looks_like_mcp_connect_error(nested):
            return True
    return False


def _tool_timeout_seconds() -> int:
    raw_value = os.getenv("MCP_TOOL_TIMEOUT_SECONDS")
    if not raw_value:
        return DEFAULT_TOOL_TIMEOUT_SECONDS
    try:
        parsed = int(raw_value)
    except ValueError:
        return DEFAULT_TOOL_TIMEOUT_SECONDS
    return max(5, parsed)


async def _maybe_retry_recon_with_certificate_domain(
    session: ClientSession,
    tool_name: str,
    tool_args: dict[str, Any],
    result_text: str,
) -> str:
    if tool_name != "run_unauthenticated_recon":
        return result_text

    original_target = tool_args.get("vault_addr")
    retry_target = _domain_retry_target_from_result(original_target, result_text)
    if not retry_target:
        return result_text

    try:
        timeout_seconds = _tool_timeout_seconds()
        retry_result = await asyncio.wait_for(
            session.call_tool(tool_name, arguments={"vault_addr": retry_target}),
            timeout=timeout_seconds,
        )
        retry_text = _tool_result_text(retry_result)
    except asyncio.TimeoutError:
        retry_text = json.dumps(
            {
                "status": "error",
                "target": retry_target,
                "message": f"Domain retry timed out after {_tool_timeout_seconds()} seconds.",
            },
            ensure_ascii=False,
        )
    except Exception as error:
        retry_text = json.dumps(
            {"status": "error", "target": retry_target, "message": str(error)},
            ensure_ascii=False,
        )

    return _merge_recon_retry_results(result_text, retry_text, original_target, retry_target)


def _domain_retry_target_from_result(original_target: str | None, result_text: str) -> str | None:
    if not original_target:
        return None

    parsed = urlsplit(original_target)
    host = parsed.hostname
    if not host or not _is_ip_address(host):
        return None

    domain = _certificate_domain_from_result(result_text)
    if not domain:
        return None

    port = f":{parsed.port}" if parsed.port else ""
    scheme = parsed.scheme or "https"
    return f"{scheme}://{domain}{port}"


def _certificate_domain_from_result(result_text: str) -> str | None:
    try:
        payload = json.loads(result_text)
    except json.JSONDecodeError:
        return None

    findings = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(findings, list):
        return None

    candidates = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        evidence = finding.get("evidence")
        if not evidence:
            continue
        evidence_text = evidence if isinstance(evidence, str) else json.dumps(evidence, ensure_ascii=False)
        candidates.extend(_extract_certificate_domains(evidence_text))

    for candidate in candidates:
        if candidate and not _is_ip_address(candidate):
            return candidate
    return None


def _extract_certificate_domains(evidence_text: str) -> list[str]:
    domains = []
    for marker in ("DNS:", "commonName="):
        start = 0
        while True:
            index = evidence_text.find(marker, start)
            if index == -1:
                break
            value_start = index + len(marker)
            value_end = value_start
            while value_end < len(evidence_text) and evidence_text[value_end] not in {",", ";", "/", " "}:
                value_end += 1
            domain = evidence_text[value_start:value_end].strip().lower()
            if domain.startswith("*."):
                domain = domain[2:]
            if _looks_like_domain(domain) and domain not in domains:
                domains.append(domain)
            start = value_end + 1
    return domains


def _looks_like_domain(value: str) -> bool:
    if not value or "." not in value or "@" in value:
        return False
    return all(part for part in value.split("."))


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _merge_recon_retry_results(
    first_text: str,
    retry_text: str,
    original_target: str | None,
    retry_target: str,
) -> str:
    try:
        first_payload = json.loads(first_text)
    except json.JSONDecodeError:
        first_payload = {"status": "unknown", "raw": first_text}
    try:
        retry_payload = json.loads(retry_text)
    except json.JSONDecodeError:
        retry_payload = {"status": "unknown", "raw": retry_text}

    first_findings = first_payload.get("findings", []) if isinstance(first_payload, dict) else []
    retry_findings = retry_payload.get("findings", []) if isinstance(retry_payload, dict) else []
    findings = []
    if isinstance(first_findings, list):
        findings.extend(first_findings)
    if isinstance(retry_findings, list):
        findings.extend(retry_findings)

    return json.dumps(
        {
            "status": retry_payload.get("status", "completed") if isinstance(retry_payload, dict) else "completed",
            "target": retry_target,
            "original_target": original_target,
            "auto_follow_up": (
                "Initial target was an IP address. TLS certificate evidence exposed a DNS name, "
                "so passive recon was automatically repeated against that domain."
            ),
            "first_result_summary": {
                "target": original_target,
                "findings_count": len(first_findings) if isinstance(first_findings, list) else None,
            },
            "retry_result_summary": {
                "target": retry_target,
                "findings_count": len(retry_findings) if isinstance(retry_findings, list) else None,
                "message": retry_payload.get("message") if isinstance(retry_payload, dict) else None,
            },
            "findings_count": len(findings),
            "findings": findings,
        },
        ensure_ascii=False,
    )


async def _ai_tool_analysis(
    model: str,
    messages: list[dict[str, Any]],
    tool_name: str,
    result_text: str,
) -> str:
    analysis_prompt = (
        "Son tool sonucunu bir pentest operator asistani gibi yorumla. "
        "Ham JSON tekrar etme. Bulgulari kanita dayali ozetle, mevcut senaryoda "
        "ne anlama geldigini acikla ve token yoksa aktif/token gerektiren adim "
        "onermeden en mantikli sonraki adimi soyle. Kisa ama faydali cevap ver.\n\n"
        f"Tool: {tool_name}\n"
        f"Sonuc:\n{_truncate_text(result_text, MAX_TOOL_RESULT_FOR_ANALYSIS)}"
    )
    analysis_messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        *[
            {"role": item.get("role", "user"), "content": item.get("content", "")}
            for item in messages[-6:]
            if item.get("role") in {"user", "assistant"}
        ],
        {"role": "user", "content": analysis_prompt},
    ]

    try:
        response = await asyncio.to_thread(
            ollama.chat,
            model=model,
            messages=analysis_messages,
            options={"num_predict": 450},
        )
    except Exception as error:
        print(f"\n[!] AI analiz uretilemedi: {error}\n")
        return

    response_message = _response_message(response)
    content = _message_content(response_message).strip()
    if content:
        print(f"\n[AI Analiz]: {content}\n")


async def _ai_tool_analysis(
    model: str,
    messages: list[dict[str, Any]],
    tool_name: str,
    result_text: str,
) -> str:
    analysis_prompt = (
        "Son arac sonucunu kullanarak kullaniciya dogrudan sohbet cevabi ver. "
        "Ham JSON, endpoint listesi, debug satiri, tool adi veya HTTP logu tekrar etme. "
        "Pentestte ise yarayacak kanitlari kisa ve net soyle. "
        "Yanlis veya uydurma hedef yazma; sadece verilen sonucu kullan. "
        "Token yoksa token gerektiren aktif adim onermeden mantikli sonraki adimi belirt. "
        "Sadece Turkce cevap ver; Ingilizce veya baska dil kullanma. "
        "Cevabin 2-4 kisa paragraf olsun, gerekirse en fazla 3 madde kullan.\n\n"
        f"Tool: {tool_name}\n"
        f"Sonuc ozeti:\n{_analysis_context_from_result(result_text)}"
    )
    analysis_messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        *[
            {"role": item.get("role", "user"), "content": item.get("content", "")}
            for item in messages[-6:]
            if item.get("role") in {"user", "assistant"}
        ],
        {"role": "user", "content": analysis_prompt},
    ]

    try:
        response = await asyncio.to_thread(
            ollama.chat,
            model=model,
            messages=analysis_messages,
            options={"num_predict": 450},
        )
    except Exception as error:
        return f"AI analiz uretilemedi: {error}"

    response_message = _response_message(response)
    content = _strip_chat_noise(_message_content(response_message).strip())
    if not content or _contains_cjk(content) or _mentions_internal_tool(content):
        return _fallback_analysis_from_result(result_text)
    return content


def _analysis_context_from_result(result_text: str) -> str:
    try:
        payload = json.loads(result_text)
    except json.JSONDecodeError:
        return _truncate_text(result_text, MAX_TOOL_RESULT_FOR_ANALYSIS)

    if not isinstance(payload, dict):
        return _truncate_text(result_text, MAX_TOOL_RESULT_FOR_ANALYSIS)

    lines = []
    for key, label in (
        ("status", "Durum"),
        ("target", "Hedef"),
        ("original_target", "Ilk hedef"),
        ("auto_follow_up", "Otomatik takip"),
        ("path", "Yol"),
        ("findings_count", "Bulgu sayisi"),
        ("message", "Mesaj"),
    ):
        if key in payload:
            lines.append(f"{label}: {payload[key]}")

    findings = payload.get("findings")
    if isinstance(findings, list) and findings:
        severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "PASS": 0}
        prioritized = sorted(
            [finding for finding in findings if isinstance(finding, dict)],
            key=lambda item: severity_order.get(str(item.get("severity", "INFO")), 1),
            reverse=True,
        )
        lines.append("Onemli bulgular:")
        for finding in prioritized[:6]:
            title = finding.get("title", "Untitled finding")
            severity = finding.get("severity", "INFO")
            module = finding.get("module", "")
            evidence = finding.get("evidence")
            if isinstance(evidence, str):
                evidence_text = evidence[:220]
            elif evidence:
                evidence_text = json.dumps(evidence, ensure_ascii=False)[:220]
            else:
                evidence_text = ""
            detail = f"- {severity}: {title}"
            if module:
                detail += f" ({module})"
            if evidence_text:
                detail += f" | Kanit: {evidence_text}"
            lines.append(detail)

    return _truncate_text("\n".join(lines) or result_text, MAX_TOOL_RESULT_FOR_ANALYSIS)


def _contains_cjk(content: str) -> bool:
    return any("\u4e00" <= char <= "\u9fff" for char in content)


def _mentions_internal_tool(content: str) -> bool:
    return "run_" in content or "get_findings" in content or "get_risk_score" in content


def _fallback_analysis_from_result(result_text: str) -> str:
    try:
        payload = json.loads(result_text)
    except json.JSONDecodeError:
        return _truncate_text(result_text, 900)

    if not isinstance(payload, dict):
        return _truncate_text(result_text, 900)

    target = payload.get("target") or payload.get("path") or "hedef"
    original_target = payload.get("original_target")
    auto_follow_up = payload.get("auto_follow_up")
    findings = [finding for finding in payload.get("findings", []) if isinstance(finding, dict)]
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "PASS": 0}
    actionable = sorted(
        [finding for finding in findings if finding.get("severity") != "PASS"],
        key=lambda item: severity_order.get(str(item.get("severity", "INFO")), 1),
        reverse=True,
    )

    if not actionable:
        return (
            f"{target} icin pasif kesifte kritik bir bulgu cikmadi. "
            "Token olmadigi icin simdilik aktif veya authenticated adimlara gecmek dogru olmaz. "
            "Bir sonraki mantikli adim, hedefe ait repo/log/artifact varsa credential hijack taramasi yapmak."
        )

    top = actionable[0]
    title = top.get("title", "bulgu")
    severity = top.get("severity", "INFO")
    evidence = top.get("evidence")
    if isinstance(evidence, dict):
        evidence_text = json.dumps(evidence, ensure_ascii=False)[:240]
    else:
        evidence_text = str(evidence or "")[:240]

    extra_titles = [
        f"{finding.get('severity', 'INFO')}: {finding.get('title', 'bulgu')}"
        for finding in actionable[1:4]
    ]
    extra = ""
    if extra_titles:
        extra = " Diger dikkate deger sinyaller: " + "; ".join(extra_titles) + "."

    evidence_sentence = f" Kanit: {evidence_text}." if evidence_text else ""
    follow_up_sentence = ""
    if original_target and auto_follow_up:
        follow_up_sentence = (
            f" Ilk hedef {original_target} IP/adresiydi; sertifika kanitindan domain ipucu cikarilip "
            f"tarama otomatik olarak {target} uzerinden tekrarlandi."
        )

    return (
        f"{target} icin pasif kesif tamamlandi.{follow_up_sentence} "
        f"En onemli sinyal {severity} seviyesinde: {title}."
        f"{evidence_sentence}{extra}\n\n"
        "Su an token olmadigi icin secret okuma, capability audit veya yetki yukseltme gibi authenticated "
        "adimlara gecmemeliyiz. Pentest acisindan en mantikli sonraki adim, hedefe dogru hostname/domain "
        "ile tekrar ulasmayi denemek ve paralelde repo, log veya CI artifact icinde Vault token/AppRole "
        "izi aramak."
    )


def _deterministic_tool_answer(tool_name: str, result_text: str) -> str | None:
    if tool_name == "run_unauthenticated_recon":
        return _recon_operator_answer(result_text)
    if tool_name == "run_capability_audit":
        return _capability_operator_answer(result_text)
    return None


def _capability_operator_answer(result_text: str) -> str:
    try:
        payload = json.loads(result_text)
    except json.JSONDecodeError:
        return _truncate_text(result_text, 900)

    if not isinstance(payload, dict):
        return _truncate_text(result_text, 900)

    findings = [finding for finding in payload.get("findings", []) if isinstance(finding, dict)]
    target = payload.get("target") or "hedef"
    failure = next(
        (
            finding
            for finding in findings
            if "capability audit failed" in str(finding.get("title", "")).lower()
        ),
        None,
    )
    if failure:
        evidence = _finding_evidence_text(failure)
        if "permission denied" in evidence.lower():
            return (
                "Token girdisi alindi, ama bu token `sys/capabilities-self` endpoint'ini sorgulamaya yetmedi. "
                "Bu token yok demek degil; token ya yanlis/eksik kopyalanmis, suresi dolmus, namespace farkli, "
                "ya da policy tarafinda capability audit izni verilmemis demek.\n\n"
                "Labda ilerlemek icin once ayni tokeni dogrulamaliyiz: `vault token lookup` basarili olmali ve "
                "`sys/capabilities-self` icin `update` izni gorunmeli. Dogru tokenla tekrar calistiginda arac "
                "hangi Vault yollarinda `read`, `create`, `update` veya `sudo` oldugunu cikarip zinciri oradan "
                "ilerletebilir."
            )
        return (
            "Tokenli capability audit calisti ama Vault tarafindan tamamlanamadi. "
            f"Kanita gore hata su: {_shorten_evidence(evidence)}. Bu asamada token yok varsaymak yerine "
            "tokenin gecerliligini, namespace'i ve hedef adresini dogrulamak gerekiyor."
        )

    critical = []
    write_like = []
    readable = []
    for finding in findings:
        evidence = _finding_evidence_text(finding)
        path = _extract_value(evidence, "path")
        capabilities = _extract_evidence_field(evidence, "capabilities")
        title = str(finding.get("title", "")).lower()
        record = (path, capabilities)
        if "sudo capability" in title:
            critical.append(record)
        elif "write capability" in title or "over-privileged" in title:
            write_like.append(record)
        elif capabilities and "read" in capabilities:
            readable.append(record)

    if critical or write_like:
        focus = critical[0] if critical else write_like[0]
        path, capabilities = focus
        path_text = f"`{path}`" if path else "kritik bir Vault yolu"
        cap_text = f" ({capabilities})" if capabilities else ""
        next_step = (
            "Bu lab senaryosunda en mantikli ilerleme, bu yetkiyi kullanarak kontrollu sekilde yeni token "
            "uretme veya mevcut policy kapsaminda KV secret okuma modullerini calistirmak. Ozellikle "
            "`auth/token/create` uzerinde `sudo/create/update` varsa privilege escalation zinciri denenebilir; "
            "`secret/data/...` uzerinde `read` varsa dogrudan secret enumeration tarafina gecilir."
        )
        return (
            f"Token calisiyor ve capability audit anlamli bir ilerleme yolu buldu. En onemli kanit {path_text} "
            f"uzerindeki yetki{cap_text}; bu, tokenin sadece kimlik dogrulamakla kalmadigini, Vault icinde "
            "islem yapabilecek policy haklari tasidigini gosteriyor.\n\n"
            f"{next_step}"
        )

    if readable:
        path, capabilities = readable[0]
        path_text = f"`{path}`" if path else "bir Vault yolu"
        return (
            f"Token gecerliligi dogrulandi ve {path_text} uzerinde okuma yetkisi gorunuyor. "
            "Bu noktada privilege escalation yerine daha dogrudan ilerleme KV secret enumeration ve yetki "
            "kapsami icinde okunabilen secret'lari kanitli sekilde cikarmak olur."
        )

    return (
        f"{target} icin tokenli capability audit tamamlandi, fakat denetlenen yollarda sudo, yazma veya "
        "okuma gibi ilerleme saglayacak net bir yetki gorunmedi. Bu token tamamen ise yaramaz demek degil; "
        "sadece kontrol edilen path listesinde kullanilabilir bir hak yakalanmadi. Daha iyi sonuc icin hedefe "
        "ozel secret path'leri veya auth path'leri denetime eklemek gerekir."
    )


def _capability_result_has_progress_path(result_text: str) -> bool:
    try:
        payload = json.loads(result_text)
    except json.JSONDecodeError:
        return False
    findings = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(findings, list):
        return False
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title", "")).lower()
        evidence = _finding_evidence_text(finding).lower()
        if "capability audit failed" in title:
            return False
        if "sudo capability" in title or "write capability" in title:
            return True
        if "auth/token/create" in evidence and any(cap in evidence for cap in ("sudo", "create", "update")):
            return True
        if "secret/data/" in evidence and "read" in evidence:
            return True
    return False


def _active_chain_operator_answer(
    capability_text: str,
    escalation_text: str,
    exfil_text: str,
) -> str:
    escalation = _json_object(escalation_text)
    exfil = _json_object(exfil_text)

    if escalation.get("status") != "success":
        message = escalation.get("message") or "aktif yetki yukseltme tamamlanamadi"
        return (
            "Capability audit tokenla ilerlenebilir bir path gosterdi, fakat aktif yetki yukseltme adimi basarisiz oldu. "
            f"Vault'un dondurdugu sonuc: {_shorten_evidence(str(message))}. Bu durumda siradaki mantikli hamle, tokenin "
            "gercek policy kapsaminda hangi path'leri okuyabildigini KV enumeration ile sinirli sekilde kanitlamak."
        )

    escalation_evidence = escalation.get("evidence") if isinstance(escalation.get("evidence"), dict) else {}
    selected_policy = escalation_evidence.get("selected_policy")
    added_policies = escalation_evidence.get("added_policies") or []
    policy_text = selected_policy or ", ".join(added_policies) or "yuksek yetkili policy"

    if exfil.get("status") != "success":
        message = exfil.get("message") or "secret okuma tamamlanamadi"
        return (
            f"Zincirin yetki yukseltme kismi basarili: dusuk yetkili token yeni bir token uretip `{policy_text}` "
            f"kapsamina cikabildi. Secret okuma adimi ise tamamlanamadi: {_shorten_evidence(str(message))}. "
            "Bu yine de kritik bir bulgu; cunku token uretme/yetki genisletme kanitlanmis durumda."
        )

    exfil_evidence = exfil.get("evidence") if isinstance(exfil.get("evidence"), dict) else {}
    total_leaked = exfil_evidence.get("total_leaked_secrets", 0)
    leaked_payloads = exfil_evidence.get("leaked_payloads")
    leaked_paths = list(leaked_payloads.keys()) if isinstance(leaked_payloads, dict) else []
    path_text = ", ".join(f"`{path}`" for path in leaked_paths[:4]) or "erisilebilen KV path'leri"
    captured_token = escalation.get("captured_token") or escalation_evidence.get("captured_token")
    token_sentence = (
        " Yeni token ele gecirildi ve sonraki secret okuma adiminda kullanildi."
        if captured_token
        else ""
    )
    outputs = _format_active_chain_outputs(captured_token, leaked_payloads)

    return (
        f"Zincir calisti. Dusuk yetkili token `auth/token/create` uzerinden yeni token uretebildi ve `{policy_text}` "
        f"kapsamina yukseldi.{token_sentence}\n\n"
        f"Ardindan KV tarafinda {total_leaked} secret okunabildi: {path_text}. Bu lab icin net ilerleme kaniti su: "
        "ilk token sadece discovery degil, state-changing token uretimi ve secret okuma zincirine donusebiliyor. "
        "Raporlanacak ana zafiyet, dusuk yetkili tokenin token creation/sudo yetkisiyle privilege escalation'a izin vermesi."
        f"{outputs}\n\n"
        "Buradan sonra ilerleme sirasi net: ele gecen yuksek yetkili tokenla policy audit yapip hangi policy'lerin "
        "asiri genis oldugunu kanitlamak, tum KV mount'larini enumerate etmek, ardindan database/cloud secrets engine "
        "varsa dinamik credential veya cloud key uretilip uretilemedigini kontrol etmek. Bu lab bulgusunda raporun ana "
        "kanit zinciri dusuk token -> admin-policy token -> secret okuma seklinde kurulmali."
    )


def _format_active_chain_outputs(captured_token: str | None, leaked_payloads: Any) -> str:
    lines = []
    if captured_token:
        lines.append(f"Yukseltilmis token: `{captured_token}`")

    if isinstance(leaked_payloads, dict) and leaked_payloads:
        lines.append("Okunan secret ciktilari:")
        for path, payload in leaked_payloads.items():
            if isinstance(payload, dict):
                values = ", ".join(f"{key}={value}" for key, value in payload.items())
            else:
                values = str(payload)
            lines.append(f"{path}: {values}")

    if not lines:
        return ""
    return "\n\n" + "\n".join(lines)


def _captured_token_follow_up_answer(
    policy_text: str,
    kv_text: str,
    database_text: str,
    cloud_text: str,
) -> str:
    policy = _json_object(policy_text)
    kv = _json_object(kv_text)
    database = _json_object(database_text)
    cloud = _json_object(cloud_text)

    policy_line = _policy_audit_summary(policy)
    kv_findings = _findings_from_payload(kv)
    kv_outputs = _kv_enumeration_summary(kv, kv_findings)

    lines = [
        "Yeni tokenla devam ettim. Bu asamada token sadece ele gecirilmis olarak kalmadi; policy ve secret yuzeyinde kullanildi.",
        "",
        policy_line,
    ]

    if kv_outputs:
        lines.extend(kv_outputs)
    else:
        count = kv.get("findings_count", 0)
        lines.append(f"KV enumeration tamamlandi; {count} bulgu dondu ama ekranda gosterecek yeni secret degeri yakalanmadi.")

    lines.append(_credential_module_summary("Database secrets engine", database))
    lines.append(_credential_module_summary("Cloud secrets engine", cloud))
    lines.append("")
    lines.append(
        "Buradan sonraki mantikli ilerleme raporu kanitlamak: zafiyet zincirini dusuk token -> token create/sudo -> "
        "admin-policy token -> secret okuma olarak yazmak, policy audit bulgularindan asiri genis path/capability "
        "kanitlarini eklemek ve labda database/cloud engine profili aciksa ayni tokenla credential uretimini tekrar denemek."
    )
    return "\n".join(line for line in lines if line is not None)


def _policy_audit_summary(payload: dict[str, Any]) -> str:
    policy_count = payload.get("policies_analyzed", 0)
    policy_findings = payload.get("findings_count", 0)
    denied = payload.get("policies_read_denied", 0)
    if policy_count:
        return f"Policy audit sonucu: {policy_count} policy analiz edildi, {policy_findings} policy bulgusu uretildi."
    if denied:
        return (
            f"Policy audit sonucu: token policy listesini gorebildi ama {denied} policy icerigini okuyamadi; "
            f"bu nedenle {policy_findings} sinirli bulgu uretildi."
        )
    return (
        "Policy audit sonucu: tokenla policy icerigi analiz edilemedi. Bu, admin-policy adina ragmen "
        "sys/policies/acl okuma yetkisinin bu lab policy'sinde acik olmadigini gosterir."
    )


def _kv_enumeration_summary(payload: dict[str, Any], findings: list[dict[str, Any]]) -> list[str]:
    skipped = any("skipped" in str(finding.get("title", "")).lower() for finding in findings)
    if skipped:
        return ["KV enumeration sonucu: calismadi; KV baslangic path'i verilmedigi icin modul atlandi."]

    outputs = ["KV enumeration sonucu:"]
    outputs.extend(_format_findings_by_keywords(findings, ("secret", "kv", "path"), limit=5))
    if len(outputs) > 1:
        return outputs

    count = payload.get("findings_count", 0)
    return [f"KV enumeration tamamlandi; {count} bulgu dondu ama ekranda gosterecek yeni secret path'i yakalanmadi."]


def _findings_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = payload.get("findings")
    return [finding for finding in findings if isinstance(finding, dict)] if isinstance(findings, list) else []


def _format_findings_by_keywords(
    findings: list[dict[str, Any]],
    keywords: tuple[str, ...],
    limit: int = 5,
) -> list[str]:
    output = []
    for finding in findings:
        evidence = _finding_evidence_text(finding)
        text = f"{finding.get('title', '')} {evidence}".lower()
        if not any(keyword in text for keyword in keywords):
            continue
        title = finding.get("title", "bulgu")
        severity = finding.get("severity", "INFO")
        detail = _shorten_evidence(evidence)
        output.append(f"- {severity}: {title}" + (f" | {detail}" if detail else ""))
        if len(output) >= limit:
            break
    return output


def _credential_module_summary(label: str, payload: dict[str, Any]) -> str:
    status = payload.get("status", "unknown")
    if status == "success":
        total = payload.get("total_harvested") or payload.get("total_leaked_secrets") or "en az 1"
        high = payload.get("high_privilege_count")
        high_text = f", {high} yuksek yetkili" if high is not None else ""
        return f"{label}: basarili, {total} credential/secret uretildi{high_text}."
    message = str(payload.get("message") or payload.get("summary") or "uygun mount/role bulunamadi")
    return f"{label}: kullanilabilir credential uretilemedi ({_shorten_evidence(message)})."


def _json_object(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {"status": "error", "message": text}
    return payload if isinstance(payload, dict) else {"status": "error", "message": text}


def _recon_operator_answer(result_text: str) -> str:
    try:
        payload = json.loads(result_text)
    except json.JSONDecodeError:
        return _truncate_text(result_text, 900)

    if not isinstance(payload, dict):
        return _truncate_text(result_text, 900)

    target = payload.get("target") or "hedef"
    original_target = payload.get("original_target")
    findings = [finding for finding in payload.get("findings", []) if isinstance(finding, dict)]
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "PASS": 0}
    actionable = sorted(
        [finding for finding in findings if finding.get("severity") != "PASS"],
        key=lambda item: severity_order.get(str(item.get("severity", "INFO")), 1),
        reverse=True,
    )

    intro = f"Verdigin hedef uzerinden erisebildigim pasif kesfi tamamladim."
    if original_target and original_target != target:
        intro += (
            f" Ilk URL IP uzerinden geliyordu; sertifika bilgisinden domain ipucunu cikardim "
            f"ve taramayi otomatik olarak {target} uzerinden de tekrar yaptim."
        )
    else:
        intro += f" Kullanilabilir hedef olarak {target} degerlendirildi."

    if not actionable:
        return (
            f"{intro}\n\n"
            "Token gerektirmeyen pasif yuzeyde raporlanacak anlamli bir zafiyet sinyali yakalayamadim. "
            "Bu, hedefin guvenli oldugu anlamina gelmez; sadece disaridan health, UI, auth surface, header, "
            "fingerprint ve endpoint kontrollerinde kanitlanabilir bir acik bilgi ya da yanlis yapilandirma "
            "gorunmedigi anlamina gelir."
        )

    auth_methods = _auth_methods_from_findings(findings)
    summary_paragraph = " ".join(_summarize_recon_findings(actionable, auth_methods))
    lines = [intro, "", f"Elde ettigim sonuclarin anlami su: {summary_paragraph}"]
    return "\n".join(lines)


def _summarize_recon_findings(findings: list[dict[str, Any]], auth_methods: set[str] | None = None) -> list[str]:
    summaries = []
    seen = set()
    groups = [
        _recon_finding_group(str(finding.get("title", "")), _finding_evidence_text(finding))
        for finding in findings
        if isinstance(finding, dict)
    ]
    for finding in findings:
        title = str(finding.get("title", ""))
        evidence_text = _finding_evidence_text(finding)
        key = _recon_finding_group(title, evidence_text)
        if key == "vault_version_disclosed" and "vault_old_version" in groups:
            continue
        if key in seen:
            continue
        seen.add(key)
        summaries.append(_explain_recon_finding(title, evidence_text, auth_methods or set()))
        if len(summaries) >= 4:
            break
    return summaries


def _finding_evidence_text(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence")
    return evidence if isinstance(evidence, str) else json.dumps(evidence, ensure_ascii=False) if evidence else ""


def _auth_methods_from_findings(findings: list[dict[str, Any]]) -> set[str]:
    methods = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title", ""))
        if title.startswith("Detected auth mount: "):
            methods.add(title.split(":", 1)[1].strip().lower())
            continue
        evidence = _finding_evidence_text(finding).lower()
        match = re.search(r"mount_type:\s*([^,;\s]+)", evidence)
        if match:
            methods.add(match.group(1))
    return methods


def _recon_finding_group(title: str, evidence_text: str) -> str:
    lowered = f"{title} {evidence_text}".lower()
    if "certificate_verify_failed" in lowered or "ip address mismatch" in lowered:
        return "tls_certificate_mismatch"
    if "getaddrinfo failed" in lowered or "nameresolutionerror" in lowered:
        return "dns_resolution_failed"
    if "health endpoint" in lowered:
        return "health_endpoint_unreachable"
    if "served over http" in lowered or "scheme: http" in lowered:
        return "vault_over_http"
    if "below recommended baseline" in lowered:
        return "vault_old_version"
    if "version disclosed" in lowered:
        return "vault_version_disclosed"
    if "cluster name disclosed" in lowered:
        return "vault_cluster_disclosed"
    if "cluster id disclosed" in lowered:
        return "vault_cluster_id_disclosed"
    if "expires soon" in lowered:
        return "tls_expiry"
    if "handshake failed" in lowered:
        return "tls_handshake_failed"
    return title.lower()


def _explain_recon_finding(title: str, evidence_text: str, auth_methods: set[str] | None = None) -> str:
    lowered = f"{title} {evidence_text}".lower()
    host = _extract_host_from_evidence(evidence_text)
    auth_methods = auth_methods or set()

    if "certificate_verify_failed" in lowered or "ip address mismatch" in lowered:
        target_text = f" `{host}`" if host else ""
        return (
            f"TLS dogrulamasi{target_text} icin basarisiz oldu; sertifika IP adresine degil farkli bir "
            "hostname'e ait gorunuyor. Bu yuzden Vault endpoint'lerine yapilan pasif isteklerin bir kismi "
            "sertifika kontrolunde kesiliyor."
        )

    if "getaddrinfo failed" in lowered or "nameresolutionerror" in lowered:
        target_text = f" `{host}`" if host else " hedef hostname"
        return (
            f"DNS cozumlemesi{target_text} icin basarisiz oldu; bu isim su an bulundugumuz ortamdan "
            "cozulemiyor. Bu, hedefin ic ag/VPN arkasinda olabilecegini veya DNS kaydinin disariya acik "
            "olmadigini gosterir."
        )

    if "health endpoint" in lowered:
        return (
            "Vault health endpoint'inden dogrulanabilir yanit alinamadi. Token gerektirmeyen saglik bilgisi "
            "sizmiyor olabilir veya erisim TLS/DNS katmaninda engelleniyor."
        )

    if "served over http" in lowered or "scheme: http" in lowered:
        return (
            "Vault servisi HTTP uzerinden cevap veriyor; bu, token veya Secret ID gibi hassas degerler kullanilirsa "
            "trafigin sifrelenmeden tasinabilecegi anlamina gelir. Token yokken bunu somuremem, ama hedefin TLS "
            "zorlamasi yapmadigini kanitlamis oldum."
        )

    if "below recommended baseline" in lowered:
        version = _extract_value(evidence_text, "version")
        minimum = _extract_value(evidence_text, "minimum_recommended_version")
        version_text = f" {version}" if version else ""
        minimum_text = f"; aractaki referans esik {minimum}" if minimum else ""
        cve_text = _local_cve_assessment(version, auth_methods)
        return (
            f"Vault surumu{version_text} guncel kabul edilen tabanin altinda gorunuyor{minimum_text}. "
            f"{cve_text}"
        )

    if "version disclosed" in lowered:
        version = _extract_value(evidence_text, "version")
        version_text = f" ({version})" if version else ""
        cve_text = _local_cve_assessment(version, auth_methods)
        return (
            f"Hedef Vault surum bilgisini disariya sizdiriyor{version_text}. Bu bilgi saldiri yuzeyini daraltir; "
            f"{cve_text}"
        )

    if "cluster name disclosed" in lowered:
        cluster_name = _extract_value(evidence_text, "cluster_name")
        cluster_text = f" `{cluster_name}`" if cluster_name else ""
        return (
            f"Vault cluster adi{cluster_text} unauthenticated taraftan gorulebiliyor. Bu dogrudan erisim saglamaz, "
            "ama ortam/topoloji bilgisi verdigi icin hedef ayrimi, raporlama ve artifact korelasyonu acisindan "
            "ise yarayan bir kesif verisidir."
        )

    if "cluster id disclosed" in lowered:
        cluster_id = _extract_value(evidence_text, "cluster_id")
        cluster_text = f" `{cluster_id}`" if cluster_id else ""
        return (
            f"Vault cluster ID{cluster_text} unauthenticated taraftan gorulebiliyor. Bu tek basina sizma saglamaz, "
            "ama ayni cluster'a ait farkli endpoint/artifact bulgularini eslestirmek ve hedef ortami takip etmek "
            "icin kullanilabilecek bir tanimlayicidir."
        )

    if "expires soon" in lowered:
        days = _extract_days_remaining(evidence_text)
        suffix = f" Yaklasik {days} gun kalmis." if days else ""
        return f"TLS sertifikasinin suresi yakinda doluyor.{suffix} Bu dogrudan sizma degil ama hedef altyapi hijyeni icin anlamli bir sinyal."

    if "handshake failed" in lowered:
        return (
            "TLS handshake tamamlanamadi. Bu genelde yanlis hostname, kapali/filtreli servis veya sertifika "
            "sunumundaki uyumsuzluk nedeniyle olur; bu yuzden pasif kesif yuzeyi sinirli kaldi."
        )

    return f"{title}: {_shorten_evidence(evidence_text)}" if evidence_text else title


def _extract_host_from_evidence(evidence_text: str) -> str | None:
    match = re.search(r"host='([^']+)'", evidence_text)
    if match:
        return match.group(1)
    match = re.search(r"HTTPSConnectionPool\(host='([^']+)'", evidence_text)
    if match:
        return match.group(1)
    return None


def _local_cve_assessment(version: str | None, auth_methods: set[str] | None = None) -> str:
    if not version:
        return (
            "Surum degeri net olmadigi icin yerel CVE eslestirmesi yapamadim; bu durumda sadece surum ifsasini "
            "kesif verisi olarak kullanabiliyorum."
        )

    auth_methods = auth_methods or set()
    matches = match_vault_version_cves(version, add_findings=False)
    if not matches:
        return (
            "Yerel advisory tablomda bu surum icin dogrudan CVE eslesmesi cikmadi; bu yuzden sadece surum ifsasi "
            "ve yapilandirma kontrolleri uzerinden ilerlenebilir, dogrulanmis somurulebilirlik kaniti yok."
        )

    details = []
    for match in matches:
        cve_id = match["cve_id"]
        if cve_id == "CVE-2024-2048":
            if "cert" in auth_methods:
                details.append(
                    "CVE-2024-2048 bu hedef icin oncelikli dogrulama hatti: surum araligi etkileniyor ve cert auth "
                    "mount'u disaridan gorulebiliyor. Yetkili testte odak, cert auth'in non-CA sertifikayi gercekten "
                    "reddedip reddetmedigini kanitlamak olmali; bu kosul saglanmadan somurulebilirlik var diyemem."
                )
            else:
                details.append(
                    "CVE-2024-2048 surum araligina gore aday gorunuyor, fakat bu bulguda cert auth mount'u tespit "
                    "edilmedi. Bu yuzden su an hedefe uygulanabilirligi kanitlanmis degil."
                )
        elif cve_id == "CVE-2023-6337":
            details.append(
                "CVE-2023-6337 surum araligina gore aday, ancak bu bir bellek tuketimi/DoS sinifi risk. Yetkili "
                "lab disinda aktif olarak zorlanmamali; su an raporlanabilir risk olarak tutulur, sizma ilerleme "
                "yolu olarak kullanilmaz."
            )
        else:
            details.append(
                f"{cve_id} ({match['severity']}) surum araligina gore aday. Somurulebilirlik, ilgili konfigurasyonun "
                "hedefte acik olmasina bagli."
            )
    return " ".join(details)


def _extract_days_remaining(evidence_text: str) -> str | None:
    match = re.search(r"days_remaining:\s*(-C\d+)", evidence_text)
    return match.group(1) if match else None


def _extract_value(evidence_text: str, key: str) -> str | None:
    match = re.search(rf"{re.escape(key)}:\s*([^,;\s]+)", evidence_text)
    return match.group(1) if match else None


def _extract_evidence_field(evidence_text: str, key: str) -> str | None:
    match = re.search(rf"{re.escape(key)}:\s*([^;]+)", evidence_text)
    return match.group(1).strip() if match else None


def _shorten_evidence(evidence_text: str) -> str:
    cleaned = " ".join(evidence_text.split())
    return cleaned[:180] + ("..." if len(cleaned) > 180 else "")


def _strip_chat_noise(content: str) -> str:
    lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith(("[AI", "[Sonuc", "HTTP Request:", "```json", "```")):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _compact_tool_preview(result_text: str) -> str:
    try:
        payload = json.loads(result_text)
    except json.JSONDecodeError:
        return _truncate_text(result_text, MAX_TOOL_RESULT_PREVIEW)

    if not isinstance(payload, dict):
        return _truncate_text(result_text, MAX_TOOL_RESULT_PREVIEW)

    compact = {
        key: payload.get(key)
        for key in ("status", "target", "path", "findings_count", "total", "risk_score", "risk_grade", "message")
        if key in payload
    }
    findings = payload.get("findings")
    if isinstance(findings, list):
        compact["top_findings"] = [
            {
                "severity": finding.get("severity"),
                "title": finding.get("title"),
                "module": finding.get("module"),
            }
            for finding in findings[:5]
            if isinstance(finding, dict)
        ]
    return _truncate_text(json.dumps(compact or payload, ensure_ascii=False), MAX_TOOL_RESULT_PREVIEW)


def _truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + " [...]"


def _verbose_chat() -> bool:
    return os.getenv("VAULT_AI_VERBOSE", "").strip().lower() in {"1", "true", "yes", "on"}


def _configure_quiet_logging() -> None:
    if _verbose_chat():
        return
    for logger_name in ("httpx", "httpcore", "mcp", "ollama"):
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def _tool_result_text(tool_result: Any) -> str:
    texts = []
    for item in getattr(tool_result, "content", []) or []:
        text = getattr(item, "text", None)
        if text:
            texts.append(text)
    return "\n".join(texts) if texts else str(tool_result)


if __name__ == "__main__":
    start_chat_session()
