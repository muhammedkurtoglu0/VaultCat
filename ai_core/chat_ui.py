"""Interactive AI pentest chat — powered by the autonomous agent.

Connects the LLM agent to real MCP tool execution and provides a
terminal-based chat interface.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Optional

try:
    import readline  # noqa: F401
except ImportError:
    try:
        import pyreadline3 as readline  # noqa: F401
    except ImportError:
        pass

from ai_core.agent import PentestAgent
from ai_core.dynamic_session import global_store
from ai_core.llm_engine import LLMClient, detect_provider
from ai_core.memory import Memory
from ai_core.models import get_models, get_default_model, list_providers, get_provider_name
from ai_core.tools import ALL_TOOLS


def _extract_target_url(text: str) -> str | None:
    """Extract a Vault target URL from natural-language user input.

    Returns a normalized ``scheme://host:port`` string if the text
    contains an HTTP(S) URL pointing to a Vault-like port (8200, 8201)
    or a path that looks like a Vault UI, otherwise ``None``.
    """
    import re
    from urllib.parse import urlparse, urlunparse

    # Match http:// or https:// URLs
    for match in re.finditer(r"https?://[^\s]+", text):
        raw = match.group(0).rstrip(".,;:)")
        try:
            p = urlparse(raw)
        except Exception:
            continue
        if not p.hostname:
            continue
        # Accept if port is 8200/8201, or path looks Vault-related,
        # or the user explicitly said "hedef" / "target" nearby.
        is_vault_port = p.port in (8200, 8201)
        is_vault_path = any(
            seg in (p.path or "")
            for seg in ("/ui/vault", "/v1/sys", "/v1/auth")
        )
        is_target_keyword = any(
            kw in text.lower()
            for kw in ("hedef", "target", "yeni hedef", "new target")
        )
        if is_vault_port or is_vault_path or is_target_keyword:
            return urlunparse((p.scheme, p.netloc, "", "", "", ""))
        # Fallback: any https:// URL on port 443 with Vault TLD might be legit
        if p.scheme == "https" and not p.port:
            # User gave https://IP — likely Vault UI
            if is_target_keyword:
                return urlunparse((p.scheme, p.netloc, "", "", "", ""))

    return None


class ChatUI:
    """Terminal chat interface for the AI pentest agent."""

    def __init__(
        self,
        vault_addr: str | None = None,
        token: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        auto: bool = False,
        pdf_report: str | None = None,
        hijack_path: str | None = None,
        auto_max_risk: str = "read_only",
        auto_max_turns: int = 30,
        disable_web: bool = False,
        auto_pilot: bool = False,
        interval: int | None = None,
    ):
        self.vault_addr = vault_addr
        self.token = token
        self.disable_web = disable_web
        self.auto_pilot = auto_pilot
        # Track whether provider/model were explicitly passed (vs auto-detected)
        self._provider_explicit = provider is not None
        self._model_explicit = model is not None
        self.provider = provider or detect_provider()
        self.model = model or get_default_model(self.provider)
        self.memory = Memory()

        # Dynamic credential store — the global singleton shared with the
        # agent, tree walker, and active execution engine so tokens
        # discovered anywhere are visible everywhere.
        self.session = global_store
        if token:
            self.session.add_user_token(token)

        self.agent = PentestAgent(
            vault_addr=vault_addr,
            token=token,
            provider=self.provider,
            model=self.model,
            disable_web=self.disable_web,
            auto_pilot=self.auto_pilot,
        )
        self.agent.set_tool_executor(self._execute_tool)

        # Shared tool executor (token injection, MCP routing, credential parse)
        from ai_core.tool_executor import ToolExecutor
        self.tool_executor = ToolExecutor(vault_addr, token, self.session, self.memory)
        self.tool_executor.on_discovery = self._on_credential_discovery

        self.running = True

        # Auto mode config
        self.auto = auto
        self.pdf_report = pdf_report
        self.hijack_path = hijack_path
        self.auto_max_risk = auto_max_risk
        self.auto_max_turns = auto_max_turns
        self.interval = interval  # continuous cron-like mode (seconds)

        if vault_addr:
            self.memory.set_context("vault_addr", vault_addr)
        if token:
            self.memory.set_context("token", token)

    # ── public entry point ──────────────────────────────────────────────

    def start(self):
        """Main entry point — interactive or auto mode."""
        if self.auto:
            self._start_auto()
            return

        # ── Interactive provider/model selection (when not passed via CLI) ──
        if not self._provider_explicit or not self._model_explicit:
            self._select_provider_and_model()

        # ── Verify LLM is actually usable before entering chat loop ─────
        self._verify_llm_ready()

        print("\n" + "=" * 60)
        print("  VAULT AI PENTEST AGENT")
        print("=" * 60)
        print(f"\n  Provider : {self.provider}")
        print(f"  Model    : {self.agent.llm.model}")
        print(f"  Target   : {self.vault_addr or 'set target <url>'}")
        print(f"  Token    : {self.token or 'none'}")
        print(f"  Tools    : {len(ALL_TOOLS)} available")
        print("\n  The agent decides WHAT to do, WHEN, and WHY.")
        print("  Just tell it your objective — it handles everything.")
        print("  Commands: help, modules, findings, status, auto, pilot, walk, orchestrate, smart, mutate, fix, set, exit")
        print("=" * 60 + "\n")

        while self.running:
            try:
                user_input = input("\n🔓 YOU: ").strip()
                if not user_input:
                    continue

                self.memory.add_conversation("user", user_input)

                cmd = user_input.lower()

                if cmd in ("exit", "quit", "q"):
                    print("\n[AGENT] Shutting down. Goodbye!")
                    break

                if cmd in ("help", "yardım", "?"):
                    self._show_help()
                    continue

                if cmd in ("modules", "modüller", "ls"):
                    self._show_tools()
                    continue

                if cmd == "findings":
                    self._show_findings()
                    continue

                if cmd == "status":
                    self._show_status()
                    continue

                if cmd in ("auto", "otomatik"):
                    self._start_auto_from_chat()
                    continue

                if cmd in ("pilot", "auto-pilot", "otopilot"):
                    self.agent._auto_pilot = not getattr(self.agent, '_auto_pilot', False)
                    state = "ON" if self.agent._auto_pilot else "OFF"
                    print(f"\n  Auto-Pilot mode: {state}")
                    print(f"  {'Web PoC chains will auto-execute without asking.' if self.agent._auto_pilot else 'PoCs will be suggested, not auto-executed.'}")
                    continue

                if cmd in ("stealth", "gizli"):
                    from reconnaissance.stealth_http import enable_stealth, disable_stealth, is_stealth_enabled
                    if is_stealth_enabled():
                        disable_stealth()
                        print("\n  Stealth HTTP: OFF (fast direct requests)")
                    else:
                        enable_stealth()
                        print("\n  Stealth HTTP: ON (jitter 1-5s, backoff, rate-limit evasion)")
                    continue

                if cmd in ("mutate", "mutasyon", "branch"):
                    self._show_mutation()
                    continue

                if cmd in ("walk", "yürü"):
                    self._start_tree_walk()
                    continue

                if cmd in ("orchestrate", "parallel", "fanout", "paralel"):
                    self._start_orchestrator(use_llm=False)
                    continue

                if cmd in ("smart", "akilli", "akıllı", "orchestrate-llm"):
                    self._start_orchestrator(use_llm=True)
                    continue

                if cmd in ("remediate", "fix", "çözüm", "cozum") or cmd.startswith(("fix ", "remediate ", "çözüm ", "cozum ")):
                    parts = user_input.split(maxsplit=1)
                    self._show_remediation(parts[1].strip() if len(parts) > 1 else "")
                    continue

                if cmd.startswith("set "):
                    self._handle_set(user_input[4:])
                    continue

                # ── Auto-detect target URLs in natural language ──────────
                # Users often paste URLs like "https://IP:8200 yeni hedef bu"
                # instead of typing "set target https://IP:8200".
                _auto_target = _extract_target_url(user_input)
                if _auto_target and _auto_target != self.vault_addr:
                    prev = self.vault_addr
                    self.vault_addr = _auto_target
                    self.agent.vault_addr = _auto_target
                    self.memory.set_context("vault_addr", _auto_target)
                    if _auto_target.startswith("https://"):
                        from core.tls_config import set_insecure_mode
                        set_insecure_mode()
                    print(f"🔄 Target auto-detected: {prev or 'none'} → {_auto_target}")
                    print("   (use 'set target <url>' to change explicitly)")
                    # Don't continue — feed the original message to the agent
                    # so it can act on the new target immediately.

                # Run the agent for any other input
                asyncio.run(self._run_agent(user_input))

            except KeyboardInterrupt:
                print("\n\n👾 AGENT: Interrupted. Type 'exit' to quit.")
            except Exception as e:
                print(f"\n❌ ERROR: {e}")
                import traceback
                traceback.print_exc()

    # ── interactive provider / model selection ───────────────────────────

    def _select_provider_and_model(self):
        """Show interactive menus so the user can pick a provider and model.

        Called at the start of ``start()`` when the user did NOT pass both
        ``--provider`` and ``--model`` via the CLI.  The auto-detected
        provider and default model are pre-selected so the user can just
        press Enter to accept them.
        """
        import os

        # ── 1. Pick provider ──────────────────────────────────────────
        providers = list_providers()
        if not self._provider_explicit:
            print("\n" + "=" * 54)
            print("  🤖 SELECT AI PROVIDER")
            print("=" * 54)

            for i, p in enumerate(providers, 1):
                pid = p["id"]
                # Check availability
                env_var = {
                    "anthropic": "ANTHROPIC_API_KEY",
                    "openai": "OPENAI_API_KEY",
                    "deepseek": "DEEPSEEK_API_KEY",
                    "kimi": "KIMI_API_KEY",
                    "cursor": "CURSOR_API_KEY",
                }.get(pid, "")
                available = True
                if env_var:
                    available = bool(os.environ.get(env_var, "").strip())
                elif pid == "ollama":
                    try:
                        from ai_core.models import _detect_ollama_models
                        available = len(_detect_ollama_models()) > 0
                    except Exception:
                        available = False

                icon = " ✅" if available else " ⚠️"
                marker = "  ← varsayılan" if pid == self.provider else ""
                print(f"  [{i}] {p['name']}{icon}{marker}")
                print(f"      {p['description']}")

            # Show env var hints for unavailable providers
            for p in providers:
                pid = p["id"]
                env_var = {
                    "anthropic": "ANTHROPIC_API_KEY",
                    "openai": "OPENAI_API_KEY",
                    "deepseek": "DEEPSEEK_API_KEY",
                    "kimi": "KIMI_API_KEY",
                    "cursor": "CURSOR_API_KEY",
                }.get(pid, "")
                if env_var and not os.environ.get(env_var, "").strip():
                    print(f"      💡 {pid}: set {env_var} env var")

            print()

            while True:
                try:
                    choice = input(
                        f"  Sağlayıcı numarası [1-{len(providers)}, Enter={self.provider}]: "
                    ).strip()
                    if not choice:
                        break  # keep current (auto-detected) provider
                    idx = int(choice) - 1
                    if 0 <= idx < len(providers):
                        self.provider = providers[idx]["id"]
                        # Pick a sensible default model for the new provider
                        default = get_default_model(self.provider)
                        self.model = default
                        break
                    print(f"  1-{len(providers)} arası bir sayı girin.")
                except ValueError:
                    print(f"  1-{len(providers)} arası bir sayı girin.")
                except (KeyboardInterrupt, EOFError):
                    print("\n  Çıkış yapılıyor...")
                    sys.exit(0)

        # ── 2. Pick model ─────────────────────────────────────────────
        if not self._model_explicit or not self._provider_explicit:
            models = get_models(self.provider)
            default_model = self.model or get_default_model(self.provider)

            if not models:
                print(
                    f"\n  ⚠️  {get_provider_name(self.provider)} için model bulunamadı."
                )
                if default_model:
                    print(f"  Varsayılan kullanılıyor: {default_model}")
                    self.model = default_model
                return

            print(f"\n{'─' * 54}")
            print(f"  📦 SELECT {get_provider_name(self.provider).upper()} MODEL")
            print(f"{'─' * 54}")

            for i, m in enumerate(models, 1):
                marker = "  ← varsayılan" if m.id == default_model else ""
                tags_str = ""
                if m.tags:
                    tags_str = f" [{', '.join(m.tags)}]"
                print(f"  [{i}] {m.name}{marker}")
                print(f"      {m.description}{tags_str}")

            print()
            while True:
                try:
                    choice = input(
                        f"  Model numarası [1-{len(models)}, Enter={default_model or models[0].id}]: "
                    ).strip()
                    if not choice:
                        self.model = default_model or models[0].id
                        break
                    idx = int(choice) - 1
                    if 0 <= idx < len(models):
                        self.model = models[idx].id
                        break
                    print(f"  1-{len(models)} arası bir sayı girin.")
                except ValueError:
                    print(f"  1-{len(models)} arası bir sayı girin.")
                except (KeyboardInterrupt, EOFError):
                    print("\n  Çıkış yapılıyor...")
                    sys.exit(0)

        # ── 3. Apply selection ─────────────────────────────────────────
        # Reinitialize LLM client with chosen provider & model
        self.agent.llm = LLMClient(provider=self.provider, model=self.model)
        self._provider_explicit = True
        self._model_explicit = True
        print(f"\n  ✅ {get_provider_name(self.provider)} / {self.model} seçildi.\n")

    # ── LLM readiness check ───────────────────────────────────────────────

    def _verify_llm_ready(self):
        """Check that the selected LLM provider is actually usable.

        If the provider needs an API key and none is set, prompt the user
        to either enter one via ``set api-key`` or switch to another provider.
        Loops until the LLM is ready or the user explicitly chooses to exit.
        """
        import os

        while True:
            health = self.agent.llm.health()

            # ── OK: no issues ───────────────────────────────────────────
            if health.get("reachable") and health.get("has_api_key"):
                return  # all good, proceed silently

            # ── Ollama: not running ──────────────────────────────────────
            if self.provider == "ollama" and not health.get("reachable"):
                print(f"\n{'─' * 54}")
                print("  ⚠️  OLLAMA IS NOT RUNNING")
                print(f"{'─' * 54}")
                print(f"  Ollama is selected but not reachable at "
                      f"{self.agent.llm.base_url}.")
                print(f"  Start it with: ollama serve")
                print(f"  Then pull a model: ollama pull llama3.2")
                print()
                print("  Options:")
                print("    [Enter]  Retry connection")
                print("    [number] Switch to a different provider:")
                alt_providers = list_providers()
                for i, p in enumerate(alt_providers, 1):
                    if p["id"] == "ollama":
                        continue
                    pid = p["id"]
                    alt_env = {
                        "anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
                        "deepseek": "DEEPSEEK_API_KEY", "kimi": "KIMI_API_KEY",
                        "cursor": "CURSOR_API_KEY",
                    }.get(pid, "")
                    alt_ready = bool(alt_env and os.environ.get(alt_env, "").strip())
                    icon = " ✅" if alt_ready else ""
                    print(f"      [{i}] {p['name']}{icon}")
                print(f"    [q]      Quit")
                choice = input("  Choice [Enter=retry]: ").strip().lower()
                if choice == "q":
                    print("  Exiting...")
                    sys.exit(1)
                if choice and choice.isdigit():
                    self._switch_provider_by_number(int(choice))
                continue

            # ── Cloud provider: missing API key ──────────────────────────
            env_map = {
                "anthropic": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
                "deepseek": "DEEPSEEK_API_KEY",
                "kimi": "KIMI_API_KEY",
                "cursor": "CURSOR_API_KEY",
            }
            env_var = env_map.get(self.provider, "")
            provider_name = get_provider_name(self.provider)

            print(f"\n{'─' * 54}")
            print(f"  🔑 API KEY REQUIRED — {provider_name}")
            print(f"{'─' * 54}")
            if env_var and not os.environ.get(env_var, "").strip():
                print(f"  No API key found for {provider_name}.")
                print(f"  Set the {env_var} environment variable, or")
                print(f"  enter it below to use it this session.")
                print()
            print(f"  Get your key:")
            if self.provider == "anthropic":
                print(f"    https://console.anthropic.com/")
            elif self.provider == "openai":
                print(f"    https://platform.openai.com/api-keys")
            elif self.provider == "deepseek":
                print(f"    https://platform.deepseek.com/api_keys")
            elif self.provider == "kimi":
                print(f"    https://platform.moonshot.ai/")
            print()
            print(f"  Options:")
            print(f"    [api-key]  Paste your {env_var} now")
            print(f"    [number]   Switch to a different provider:")
            # Show available alternatives (only those ready to use)
            alt_providers = list_providers()
            for i, p in enumerate(alt_providers, 1):
                if p["id"] == self.provider:
                    continue  # skip current
                pid = p["id"]
                alt_env = env_map.get(pid, "")
                alt_ready = bool(alt_env and os.environ.get(alt_env, "").strip()) or pid == "ollama"
                icon = " ✅" if alt_ready else ""
                print(f"      [{i}] {p['name']}{icon}")
            print(f"    [q]        Quit")
            choice = input("  Choice: ").strip()

            if choice.lower() == "q":
                print("  Exiting...")
                sys.exit(1)

            if choice and choice.isdigit():
                self._switch_provider_by_number(int(choice))
                continue

            if choice and len(choice) > 10:
                # Treat as API key
                os.environ[env_var] = choice
                self.agent.llm = LLMClient(provider=self.provider, model=self.model)
                print(f"  ✅ Key set: {choice}")
                # Re-check — loop will verify on next iteration
                continue

            if not choice:
                # Empty = maybe they set the env var externally
                self.agent.llm = LLMClient(provider=self.provider, model=self.model)
                continue

            print(f"  ❓ Unknown option. Enter an API key, provider number, or 'q'.")

    def _switch_provider_by_number(self, idx: int):
        """Switch to a different provider by menu number. Prints available list."""
        providers = list_providers()
        if 1 <= idx <= len(providers):
            self.provider = providers[idx - 1]["id"]
            self.model = get_default_model(self.provider)
            self.agent.llm = LLMClient(provider=self.provider, model=self.model)
            print(f"  ✅ Switched to {get_provider_name(self.provider)} / {self.model}")
        else:
            print(f"  ❌ Invalid provider number: {idx}")
            print(f"  Available providers:")
            for i, p in enumerate(providers, 1):
                print(f"    [{i}] {p['name']}")

    # ── auto mode ─────────────────────────────────────────────────────────

    def _start_auto(self):
        """Run autonomous pentest from CLI (--auto). Exits when done."""
        exit_code = self._run_auto()
        sys.exit(exit_code)

    def _start_auto_from_chat(self):
        """Run autonomous pentest from within interactive chat (typing 'auto')."""
        if not self.vault_addr:
            print("[ERROR] Set a target first: set target http://VAULT_IP:8200")
            return
        if not self.token:
            print("[WARN] No token set — only unauthenticated recon will run.")
            print("       Set a token first for full audit: set token hvs.xxx")
        print("\n[*] Starting autonomous pentest. Press Ctrl+C to abort.\n")
        exit_code = self._run_auto()
        print(f"\n[*] Auto mode finished (exit code: {exit_code}). Back to chat.\n")

    def _run_auto(self) -> int:
        """Core autonomous pentest runner. Returns exit code (0=clean, 1=findings, 2=error).

        When ``self.interval`` is set, runs in a continuous loop:
        auto pentest → PDF report → sleep(interval) → repeat.
        Each iteration produces a timestamped PDF. Ctrl+C stops the loop.
        """
        import io
        import sys as _sys
        from datetime import datetime
        from ai_core.auto_mode import run_auto_pentest

        # Force UTF-8 stdout so Unicode characters from tools don't crash
        # on Windows terminals with cp1254/cp1252.
        if hasattr(_sys.stdout, "buffer"):
            try:
                _sys.stdout = io.TextIOWrapper(
                    _sys.stdout.buffer, encoding="utf-8", errors="replace"
                )
            except Exception:
                pass

        if not self.vault_addr:
            return 1

        # Use current provider/model (already set from CLI or interactive menus)
        if not self._provider_explicit and not self._model_explicit:
            pass  # already set in __init__ or _select_provider_and_model

        # Reinitialize agent with current provider/model
        self.agent.llm = LLMClient(provider=self.provider, model=self.model)

        is_continuous = self.interval and self.interval >= 10

        print("\n" + "=" * 60)
        print("  VAULT AI PENTEST — AUTO MODE")
        if is_continuous:
            print(f"  CONTINUOUS MODE — every {self.interval}s")
        print("=" * 60)
        print(f"\n  Provider : {self.provider}")
        print(f"  Model    : {self.model}")
        print(f"  Target   : {self.vault_addr}")
        print(f"  Token    : {self.token or 'none'}")
        print(f"  Max Risk : {self.auto_max_risk}")
        print(f"  Max Turns: {self.auto_max_turns}")
        print(f"  PDF      : {self.pdf_report or 'auto-generated (per-iteration timestamped)'}")
        if is_continuous:
            print(f"  Interval : {self.interval}s (Ctrl+C to stop)")
        print("=" * 60 + "\n")

        # ── Continuous loop or single run ────────────────────────────────
        iteration = 0
        total_findings_all_runs = 0
        last_exit_code = 0

        while True:
            iteration += 1
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")

            if is_continuous:
                print(f"\n{'═' * 54}")
                print(f"  ITERATION {iteration} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"{'═' * 54}")

            # Build per-iteration PDF path
            if is_continuous:
                base = self.pdf_report
                if not base:
                    base = "pentest_report"
                # Strip .pdf extension, add timestamp + iteration
                if base.lower().endswith(".pdf"):
                    base = base[:-4]
                iter_pdf = f"reports/{base}_{ts}_iter{iteration:03d}.pdf"
            else:
                iter_pdf = self.pdf_report

            # Run the autonomous pentest
            exit_code = 0
            findings_count = 0

            async def _run():
                nonlocal exit_code, findings_count
                async for event in run_auto_pentest(
                    vault_addr=self.vault_addr,
                    token=self.token,
                    provider=self.provider,
                    model=self.model,
                    hijack_path=self.hijack_path,
                    max_risk=self.auto_max_risk,
                    max_turns=self.auto_max_turns,
                    pdf_report=iter_pdf,
                    tool_executor=self._execute_tool,
                ):
                    etype = event.get("type", "")

                    if etype == "status":
                        print(event["message"])
                    elif etype == "thinking":
                        print(f"\n{event['message']}")
                    elif etype == "tool_call":
                        print(f"\n>> {event['message']}")
                    elif etype == "tool_result":
                        result = event["message"]
                        if len(result) > 300:
                            result = result[:300] + "..."
                        print(f"   -> {result}")
                    elif etype == "message":
                        print(f"\n[AGENT] {event['message']}")
                    elif etype == "complete":
                        print(f"\n[DONE] {event['message']}")
                    elif etype == "warning":
                        print(f"\n[WARN] {event['message']}")
                    elif etype == "error":
                        print(f"\n[ERROR] {event['message']}")
                    elif etype == "pdf_report":
                        print(f"\n[PDF] Report: {event['path']}")
                    elif etype == "exit_code":
                        exit_code = event.get("code", 0)
                    elif etype == "findings_count":
                        findings_count = event.get("count", 0)

            try:
                asyncio.run(_run())
            except KeyboardInterrupt:
                print("\n\n[WARN] Interrupted by user.")
                if is_continuous:
                    print(f"  Ran {iteration} iteration(s), {total_findings_all_runs} total findings across all runs.")
                return 2
            except Exception as exc:
                print(f"\n[ERROR] Auto mode failed: {exc}")
                import traceback
                traceback.print_exc()
                if is_continuous:
                    print(f"[WARN] Continuing to next iteration in {self.interval}s...")
                    try:
                        import time as _time
                        _time.sleep(self.interval)
                    except KeyboardInterrupt:
                        return 2
                    continue
                return 2

            last_exit_code = exit_code
            total_findings_all_runs += findings_count

            # ── Single run: exit ──────────────────────────────────────
            if not is_continuous:
                print(f"\n{'=' * 60}")
                print(f"  AUTO MODE COMPLETE — exit code: {exit_code}")
                print(f"{'=' * 60}")
                return exit_code

            # ── Continuous: print iteration summary ───────────────────
            print(f"\n{'─' * 54}")
            print(f"  Iteration {iteration} complete")
            print(f"  Findings this run : {findings_count}")
            print(f"  Total all runs    : {total_findings_all_runs}")
            print(f"  PDF               : {iter_pdf}")
            print(f"  Next run in       : {self.interval}s (Ctrl+C to stop)")
            print(f"{'─' * 54}")

            # ── Reset state for next iteration ────────────────────────
            from core.report import clear_findings
            clear_findings()

            # Sleep between iterations
            try:
                import time as _time
                _time.sleep(self.interval)
            except KeyboardInterrupt:
                print(f"\n\n[INFO] Continuous mode stopped by user.")
                print(f"  Total iterations : {iteration}")
                print(f"  Total findings   : {total_findings_all_runs}")
                print(f"  Last exit code   : {last_exit_code}")
                return 0 if total_findings_all_runs == 0 else 1

    # ── agent runner ────────────────────────────────────────────────────

    async def _run_agent(self, objective: str):
        """Stream agent output to the terminal."""
        print(f"\n{'─' * 50}")

        async for event in self._agent_stream(objective):
            etype = event.get("type", "")

            if etype == "status":
                print(event["message"])
            elif etype == "thinking":
                print(f"\n{event['message']}")
            elif etype == "tool_call":
                print(f"\n{event['message']}")
            elif etype == "tool_result":
                result = event["message"]
                # Truncate long results for display
                if len(result) > 300:
                    result = result[:300] + "..."
                print(f"   ↳ {result}")
            elif etype == "message":
                print(f"\n💬 AGENT: {event['message']}")
            elif etype == "complete":
                print(f"\n{event['message']}")
            elif etype == "error":
                print(f"\n❌ {event['message']}")
            elif etype == "warning":
                print(f"\n{event['message']}")

        print(f"{'─' * 50}")

    async def _agent_stream(self, objective: str):
        """Yield agent events, handling the async generator."""
        try:
            async for event in self._async_gen_wrapper(objective):
                yield event
        except Exception as e:
            yield {"type": "error", "message": str(e)}

    async def _async_gen_wrapper(self, objective: str):
        """Iterate the async agent.run() generator yielding events."""
        async for event in self.agent.run(objective):
            yield event
            await asyncio.sleep(0)

    # ── tool executor ───────────────────────────────────────────────────

    async def _execute_tool(self, tool_name: str, params: dict) -> str:
        """Delegate to the shared ToolExecutor."""
        return await self.tool_executor.execute_tool(tool_name, params)

    async def _call_mcp_tool(self, tool_name: str, params: dict) -> str:
        """Delegate to the shared ToolExecutor."""
        return await self.tool_executor.call_mcp_tool(tool_name, params)

    def _on_credential_discovery(self, discoveries: list[str]) -> None:
        """Callback from ToolExecutor — print credential alerts to terminal."""
        for msg in discoveries:
            if "*** ESCALATED ***" in msg or "ESCALATED" in msg:
                print(f"\n  *** PRIVILEGE ESCALATION: new token discovered! ***")

    # ── UI helpers ──────────────────────────────────────────────────────

    def _show_help(self):
        print(f"""
  COMMANDS:

    <anything>  -> Tell the agent what to do (it decides HOW)
    modules     -> List all tools the agent can use
    findings    -> Show accumulated pentest findings
    status      -> Show current target, token, provider, model, session
    auto        -> Run fully autonomous pentest + PDF report
    pilot       -> Toggle auto-pilot mode (auto-execute web PoC chains)
    walk        -> Walk the attack tree (sequential, risk-ordered branches)
    orchestrate -> Run attack plan in PARALLEL via domain specialists
    smart       -> Same as orchestrate, but each specialist uses LLM ReAct
    mutate      -> Ask LLM for alternative attack paths (dynamic branching)
    fix         -> Get remediation advice for all findings
    set target  -> Set the Vault target URL
    set token   -> Set a Vault token
    set api-key -> Set the API key for the current provider
    set model   -> Change model (interactive pick if no value)
    exit        -> Quit

  EXAMPLES:
    > "Scan this Vault and find every vulnerability"
    > "I found token hvs.abc123 — assess its power and escalate"
    > auto
    > orchestrate
    > walk

  Provider: {self.provider}  Model: {self.agent.llm.model}  Tools: {len(ALL_TOOLS)}
""")

    def _show_tools(self):
        print(f"\n🔧 AVAILABLE TOOLS ({len(ALL_TOOLS)}):\n")
        phases = {
            "recon": "🔍 RECON (no auth needed)",
            "hijack": "🔑 HIJACK (local scan)",
            "audit": "📊 AUDIT (token required)",
            "active": "⚡ ACTIVE (state-changing)",
            "meta": "📋 META",
        }
        for phase, label in phases.items():
            tools = [t for t in ALL_TOOLS if t.phase == phase]
            if not tools:
                continue
            print(f"  {label}")
            for t in tools:
                icon = "🟢" if t.risk == "read_only" else "🟡" if t.risk == "state_changing" else "🔴"
                print(f"    {icon} {t.name}")
                print(f"       {t.description[:110]}...")
            print()

    def _show_findings(self):
        from core.report import findings as global_findings

        findings = self.memory.findings or global_findings
        if not findings:
            print("\n📭 No findings yet — try running some tools first.")
            return

        print(f"\n🔍 FINDINGS ({len(findings)}):")
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                      "LOW": "🔵", "INFO": "⚪", "PASS": "🟢"}.get(sev, "⚪")
            print(f"  {i}. {emoji} [{sev}] {f.get('title', '')}")
            desc = f.get("description", "")
            if desc:
                print(f"     {desc[:120]}")

    def _show_remediation(self, filter_text: str = ""):
        """Hybrid remediation: deterministic rule engine first, LLM for the rest.

        1. ``core.remediation_engine`` matches findings against ~60 built-in
           rules (root cause + exact Vault CLI commands) — instant, no tokens.
        2. Findings that only hit the generic catch-all rule are sent to the
           LLM for deeper analysis.  If every finding matched a specific rule,
           the LLM call is skipped entirely.
        """
        from core.remediation_engine import (
            generate_priority_action_plan,
            get_remediation,
            group_by_category,
        )
        from core.report import findings as global_findings

        findings = self.memory.findings or global_findings
        if not findings:
            print("\n  No findings yet — nothing to remediate.")
            print("  Run some scans first (or try 'auto' for a full assessment).")
            return

        # Apply optional user filter (finding number or keyword)
        if filter_text:
            if filter_text.isdigit():
                idx = int(filter_text) - 1
                findings = [findings[idx]] if 0 <= idx < len(findings) else []
            else:
                kw = filter_text.lower()
                findings = [
                    f for f in findings
                    if kw in f.get("title", "").lower()
                    or kw in f.get("description", "").lower()
                ]
            if not findings:
                print(f"\n  No findings match '{filter_text}'.")
                return

        # ── 1. Deterministic rule-based advice ───────────────────────────
        advice_list = get_remediation(findings)
        grouped = group_by_category(advice_list)

        print("\n" + "=" * 60)
        print("  REMEDIATION — RULE-BASED ANALYSIS")
        print("=" * 60)
        for cat in sorted(grouped):
            print(f"\n  ▶ {cat}")
            for a in grouped[cat]:
                print(f"\n  [P{a.priority}] {a.title}")
                print(f"    Root cause: {a.root_cause[:200]}")
                print("    Fix:")
                for step in a.fix_steps[:8]:
                    print(f"      {step}")
                if a.references:
                    print(f"    Ref: {a.references[0]}")

        print("\n  ── PRIORITY ACTION PLAN ──")
        for line in generate_priority_action_plan(advice_list):
            print(f"  {line}")
        print("=" * 60)

        # ── 2. LLM only for findings that hit the generic catch-all ──────
        # The catch-all rule always starts with this fixed first fix-step.
        generic_titles = {
            a.title for a in advice_list
            if a.fix_steps
            and a.fix_steps[0].startswith("# Review this finding in the context")
        }
        unmatched = [f for f in findings if f.get("title", "") in generic_titles]

        if not unmatched:
            print(f"\n  ✅ All {len(findings)} findings matched specific remediation rules.")
            print("  No LLM analysis needed — fixes above are exact and actionable.")
            return

        print(f"\n  {len(unmatched)}/{len(findings)} findings have no specific rule —")
        print("  asking the agent for deeper analysis of those...\n")

        lines = []
        for i, f in enumerate(unmatched, 1):
            sev = f.get("severity", "INFO")
            title = f.get("title", "")
            desc = f.get("description", "")[:200]
            evidence = f.get("evidence", "")[:150]
            lines.append(f"{i}. [{sev}] {title}")
            if desc:
                lines.append(f"   {desc}")
            if evidence:
                lines.append(f"   Evidence: {evidence}")

        findings_text = "\n".join(lines)

        prompt = (
            f"I need REMEDIATION ADVICE for the following Vault pentest findings "
            f"(the rule engine had no specific fix for these). "
            f"Target: {self.vault_addr or 'unknown'}. "
            f"Token level: {'root' if self.token else 'none'}. "
            f"\n\n"
            f"=== UNMATCHED FINDINGS ({len(unmatched)} total) ===\n{findings_text}\n=== END ===\n"
            f"IMPORTANT — your task:\n"
            f"1. Analyze the findings and identify the ROOT CAUSE patterns (not one-by-one, but grouped by type).\n"
            f"2. For each root cause, give a CONCRETE fix with exact Vault CLI commands or API calls.\n"
            f"3. Prioritize: CRITICAL/HIGH first, then MEDIUM, then LOW.\n"
            f"4. Use TABLES to present fixes clearly. Format:\n"
            f"   | # | Finding | Severity | Root Cause | Fix (CLI command) |\n"
            f"5. Be specific — no vague advice like 'review policies'. Give exact commands.\n"
            f"6. If findings show leaked credentials, explain HOW to rotate them.\n"
            f"Respond in the user's language (Turkish if they speak Turkish)."
        )

        asyncio.run(self._run_agent(prompt))

    def _show_mutation(self):
        """Ask the LLM mutation engine to suggest alternative attack paths.

        Uses the global session state (tokens, credentials, findings) to
        generate a branching attack tree.  The agent receives all context
        and produces 3 ranked alternatives.
        """
        from ai_core.mutation_engine import gather_attack_state

        state = gather_attack_state()
        if not state["tokens"] and not state["findings"]:
            print("\n  No attack state available yet.")
            print("  Run some scans first to discover tokens and findings.")
            return

        findings_text = "\n".join(
            f"  [{f.get('severity', '?')}] {f.get('title', '')}"
            for f in state["findings"][-15:]
        )
        tokens_text = "\n".join(
            f"  {t['power_level']:10s} {t['source']:20s} {t['token'][:24]}..."
            for t in state["tokens"]
        ) if state["tokens"] else "  (no tokens)"

        prompt = (
            f"ATTACK TREE MUTATION REQUEST\n\n"
            f"Current target: {self.vault_addr or 'unknown'}\n\n"
            f"=== AVAILABLE TOKENS ===\n{tokens_text}\n\n"
            f"=== RECENT FINDINGS ===\n{findings_text}\n\n"
            f"=== YOUR TASK ===\n"
            f"Based on the above state, generate 3 alternative attack paths — "
            f"from most AGGRESSIVE to STEALTHIEST.\n\n"
            f"Rules:\n"
            f"1. Each path uses a REAL tool from the pentest toolkit.\n"
            f"2. Think LATERALLY — if one path is blocked, find another.\n"
            f"3. If you have DB credentials, consider direct database pivot.\n"
            f"4. If one token is limited, try another token.\n"
            f"5. If Vault is locked down, attack backend infrastructure.\n"
            f"6. Be SPECIFIC with tool names, paths, and parameters.\n\n"
            f"Respond with EXACTLY 3 paths ranked by risk, using a TABLE format:\n"
            f"| # | Risk | Tool | Reason | Expected Outcome |"
        )

        print(f"\n  Generating attack tree mutations...\n")
        asyncio.run(self._run_agent(prompt))

    def _start_tree_walk(self):
        """Run the autonomous tree walker — aggressive by default.

        Builds a mutation engine attack tree from the current session
        state, then walks it depth-first in risk order.  New tokens
        trigger recursive re-generation of the tree with elevated privileges.
        """
        from ai_core.mutation_engine import MutationEngine, gather_attack_state
        from ai_core.tree_walker import TreeWalker, RiskProfile, WalkStatus

        if not self.vault_addr:
            print("\n  Set a target first: set target http://VAULT_IP:8200")
            return

        state = gather_attack_state()
        if not state["tokens"]:
            print("\n  No tokens yet. Run recon or set a token first.")
            return

        print("\n" + "=" * 54)
        print("  ATTACK TREE WALKER")
        print("=" * 54)
        print(f"  Profile  : AGGRESSIVE (A -> B -> S)")
        print(f"  Tokens   : {state['session_summary']['total_tokens']}")
        print(f"  Best     : {state['session_summary']['best_token_power']}")
        print(f"  Max depth: 5  |  Max steps: 50")
        print("=" * 54 + "\n")

        # Build initial tree
        engine = MutationEngine()
        root = engine.start_tree(self.vault_addr, {"token_count": len(state["tokens"])})

        # Add initial branches from findings
        from ai_core.tree_walker import AttackTreeNode, BranchRisk
        for finding in state["findings"][:10]:
            sev = finding.get("severity", "INFO")
            title = finding.get("title", "")
            mod = finding.get("module", "")

            if any(w in title.lower() for w in ("denied", "blocked", "fail")):
                continue  # skip failures as initial branches

            if sev in ("CRITICAL", "HIGH"):
                risk = BranchRisk.AGGRESSIVE
            elif sev == "MEDIUM":
                risk = BranchRisk.BALANCED
            else:
                risk = BranchRisk.STEALTH

            # Suggest tools based on module
            tool = {
                "recon": "run_unauthenticated_recon",
                "capability": "run_capability_audit",
                "privilege": "run_priv_esc_scan",
                "priv_esc": "run_priv_esc_scan",
                "kv_enum": "run_kv_enumeration",
                "ttl": "run_ttl_audit",
                "auth": "run_auth_config_audit",
                "policy": "read_single_policy",
                "secret": "run_secret_exfiltration",
                "env": "run_env_scan",
            }.get(mod, "run_raw_vault_request") if mod else "run_raw_vault_request"

            engine.add_branch(
                parent=root,
                tool=tool,
                reason=title[:150],
                risk=risk,
                phase="audit",
                expected_outcome=f"Investigate: {title[:100]}",
            )

        # Walk the tree
        async def _walk():
            walker = TreeWalker(
                tool_executor=self._execute_tool,
                risk_profile=RiskProfile.AGGRESSIVE,
                max_depth=5,
                max_total_steps=50,
            )
            result = await walker.walk(root, self.vault_addr, engine)

            print(f"\n{'=' * 54}")
            print(f"  WALK COMPLETE")
            print(f"{'=' * 54}")
            print(f"  Steps      : {result.total_steps}")
            print(f"  Successes  : {result.successes}")
            print(f"  Failures   : {result.failures}")
            print(f"  Escalations: {result.escalations}")
            print(f"  Dead ends  : {result.dead_ends}")
            print(f"  Final power: {result.final_token_power}")
            print(f"  Success %  : {result.success_rate:.0%}")
            print(f"{'=' * 54}")

            for i, step in enumerate(result.steps, 1):
                icon = {
                    WalkStatus.SUCCESS: "[+]",
                    WalkStatus.ESCALATED: "[!]",
                    WalkStatus.FAILED: "[-]",
                    WalkStatus.SKIPPED: "[~]",
                    WalkStatus.DEAD_END: "[x]",
                }.get(step.status, "[?]")
                print(f"  {i:2d} {icon} [{step.risk:11s}] {step.tool:35s} ({step.attempt}/2)")

        try:
            asyncio.run(_walk())
        except KeyboardInterrupt:
            print("\n[WARN] Tree walk interrupted.")
        except Exception as exc:
            print(f"\n[ERROR] Tree walk failed: {exc}")
            import traceback
            traceback.print_exc()

    def _start_orchestrator(self, use_llm: bool = False):
        """Run the parallel orchestrator — domain specialists in parallel.

        Builds an attack tree from the current session state, decomposes
        it into domain groups, and spawns SpecialistAgents in parallel
        via asyncio.gather.  Much faster than the sequential TreeWalker
        when multiple independent domains are involved.

        When *use_llm* is True, each specialist runs a ReAct loop with
        its own LLM reasoning (slower but adaptive to unexpected results).
        """
        from ai_core.mutation_engine import MutationEngine, gather_attack_state
        from ai_core.orchestrator import AttackOrchestrator
        from ai_core.planning.plan_schema import PentestPlan, PlannedStep, AttackPhase
        from ai_core.tools import TOOL_DOMAIN_MAP
        from ai_core.tree_walker import AttackTreeNode, BranchRisk

        if not self.vault_addr:
            print("\n  Set a target first: set target http://VAULT_IP:8200")
            return

        state = gather_attack_state()
        if not state["tokens"]:
            print("\n  No tokens yet. Run recon or set a token first.")
            return

        print("\n" + "=" * 54)
        print("  PARALLEL ORCHESTRATOR" + (" [LLM ReAct]" if use_llm else ""))
        print("=" * 54)
        if use_llm:
            print(f"  Strategy : Domain specialists with LLM ReAct loop (Think->Act->Adapt)")
        else:
            print(f"  Strategy : Domain specialists in parallel (asyncio.gather)")
        print(f"  Tokens   : {state['session_summary']['total_tokens']}")
        print(f"  Best     : {state['session_summary']['best_token_power']}")
        print(f"  Max replans: 2")
        print("=" * 54 + "\n")

        # Build attack tree (same as TreeWalker for now)
        engine = MutationEngine()
        root = engine.start_tree(self.vault_addr, {"token_count": len(state["tokens"])})

        for finding in state["findings"][:10]:
            sev = finding.get("severity", "INFO")
            title = finding.get("title", "")
            mod = finding.get("module", "")

            if any(w in title.lower() for w in ("denied", "blocked", "fail")):
                continue

            if sev in ("CRITICAL", "HIGH"):
                risk = BranchRisk.AGGRESSIVE
            elif sev == "MEDIUM":
                risk = BranchRisk.BALANCED
            else:
                risk = BranchRisk.STEALTH

            tool = {
                "recon": "run_unauthenticated_recon",
                "capability": "run_capability_audit",
                "privilege": "run_priv_esc_scan",
                "priv_esc": "run_priv_esc_scan",
                "kv_enum": "run_kv_enumeration",
                "ttl": "run_ttl_audit",
                "auth": "run_auth_config_audit",
                "policy": "read_single_policy",
                "secret": "run_secret_exfiltration",
                "env": "run_env_scan",
            }.get(mod, "run_raw_vault_request") if mod else "run_raw_vault_request"

            engine.add_branch(
                parent=root,
                tool=tool,
                reason=title[:150],
                risk=risk,
                phase="audit",
                expected_outcome=f"Investigate: {title[:100]}",
            )

        # Add token-specific branches
        for t in state["tokens"]:
            engine.add_branch(
                parent=root,
                tool="run_capability_audit",
                reason=f"Audit token: {t.get('power_level', 'unknown')}",
                risk=BranchRisk.AGGRESSIVE,
                phase="audit",
                expected_outcome="Map token capabilities",
            )

        # ── Convert tree to plan ──────────────────────────────────────
        children = list(getattr(root, "children", []) or [])
        steps = []
        for child in children:
            tool_name = getattr(child, "tool", "")
            if tool_name == "__root__":
                continue
            steps.append(PlannedStep(
                tool=tool_name,
                reason=getattr(child, "reason", "")[:200],
                params=dict(getattr(child, "params", {}) or {}),
                phase=AttackPhase.AUDIT,
                risk="state_changing",
                on_failure="skip",
                max_retries=0,
            ))

        print(f"  Decomposed into {len(steps)} steps across domains...")
        domain_count = len({
            next(iter(TOOL_DOMAIN_MAP.get(s.tool, {"general"})))
            for s in steps
        })
        print(f"  Spawning specialists for {domain_count} domains...\n")

        # ── Run orchestrator ─────────────────────────────────────────
        async def _run():
            orch = AttackOrchestrator(
                vault_addr=self.vault_addr,
                token=self.token,
                tool_executor=self._execute_tool,
                max_replans=2,
                llm_client=self.agent.llm if use_llm else None,
                use_llm=use_llm,
            )
            plan = PentestPlan(vault_addr=self.vault_addr)
            plan.steps = steps
            plan.attack_narrative = (
                "LLM-powered ReAct orchestration" if use_llm
                else "Interactive parallel orchestration"
            )

            result = await orch.execute_plan(plan)

            print(f"\n{'=' * 54}")
            print(f"  ORCHESTRATOR COMPLETE")
            print(f"{'=' * 54}")
            print(f"  Domains    : {sorted(result.domains_involved)}")
            print(f"  Steps      : {result.total_steps}")
            print(f"  Successes  : {result.successes}")
            print(f"  Failures   : {result.failures}")
            print(f"  Escalated  : {result.escalated}")
            print(f"  New tokens : {len(result.new_tokens)}")
            print(f"  Duration   : {result.execution_time_ms:.0f}ms")
            print(f"  Replans    : {result.replan_count}")
            print(f"{'=' * 54}")

            # Per-domain breakdown
            print(f"\n  PER-DOMAIN RESULTS:")
            for domain, sr in sorted(result.specialist_results.items()):
                icon = "[+]" if sr.status == "completed" else "[~]" if sr.status == "partial" else "[-]"
                print(f"  {icon} {domain:14s} | steps:{sr.steps_total} ok:{sr.steps_succeeded} fail:{sr.steps_failed} | escalated:{sr.escalated}")

            # Synthesized findings
            if result.synthesized_findings:
                print(f"\n  TOP FINDINGS:")
                for f in result.synthesized_findings[:5]:
                    print(f"    [{f.get('severity', '?')}] {f.get('title', '')}")

        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            print("\n[WARN] Orchestrator interrupted.")
        except Exception as exc:
            print(f"\n[ERROR] Orchestrator failed: {exc}")
            import traceback
            traceback.print_exc()

    def _show_status(self):
        llm = self.agent.llm
        sess = self.session.status_summary()
        print(f"""
  STATUS:
    Provider : {llm.provider}
    Model    : {llm.model}
    Target   : {self.vault_addr or 'not set (use "set target <url>")'}
    Token    : {'present' if self.token else 'not set (use "set token <token>")'}
    Session  : {sess['total_tokens']} tokens, {sess['escalation_count']} escalations
    Best     : {sess['best_token_power']} ({sess['best_token_preview']}) via {sess['best_token_source']}
    Tools    : {len(ALL_TOOLS)} available
    Findings : {len(self.memory.findings)} in session memory
    LLM OK   : {'connected' if llm.is_available() else 'check connection / API key'}
""")

    def _handle_set(self, command: str):
        parts = command.strip().split(" ", 1)
        if len(parts) < 1:
            print("❌ Usage: set <param> <value>")
            print("   set target http://vault:8200")
            print("   set token hvs.abc123...")
            print("   set api-key sk-ant-...  (API key for current provider)")
            print("   set model <name>     (no value = interactive pick)")
            print("   set provider <name>  (shows model list after)")
            print("   set tls-verify off")
            return

        key = parts[0].strip()
        value = parts[1].strip() if len(parts) > 1 else ""

        if key in ("api-key", "apikey", "api_key"):
            # Allow user to set API key interactively for current provider
            provider_env = {
                "anthropic": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
                "deepseek": "DEEPSEEK_API_KEY",
                "kimi": "KIMI_API_KEY",
                "cursor": "CURSOR_API_KEY",
            }
            env_var = provider_env.get(self.provider, "")
            if env_var:
                import os
                os.environ[env_var] = value
                # Reinitialize LLM client with new key
                self.agent.llm = LLMClient(provider=self.provider, model=self.model)
                print(f"✅ {env_var} set: {value}")
                if not self.agent.llm.api_key:
                    print(f"⚠️  Key was set but LLM client could not read it back.")
            else:
                print(f"ℹ️  Provider '{self.provider}' does not need an API key "
                      f"(or it's managed differently).")
        elif key == "target":
            self.vault_addr = value
            self.agent.vault_addr = value
            self.memory.set_context("vault_addr", value)
            # Auto-skip TLS for HTTPS targets (self-signed is common in pentests)
            if value.startswith("https://"):
                from core.tls_config import set_insecure_mode
                set_insecure_mode()
            print(f"✅ Target set: {value}")
        elif key == "token":
            self.token = value
            self.agent.token = value
            self.memory.set_context("token", value)
            self.session.add_user_token(value)
            print(f"[+] Token registered in session: {value}")
        elif key == "model":
            if not value:
                # Interactive model selection for current provider
                self._pick_model_for_provider(self.provider)
            else:
                self.agent.llm.model = value
                self.model = value
                print(f"✅ Model set: {value}")
        elif key == "provider":
            if not value:
                print("❌ Usage: set provider <openai|anthropic|deepseek|ollama>")
                return
            if value not in ("openai", "anthropic", "deepseek", "kimi", "cursor", "ollama"):
                print(f"❌ Unknown provider: {value}")
                print("   Valid: openai, anthropic, deepseek, kimi, cursor, ollama")
                return
            self.provider = value
            # Show model selection after provider change
            self._pick_model_for_provider(value)
        elif key == "tls-verify":
            if value.lower() in ("off", "false", "skip", "0", "no"):
                from core.tls_config import set_insecure_mode
                set_insecure_mode()
            elif value.lower() in ("on", "true", "verify", "1", "yes"):
                from core.tls_config import get_verify
                print("TLS verification is controlled by the --skip-tls-verify startup flag")
            else:
                print(f"Unknown tls-verify value: {value}. Use 'on' or 'off'.")
        else:
            print(f"❌ Unknown parameter: {key}")
            print("   Valid: target, token, api-key, model, provider, tls-verify")

    def _pick_model_for_provider(self, provider: str):
        """Show model selection menu for a specific provider."""
        models = get_models(provider)
        default_model = get_default_model(provider)

        if not models:
            print(f"  ⚠️  {get_provider_name(provider)} için model bulunamadı.")
            if default_model:
                print(f"  Varsayılan kullanılıyor: {default_model}")
                self.model = default_model
                self.agent.llm = LLMClient(provider=provider, model=default_model)
            return

        print(f"\n  📦 {get_provider_name(provider).upper()} MODELS:")
        for i, m in enumerate(models, 1):
            marker = "  ← varsayılan" if m.id == default_model else ""
            tags_str = f" [{', '.join(m.tags)}]" if m.tags else ""
            print(f"  [{i}] {m.name}{marker}")
            print(f"      {m.description}{tags_str}")

        print()
        while True:
            try:
                choice = input(
                    f"  Model numarası [1-{len(models)}, Enter={default_model or models[0].id}]: "
                ).strip()
                if not choice:
                    self.model = default_model or models[0].id
                    break
                idx = int(choice) - 1
                if 0 <= idx < len(models):
                    self.model = models[idx].id
                    break
                print(f"  1-{len(models)} arası bir sayı girin.")
            except ValueError:
                print(f"  1-{len(models)} arası bir sayı girin.")
            except (KeyboardInterrupt, EOFError):
                self.model = default_model or models[0].id
                break

        # Apply
        self.agent.llm = LLMClient(provider=provider, model=self.model)
        print(f"  ✅ {get_provider_name(provider)} / {self.model} seçildi.\n")


async def _invoke_mcp_handler(handler, params: dict) -> str:
    """Backward-compat shim — delegates to tool_executor."""
    from ai_core.tool_executor import invoke_mcp_handler
    return await invoke_mcp_handler(handler, params)


# ── entry point (module-level) ──────────────────────────────────────────────


def start_chat_session(
    vault_addr: str | None = None,
    token: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    auto: bool = False,
    pdf_report: str | None = None,
    hijack_path: str | None = None,
    auto_max_risk: str = "read_only",
    auto_max_turns: int = 30,
    disable_web: bool = False,
    auto_pilot: bool = False,
    interval: int | None = None,
):
    """Launch the interactive AI pentest chat session (or auto mode)."""
    chat = ChatUI(
        vault_addr=vault_addr,
        token=token,
        provider=provider,
        model=model,
        auto=auto,
        pdf_report=pdf_report,
        hijack_path=hijack_path,
        auto_max_risk=auto_max_risk,
        auto_max_turns=auto_max_turns,
        disable_web=disable_web,
        auto_pilot=auto_pilot,
        interval=interval,
    )
    chat.start()


if __name__ == "__main__":
    start_chat_session()
