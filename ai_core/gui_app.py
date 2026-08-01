"""CustomTkinter desktop GUI for the Vault pentest AI agent.

Provides a native desktop interface with:
- Settings panel (target, token, provider, model)
- Real-time chat output with colored tool calls and agent messages
- Tabbed views for Findings, Tools, and Status
- Auto-pilot toggle
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import sys
import threading
import traceback
from datetime import datetime

import customtkinter as ctk

from ai_core.agent import PentestAgent
from ai_core.dynamic_session import global_store
from ai_core.llm_engine import LLMClient, detect_provider
from ai_core.memory import Memory
from ai_core.models import get_default_model, list_providers, get_provider_name
from ai_core.tools import ALL_TOOLS
from ai_core.tool_executor import ToolExecutor

# ── theme ────────────────────────────────────────────────────────────────

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ── color tags for chat output ───────────────────────────────────────────

TAG_COLORS = {
    "thinking": "#6c757d",   # gray
    "tool_call": "#0d6efd",  # blue
    "tool_result": "#198754", # green
    "message": "#ffffff",     # white
    "warning": "#ffc107",     # yellow
    "error": "#dc3545",       # red
    "complete": "#20c997",    # teal
    "status": "#6c757d",      # gray italic
    "system": "#adb5bd",      # light gray
    "discovery": "#ff6b6b",   # red-pink
}


# ───────────────────────────────────────────────────────────────────────────
# PentestGUI
# ───────────────────────────────────────────────────────────────────────────


class PentestGUI(ctk.CTk):
    """Main desktop GUI window."""

    def __init__(
        self,
        vault_addr: str | None = None,
        token: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        disable_web: bool = False,
        auto_pilot: bool = False,
        skip_tls_verify: bool = False,
    ):
        super().__init__()

        # ── config ──────────────────────────────────────────────────
        self.vault_addr = vault_addr
        self.token = token
        self.disable_web = disable_web
        self.auto_pilot = auto_pilot
        self.skip_tls_verify = skip_tls_verify
        self.provider = provider or detect_provider()
        self.model = model or get_default_model(self.provider)
        self.memory = Memory()

        # TLS: auto-disable for HTTPS targets (self-signed certs are the norm)
        self._apply_tls_setting()
        self.session = global_store
        if token:
            self.session.add_user_token(token)

        # Agent (created on-demand or on init)
        self.agent: PentestAgent | None = None
        self.tool_executor: ToolExecutor | None = None
        self._create_agent()

        # Async bridge
        self._event_queue: queue.Queue = queue.Queue()
        self._agent_running = False

        # ── window ──────────────────────────────────────────────────
        self.title("Vault Pentest Agent")
        self.geometry("1100x750")
        self.minsize(800, 500)

        # ── build UI ────────────────────────────────────────────────
        self._build_settings_bar()
        self._build_main_area()
        self._build_input_bar()

        # ── start polling the event queue ───────────────────────────
        self._poll_events()

        # ── initial status ───────────────────────────────────────────
        self._append_chat(
            f"Welcome to Vault Pentest Agent\n"
            f"Provider: {self.provider}  |  Model: {self.model}  |  "
            f"Tools: {len(ALL_TOOLS)}\n"
            f"Target: {self.vault_addr or 'not set — use Settings'}\n"
            f"Token: {'present' if self.token else 'not set'}\n"
            f"Type a command or objective below.\n",
            "system",
        )
        self._refresh_status()

    # ── URL normalization ──────────────────────────────────────────────

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Strip path, query, and fragment from a Vault URL. Keep scheme + host + port."""
        from urllib.parse import urlparse, urlunparse
        url = url.strip().rstrip("/")
        # Ensure scheme — urlparse puts everything in path if no scheme
        if "://" not in url:
            url = f"https://{url}"
        parsed = urlparse(url)
        clean = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        return clean

    # ── TLS helper ───────────────────────────────────────────────────

    def _apply_tls_setting(self) -> None:
        """Disable TLS verification if target is HTTPS or --skip-tls-verify is set."""
        if self.skip_tls_verify or (
            self.vault_addr and self.vault_addr.startswith("https://")
        ):
            from core.tls_config import set_insecure_mode
            set_insecure_mode()

    # ── agent factory ─────────────────────────────────────────────────

    def _create_agent(self) -> None:
        """(Re)create the PentestAgent and ToolExecutor."""
        self.agent = PentestAgent(
            vault_addr=self.vault_addr,
            token=self.token,
            provider=self.provider,
            model=self.model,
            disable_web=self.disable_web,
            auto_pilot=self.auto_pilot,
        )
        self.tool_executor = ToolExecutor(
            self.vault_addr, self.token, self.session, self.memory
        )
        self.tool_executor.on_discovery = self._on_discovery
        self.agent.set_tool_executor(self.tool_executor.execute_tool)

    # ──────────────────────────────────────────────────────────────────
    # UI construction
    # ──────────────────────────────────────────────────────────────────

    def _build_settings_bar(self) -> None:
        """Top row: quick settings."""
        bar = ctk.CTkFrame(self, height=36)
        bar.pack(fill="x", padx=4, pady=(4, 0))

        ctk.CTkLabel(bar, text="🔓", font=ctk.CTkFont(size=18)).pack(
            side="left", padx=(8, 4)
        )
        ctk.CTkLabel(
            bar, text="Vault Pentest Agent", font=ctk.CTkFont(weight="bold", size=14)
        ).pack(side="left", padx=4)

        # Spacer
        ctk.CTkLabel(bar, text="").pack(side="left", fill="x", expand=True)

        # Auto-pilot toggle
        self._pilot_var = ctk.BooleanVar(value=self.auto_pilot)
        self._pilot_btn = ctk.CTkSwitch(
            bar,
            text="Auto-Pilot",
            variable=self._pilot_var,
            command=self._toggle_pilot,
            width=40,
        )
        self._pilot_btn.pack(side="right", padx=8)

        # Settings button
        self._settings_btn = ctk.CTkButton(
            bar, text="⚙ Settings", width=80, command=self._open_settings
        )
        self._settings_btn.pack(side="right", padx=4)

    def _build_main_area(self) -> None:
        """Center: TabView with Chat, Findings, Tools, Status tabs."""
        self._tabs = ctk.CTkTabview(self)
        self._tabs.pack(fill="both", expand=True, padx=4, pady=4)

        # ── Chat tab ────────────────────────────────────────────────
        chat_tab = self._tabs.add("Chat")
        chat_tab.grid_rowconfigure(0, weight=1)
        chat_tab.grid_columnconfigure(0, weight=1)

        self._chat_output = ctk.CTkTextbox(
            chat_tab,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#0d1117",
            text_color="#c9d1d9",
            state="disabled",
        )
        self._chat_output.grid(row=0, column=0, sticky="nsew")

        # Configure chat text tags (foreground color only — font is forbidden
        # in CTkTextbox.tag_config because of DPI scaling).
        for tag, color in TAG_COLORS.items():
            self._chat_output.tag_config(tag, foreground=color)
        # "bold" tag uses a bright white to visually distinguish user input
        self._chat_output.tag_config("bold", foreground="#f0f6fc")

        # ── Findings tab ────────────────────────────────────────────
        findings_tab = self._tabs.add("Findings")
        findings_tab.grid_rowconfigure(0, weight=1)
        findings_tab.grid_columnconfigure(0, weight=1)

        self._findings_output = ctk.CTkTextbox(
            findings_tab,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#0d1117",
            text_color="#c9d1d9",
            state="disabled",
        )
        self._findings_output.grid(row=0, column=0, sticky="nsew")

        ctk.CTkButton(
            findings_tab,
            text="🔄 Refresh Findings",
            command=self._refresh_findings,
        ).grid(row=1, column=0, pady=4)

        # ── Tools tab ───────────────────────────────────────────────
        tools_tab = self._tabs.add("Tools")
        tools_tab.grid_rowconfigure(0, weight=1)
        tools_tab.grid_columnconfigure(0, weight=1)

        self._tools_output = ctk.CTkTextbox(
            tools_tab,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#0d1117",
            text_color="#c9d1d9",
            state="disabled",
        )
        self._tools_output.grid(row=0, column=0, sticky="nsew")
        self._refresh_tools()

        # ── Status tab ──────────────────────────────────────────────
        status_tab = self._tabs.add("Status")
        status_tab.grid_rowconfigure(0, weight=1)
        status_tab.grid_columnconfigure(0, weight=1)

        self._status_output = ctk.CTkTextbox(
            status_tab,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#0d1117",
            text_color="#c9d1d9",
            state="disabled",
        )
        self._status_output.grid(row=0, column=0, sticky="nsew")

    def _build_input_bar(self) -> None:
        """Bottom row: input field + send/clear buttons."""
        bar = ctk.CTkFrame(self, height=40)
        bar.pack(fill="x", padx=4, pady=(0, 4))

        self._input = ctk.CTkEntry(
            bar,
            placeholder_text="Type your objective or command (help, status, findings, modules, set target...)",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color="#161b22",
            height=34,
        )
        self._input.pack(side="left", fill="x", expand=True, padx=(4, 4))
        self._input.bind("<Return>", lambda e: self._send_message())

        ctk.CTkButton(
            bar,
            text="Send",
            width=70,
            command=self._send_message,
            fg_color="#238636",
            hover_color="#2ea043",
        ).pack(side="right", padx=2)

        ctk.CTkButton(
            bar,
            text="Clear",
            width=60,
            command=self._clear_chat,
            fg_color="#30363d",
            hover_color="#484f58",
        ).pack(side="right", padx=2)

    # ──────────────────────────────────────────────────────────────────
    # Settings dialog
    # ──────────────────────────────────────────────────────────────────

    def _open_settings(self) -> None:
        """Open a settings popup dialog."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Settings")
        dialog.geometry("500x400")
        dialog.grab_set()

        ctk.CTkLabel(
            dialog,
            text="⚙ Agent Settings",
            font=ctk.CTkFont(weight="bold", size=16),
        ).pack(pady=(16, 8))

        # Target
        ctk.CTkLabel(dialog, text="Vault Target URL").pack()
        target_entry = ctk.CTkEntry(dialog, width=400)
        target_entry.pack(pady=(0, 8))
        if self.vault_addr:
            target_entry.insert(0, self.vault_addr)

        # Token
        ctk.CTkLabel(dialog, text="Vault Token").pack()
        token_entry = ctk.CTkEntry(dialog, width=400, show="*")
        token_entry.pack(pady=(0, 8))
        if self.token:
            token_entry.insert(0, self.token)

        # Provider
        ctk.CTkLabel(dialog, text="LLM Provider").pack()
        providers = list_providers()
        provider_names = [p["name"] for p in providers]
        provider_ids = [p["id"] for p in providers]
        provider_var = ctk.StringVar(value=self.provider)
        provider_menu = ctk.CTkOptionMenu(
            dialog, values=provider_names, variable=provider_var
        )
        provider_menu.pack(pady=(0, 8))

        # Model
        ctk.CTkLabel(dialog, text="Model").pack()
        model_entry = ctk.CTkEntry(dialog, width=400)
        model_entry.pack(pady=(0, 16))
        model_entry.insert(0, self.model)

        def _save():
            raw = target_entry.get().strip()
            self.vault_addr = self._normalize_url(raw) if raw else None
            self.token = token_entry.get().strip() or None
            # Map provider name back to ID
            try:
                idx = provider_names.index(provider_var.get())
                self.provider = provider_ids[idx]
            except ValueError:
                pass
            self.model = model_entry.get().strip() or get_default_model(self.provider)

            if self.token:
                self.session.add_user_token(self.token)
            self._apply_tls_setting()
            self._create_agent()
            self._refresh_status()
            self._refresh_tools()
            self._append_chat(
                f"Settings updated:\n"
                f"  Target: {self.vault_addr or 'not set'}\n"
                f"  Token: {'present' if self.token else 'not set'}\n"
                f"  Provider: {self.provider}\n"
                f"  Model: {self.model}\n"
                f"  TLS verify: {'OFF' if not self.skip_tls_verify or (self.vault_addr and self.vault_addr.startswith('https://')) else 'ON'}\n",
                "system",
            )
            dialog.destroy()

        ctk.CTkButton(dialog, text="Save", command=_save).pack()

    # ──────────────────────────────────────────────────────────────────
    # Message sending
    # ──────────────────────────────────────────────────────────────────

    def _send_message(self) -> None:
        """Read the input field and dispatch."""
        text = self._input.get().strip()
        if not text:
            return
        self._input.delete(0, "end")

        cmd = text.lower()

        # ── built-in commands (handled synchronously) ──────────────
        if cmd in ("exit", "quit", "q"):
            self._append_chat("Goodbye!\n", "system")
            self.after(500, self.destroy)
            return

        if cmd in ("restart", "yenile", "reboot"):
            self._restart_app()
            return

        if cmd in ("help", "yardım", "?"):
            self._show_help()
            return

        if cmd in ("modules", "modüller", "ls"):
            self._tabs.set("Tools")
            return

        if cmd == "findings":
            self._refresh_findings()
            self._tabs.set("Findings")
            return

        if cmd == "status":
            self._refresh_status()
            self._tabs.set("Status")
            return

        if cmd in ("pilot", "auto-pilot", "otopilot"):
            self._pilot_var.set(not self._pilot_var.get())
            self._toggle_pilot()
            return

        if cmd.startswith("set "):
            self._handle_set(text[4:])
            return

        # ── everything else → agent ─────────────────────────────────
        self.memory.add_conversation("user", text)
        self._append_chat(f"YOU: {text}\n", "bold")
        self._run_agent(text)

    def _run_agent(self, objective: str) -> None:
        """Launch the agent in a background thread."""
        if self._agent_running:
            self._append_chat("⚠ Agent is already processing.\n", "warning")
            return

        self._agent_running = True
        self._input.configure(state="disabled")

        def _agent_thread():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._agent_loop(objective))
            except Exception as e:
                self._event_queue.put(("error", str(e)))
                traceback.print_exc()
            finally:
                loop.close()
                self._event_queue.put(("done", None))

        t = threading.Thread(target=_agent_thread, daemon=True)
        t.start()

    async def _agent_loop(self, objective: str) -> None:
        """Iterate agent.run() and push events into the GUI queue."""
        try:
            async for event in self.agent.run(objective):
                self._event_queue.put((event.get("type", "unknown"), event))
        except Exception as e:
            self._event_queue.put(("error", {"message": str(e)}))

    # ──────────────────────────────────────────────────────────────────
    # Event polling (Tkinter main thread)
    # ──────────────────────────────────────────────────────────────────

    def _poll_events(self) -> None:
        """Process all queued agent events in the GUI thread."""
        while True:
            try:
                etype, event = self._event_queue.get_nowait()
            except queue.Empty:
                break

            if etype == "done":
                self._agent_running = False
                self._input.configure(state="normal")
                self._refresh_findings()
                self._refresh_status()
                continue

            if etype == "thinking":
                self._append_chat(f"🧠 {event.get('message', '')}\n", "thinking")
            elif etype == "tool_call":
                tool = event.get("tool", "?")
                params = json.dumps(event.get("params", {}), indent=2)
                self._append_chat(f"\n▶ {tool}\n{params}\n", "tool_call")
            elif etype == "tool_result":
                msg = event.get("message", "")
                if len(msg) > 800:
                    msg = msg[:800] + "..."
                self._append_chat(f"  ↳ {msg}\n", "tool_result")
            elif etype == "message":
                self._append_chat(f"\n💬 {event.get('message', '')}\n", "message")
            elif etype == "warning":
                self._append_chat(f"⚠ {event.get('message', '')}\n", "warning")
            elif etype == "error":
                self._append_chat(f"❌ {event.get('message', '')}\n", "error")
            elif etype == "complete":
                self._append_chat(f"✅ {event.get('message', '')}\n", "complete")
            elif etype == "status":
                self._append_chat(f"  {event.get('message', '')}\n", "status")

        self.after(100, self._poll_events)

    # ──────────────────────────────────────────────────────────────────
    # Chat output helpers
    # ──────────────────────────────────────────────────────────────────

    def _append_chat(self, text: str, tag: str = "") -> None:
        """Append text to the chat output with optional color tag."""
        self._chat_output.configure(state="normal")
        if tag:
            self._chat_output.insert("end", text, tag)
        else:
            self._chat_output.insert("end", text)
        self._chat_output.see("end")
        self._chat_output.configure(state="disabled")

    def _clear_chat(self) -> None:
        self._chat_output.configure(state="normal")
        self._chat_output.delete("1.0", "end")
        self._chat_output.configure(state="disabled")

    # ──────────────────────────────────────────────────────────────────
    # Tab refreshers
    # ──────────────────────────────────────────────────────────────────

    def _refresh_findings(self) -> None:
        """Update the Findings tab."""
        from core.report import findings as global_findings

        findings = self.memory.findings or global_findings
        self._findings_output.configure(state="normal")
        self._findings_output.delete("1.0", "end")

        if not findings:
            self._findings_output.insert("end", "📭 No findings yet.\n")
        else:
            sev_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵",
                "INFO": "⚪",
                "PASS": "🟢",
            }
            for i, f in enumerate(findings, 1):
                sev = f.get("severity", "INFO")
                emoji = sev_emoji.get(sev, "⚪")
                title = f.get("title", "")[:120]
                self._findings_output.insert(
                    "end", f"{i:3d}. {emoji} [{sev:8s}] {title}\n"
                )

        self._findings_output.configure(state="disabled")

    def _refresh_tools(self) -> None:
        """Update the Tools tab."""
        self._tools_output.configure(state="normal")
        self._tools_output.delete("1.0", "end")

        phases = {
            "recon": ("🔍 Recon (no auth)", []),
            "hijack": ("🔑 Hijack (local scan)", []),
            "audit": ("📊 Audit (token required)", []),
            "active": ("⚡ Active (state-changing)", []),
            "meta": ("📋 Meta", []),
        }
        for t in ALL_TOOLS:
            if t.phase in phases:
                phases[t.phase][1].append(t)

        for _label, (_title, tools) in phases.items():
            if not tools:
                continue
            self._tools_output.insert("end", f"\n═══ {_title} ═══\n\n")
            for t in tools:
                risk_icon = {
                    "read_only": "🟢",
                    "state_changing": "🟡",
                    "destructive": "🔴",
                }.get(t.risk, "⚪")
                self._tools_output.insert(
                    "end",
                    f"  {risk_icon} {t.name}\n"
                    f"     {t.description[:130]}...\n\n",
                )

        self._tools_output.configure(state="disabled")

    def _refresh_status(self) -> None:
        """Update the Status tab."""
        sess = self.session.status_summary()
        self._status_output.configure(state="normal")
        self._status_output.delete("1.0", "end")

        status_text = f"""══════════════ STATUS ══════════════

  Provider : {self.provider}
  Model    : {self.model}
  Target   : {self.vault_addr or 'not set'}
  Token    : {'present' if self.token else 'not set'}

  Session tokens : {sess['total_tokens']}
  Escalations    : {sess['escalation_count']}
  Best token     : {sess['best_token_power']}
  Best source    : {sess['best_token_source']}

  Tools    : {len(ALL_TOOLS)} available
  Findings : {len(self.memory.findings)} in memory

  Auto-Pilot : {'ON' if self.auto_pilot else 'OFF'}
  Agent busy : {'YES' if self._agent_running else 'no'}
"""
        self._status_output.insert("end", status_text)
        self._status_output.configure(state="disabled")

    # ──────────────────────────────────────────────────────────────────
    # Built-in commands
    # ──────────────────────────────────────────────────────────────────

    def _show_help(self) -> None:
        text = """═══════════ HELP ═══════════

  help          This message
  modules       List all tools (Tools tab)
  findings      Show findings (Findings tab)
  status        Show session status (Status tab)
  pilot         Toggle auto-pilot mode
  set target    Set Vault target URL
  set token     Set Vault token
  set api-key   Set API key for current provider
  set model     Change model
  restart       Relaunch GUI with current settings
  exit          Quit

  Anything else is sent to the AI agent.
  Example: "Scan this Vault for vulnerabilities"
"""
        self._append_chat(text, "system")

    def _restart_app(self) -> None:
        """Restart the GUI completely fresh — no settings preserved."""
        import subprocess

        self._append_chat("♻ Restarting GUI — fresh start, all settings cleared...\n", "warning")

        main_py = os.path.join(os.path.dirname(os.path.dirname(__file__)), "main.py")
        if os.path.exists(main_py):
            args = [sys.executable, main_py, "chat", "--ui", "desktop"]
        else:
            args = [sys.executable, "-m", "ai_core.gui_app"]

        # No settings carried over — clean slate

        def _do_restart():
            self.destroy()
            subprocess.Popen(args, creationflags=subprocess.CREATE_NEW_CONSOLE)

        self.after(800, _do_restart)

    def _handle_set(self, command: str) -> None:
        parts = command.strip().split(" ", 1)
        if len(parts) < 2:
            self._append_chat(
                "Usage: set target URL  |  set token TOKEN  |  "
                "set api-key KEY  |  set model NAME\n",
                "warning",
            )
            return

        key = parts[0].strip()
        value = parts[1].strip()

        if key in ("api-key", "apikey", "api_key"):
            env_map = {
                "openai": "OPENAI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
                "deepseek": "DEEPSEEK_API_KEY",
                "kimi": "KIMI_API_KEY",
                "cursor": "CURSOR_API_KEY",
            }
            env_var = env_map.get(self.provider, "")
            if env_var:
                os.environ[env_var] = value
                self._create_agent()
                self._append_chat(
                    f"✅ {env_var} set: {value[:20]}...\n", "system"
                )
            else:
                self._append_chat(
                    f"ℹ Provider '{self.provider}' has no API key.\n", "system"
                )

        elif key == "target":
            normalized = self._normalize_url(value)
            self.vault_addr = normalized
            self.agent.vault_addr = normalized
            self.tool_executor.vault_addr = normalized
            self.memory.set_context("vault_addr", normalized)
            self._apply_tls_setting()
            if normalized != value:
                self._append_chat(f"✅ Target: {normalized} (path stripped from '{value}')\n", "system")
            else:
                self._append_chat(f"✅ Target: {normalized}\n", "system")
            self._refresh_status()

        elif key == "token":
            self.token = value
            self.agent.token = value
            self.tool_executor.token = value
            self.memory.set_context("token", value)
            self.session.add_user_token(value)
            self._append_chat(
                f"✅ Token: {value[:24]}...\n", "system"
            )
            self._refresh_status()

        elif key == "model":
            self.model = value
            self._create_agent()
            self._append_chat(f"✅ Model: {value}\n", "system")
            self._refresh_status()

        elif key == "provider":
            if value not in (
                "openai", "anthropic", "deepseek", "kimi", "cursor", "ollama"
            ):
                self._append_chat(f"❌ Unknown provider: {value}\n", "error")
                return
            self.provider = value
            self.model = get_default_model(value)
            self._create_agent()
            self._append_chat(
                f"✅ Provider: {value} / Model: {self.model}\n", "system"
            )
            self._refresh_status()
        else:
            self._append_chat(
                f"❌ Unknown parameter: {key}\n", "error"
            )

    def _toggle_pilot(self) -> None:
        self.auto_pilot = self._pilot_var.get()
        if self.agent:
            self.agent._auto_pilot = self.auto_pilot
        state = "ON" if self.auto_pilot else "OFF"
        self._append_chat(f"🛩 Auto-Pilot: {state}\n", "system")
        self._refresh_status()

    # ──────────────────────────────────────────────────────────────────
    # Callbacks
    # ──────────────────────────────────────────────────────────────────

    def _on_discovery(self, discoveries: list[str]) -> None:
        """Callback from ToolExecutor — show credential discoveries."""
        for d in discoveries:
            if "ESCALATED" in d:
                self._append_chat(
                    f"🔴 PRIVILEGE ESCALATION! New token discovered!\n",
                    "discovery",
                )
            else:
                self._append_chat(f"🟢 {d}\n", "discovery")


# ───────────────────────────────────────────────────────────────────────────
# Entry point
# ───────────────────────────────────────────────────────────────────────────


def start_gui(
    vault_addr: str | None = None,
    token: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    disable_web: bool = False,
    auto_pilot: bool = False,
    skip_tls_verify: bool = False,
) -> None:
    """Launch the CustomTkinter desktop GUI."""
    app = PentestGUI(
        vault_addr=vault_addr,
        token=token,
        provider=provider,
        model=model,
        disable_web=disable_web,
        auto_pilot=auto_pilot,
        skip_tls_verify=skip_tls_verify,
    )
    app.mainloop()
