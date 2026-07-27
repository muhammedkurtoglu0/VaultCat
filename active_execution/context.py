import threading
from dataclasses import dataclass, field
from typing import Optional

from core.tls_config import get_verify


@dataclass
class ExecutionContext:
    vault_addr: str
    token: Optional[str] = None
    captured_token: Optional[str] = None
    escalated_token: Optional[str] = None
    namespace: Optional[str] = None
    verify_tls: bool = field(default_factory=get_verify)
    findings: list = field(default_factory=list)
    store: object = None  # DynamicCredentialStore (lazy import)

    # Thread-safety: protects ``self.findings`` from concurrent mutation.
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self):
        # Auto-resolve token from global store if none provided
        if not self.token and self.store:
            best = self.store.get_best_token_value()
            if best:
                self.token = best

    def add_finding(self, title: str, description: str, severity: str, evidence=None):
        """Append a finding.  Thread-safe — multiple agents can call this
        concurrently on the same context without corrupting the list."""
        finding = {
            "severity": severity,
            "title": title,
            "description": description,
        }
        if evidence is not None:
            finding["evidence"] = evidence
        with self._lock:
            self.findings.append(finding)
        return finding
