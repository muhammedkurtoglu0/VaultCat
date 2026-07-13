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

    def add_finding(self, title: str, description: str, severity: str, evidence=None):
        finding = {
            "severity": severity,
            "title": title,
            "description": description,
        }
        if evidence is not None:
            finding["evidence"] = evidence
        self.findings.append(finding)
        return finding
