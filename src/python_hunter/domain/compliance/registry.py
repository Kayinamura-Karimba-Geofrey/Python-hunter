"""Control Registry and Pre-loaded Framework Library."""

from typing import Dict, List, Optional
from python_hunter.domain.compliance.models import (
    ComplianceControlModel, ComplianceFrameworkModel, ControlCategory, ControlState
)


class ControlRegistry:
    """Registry for managing compliance frameworks and security controls."""

    def __init__(self) -> None:
        self._frameworks: Dict[str, ComplianceFrameworkModel] = {}
        self._controls: Dict[str, ComplianceControlModel] = {}
        self._load_standard_frameworks_and_library()

    def _load_standard_frameworks_and_library(self) -> None:
        """Loads standard security frameworks and reusable security control library."""
        # 1. Frameworks
        frameworks = [
            ComplianceFrameworkModel("OWASP_ASVS_V4", "OWASP Application Security Verification Standard", "4.0.3", "Standard for Web App Security Controls"),
            ComplianceFrameworkModel("OWASP_TOP_10", "OWASP Top 10 Web Application Security Risks", "2021", "Standard security awareness document for developers and security analysts"),
            ComplianceFrameworkModel("OWASP_SAMM_V2", "OWASP Software Assurance Maturity Model", "2.0", "Maturity model for software security"),
            ComplianceFrameworkModel("NIST_CSF_V2", "NIST Cybersecurity Framework", "2.0", "Framework for managing cybersecurity risk"),
            ComplianceFrameworkModel("NIST_800_53_REV5", "NIST SP 800-53", "Rev. 5", "Security and Privacy Controls for Info Systems"),
            ComplianceFrameworkModel("CIS_CONTROLS_V8", "CIS Controls", "v8", "Prioritized set of cybersecurity safeguards"),
            ComplianceFrameworkModel("ISO_27001_2022", "ISO/IEC 27001", "2022", "Information security management systems"),
            ComplianceFrameworkModel("SOC_2_TYPE_2", "SOC 2 Type II", "2023", "Trust Services Criteria for Security & Privacy"),
        ]
        for fw in frameworks:
            self.register_framework(fw)

        # 2. Reusable Security Controls Library
        controls = [
            ComplianceControlModel(
                control_id="CTRL-VULN-001",
                framework_id="NIST_CSF_V2",
                title="Vulnerability Scanning & SAST",
                description="Perform automated static application security testing (SAST) on all repositories.",
                category=ControlCategory.VULNERABILITY_MANAGEMENT,
                requirements=["Run SAST scanner on commit/PR", "No unaddressed critical vulnerabilities"],
                mapped_cwes=["CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-502"],
                mapped_rule_ids=["PYH-AST-001", "PYH-AST-004", "PYH-TAINT-001"]
            ),
            ComplianceControlModel(
                control_id="CTRL-DEP-001",
                framework_id="OWASP_ASVS_V4",
                title="Dependency Scanning & SCA",
                description="Scan third-party software dependencies for known CVEs and outdated packages.",
                category=ControlCategory.SUPPLIER_SECURITY,
                requirements=["Identify vulnerable dependencies", "Maintain lockfiles with cryptographic hashes"],
                mapped_cwes=["CWE-1395", "CWE-1104"],
                mapped_rule_ids=["PYH-SCA-001", "PYH-SCA-002"]
            ),
            ComplianceControlModel(
                control_id="CTRL-SEC-001",
                framework_id="SOC_2_TYPE_2",
                title="Secret Leak Detection",
                description="Prevent plaintext credentials, tokens, and private keys from being committed.",
                category=ControlCategory.DATA_PROTECTION,
                requirements=["Zero unredacted hardcoded secrets in repository"],
                mapped_cwes=["CWE-798", "CWE-259"],
                mapped_rule_ids=["PYH-SEC-001", "PYH-SEC-002", "PYH-SEC-003"]
            ),
            ComplianceControlModel(
                control_id="CTRL-MFA-001",
                framework_id="CIS_CONTROLS_V8",
                title="MFA Requirement",
                description="Enforce Multi-Factor Authentication for all developers and administrative accounts.",
                category=ControlCategory.ACCESS_CONTROL,
                requirements=["MFA enabled for GitHub/GitLab org members"],
                mapped_cwes=["CWE-308"]
            ),
            ComplianceControlModel(
                control_id="CTRL-LOG-001",
                framework_id="ISO_27001_2022",
                title="Audit Logging & Integrity",
                description="Maintain tamper-evident audit logs of security operations and access decisions.",
                category=ControlCategory.LOGGING,
                requirements=["Audit logging enabled", "Log retention policy enforced"],
                mapped_cwes=["CWE-778"]
            ),
            ComplianceControlModel(
                control_id="CTRL-OWASP-A03",
                framework_id="OWASP_TOP_10",
                title="A03:2021 Injection & Dangerous Code Execution",
                description="Prevent SQL injection, OS command execution, and untrusted dynamic code evaluation.",
                category=ControlCategory.VULNERABILITY_MANAGEMENT,
                requirements=["Parameterized database queries", "Safe process execution primitives"],
                mapped_cwes=["CWE-89", "CWE-78", "CWE-77"],
                mapped_rule_ids=["PYH-AST-001", "PYH-AST-004", "PYH-TAINT-001", "PYH-SEC-004"]
            ),
            ComplianceControlModel(
                control_id="CTRL-OWASP-A06",
                framework_id="OWASP_TOP_10",
                title="A06:2021 Vulnerable and Outdated Components",
                description="Verify software supply-chain integrity, audit dependencies, and prevent typosquatting.",
                category=ControlCategory.SUPPLIER_SECURITY,
                requirements=["Audited dependencies", "No malicious setup hooks or supply-chain trojans"],
                mapped_cwes=["CWE-1395", "CWE-1104", "CWE-829"],
                mapped_rule_ids=[
                    "PYHUNTER-PYPI-SETUP-001",
                    "PYHUNTER-NPM-SCRIPT-001",
                    "PYHUNTER-PYPI-TYPO-001",
                    "PYHUNTER-NPM-TYPO-001",
                    "PYH-DEP-001",
                    "PYH-DEP-002",
                    "PYH-SUPPLY-004",
                    "PYH-VULN-001"
                ]
            ),
            ComplianceControlModel(
                control_id="CTRL-OWASP-A07",
                framework_id="OWASP_TOP_10",
                title="A07:2021 Identification & Secret Security",
                description="Eliminate hardcoded API keys, tokens, and credentials from version control.",
                category=ControlCategory.DATA_PROTECTION,
                requirements=["Zero hardcoded credentials or unredacted secrets in code"],
                mapped_cwes=["CWE-798", "CWE-259"],
                mapped_rule_ids=["PYH-SECRET-001", "PYH-SECRET-002", "PYH-SEC-001"]
            ),
            ComplianceControlModel(
                control_id="CTRL-OWASP-A08",
                framework_id="OWASP_TOP_10",
                title="A08:2021 Software and Data Integrity Failures",
                description="Detect repository malware, tasks hijacking, trojan font scripts, and git droppers.",
                category=ControlCategory.VULNERABILITY_MANAGEMENT,
                requirements=["Zero malware or task jacking payloads in workspace"],
                mapped_cwes=["CWE-494", "CWE-345"],
                mapped_rule_ids=[
                    "PYH-MAL-001",
                    "PYH-MAL-002",
                    "PYH-MAL-003",
                    "PYH-MAL-004",
                    "PYH-MAL-005"
                ]
            ),
        ]
        for ctrl in controls:
            self.register_control(ctrl)

    def register_framework(self, framework: ComplianceFrameworkModel) -> None:
        self._frameworks[framework.framework_id] = framework

    def get_framework(self, framework_id: str) -> Optional[ComplianceFrameworkModel]:
        return self._frameworks.get(framework_id)

    def list_frameworks(self) -> List[ComplianceFrameworkModel]:
        return list(self._frameworks.values())

    def register_control(self, control: ComplianceControlModel) -> None:
        self._controls[control.control_id] = control

    def get_control(self, control_id: str) -> Optional[ComplianceControlModel]:
        return self._controls.get(control_id)

    def list_controls(self, framework_id: Optional[str] = None) -> List[ComplianceControlModel]:
        if framework_id:
            return [c for c in self._controls.values() if c.framework_id == framework_id]
        return list(self._controls.values())
