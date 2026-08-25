"""Domain Enums for Python Hunter."""

from enum import Enum


class Severity(str, Enum):
    """Vulnerability and finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> float:
        """Numeric weight for risk scoring calculations."""
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.5,
        }
        return weights[self]


class Confidence(str, Enum):
    """Detection confidence levels."""

    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def multiplier(self) -> float:
        """Multiplier for risk scoring calculations."""
        multipliers = {
            Confidence.CONFIRMED: 1.0,
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.8,
            Confidence.LOW: 0.5,
            Confidence.UNKNOWN: 0.2,
        }
        return multipliers[self]


class TrustBoundary(str, Enum):
    """Security trust boundaries across application and delivery infrastructure."""

    INTERNET = "INTERNET"
    USER = "USER"
    APPLICATION = "APPLICATION"
    CONTAINER = "CONTAINER"
    KUBERNETES = "KUBERNETES"
    CLOUD = "CLOUD"
    DATABASE = "DATABASE"
    INTERNAL_NETWORK = "INTERNAL_NETWORK"
    CICD = "CICD"


class PrivilegeLevel(str, Enum):
    """Privilege transition states along attack paths."""

    UNAUTHENTICATED = "UNAUTHENTICATED"
    USER = "USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    CLOUD_IDENTITY = "CLOUD_IDENTITY"
    ADMINISTRATOR = "ADMINISTRATOR"


class ScanStatus(str, Enum):
    """Scan lifecycle execution states."""

    PENDING = "PENDING"
    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        """Check if the scan state is terminal (cannot transition further)."""
        return self in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED)


class FindingStatus(str, Enum):
    """Finding lifecycle triage states."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"


class Category(str, Enum):
    """Security finding categories."""

    CODE_SECURITY = "CODE_SECURITY"
    SECRET = "SECRET"
    DEPENDENCY = "DEPENDENCY"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    TAINT = "TAINT"
    INJECTION = "INJECTION"
    CONFIGURATION = "CONFIGURATION"
    AUTHORIZATION = "AUTHORIZATION"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    GIT_HISTORY = "GIT_HISTORY"
    SECURITY_POLICY = "SECURITY_POLICY"
    INFORMATIONAL = "INFORMATIONAL"
    CODE_INJECTION = "CODE_INJECTION"
    SECRET_LEAK = "SECRET_LEAK"
    VULNERABLE_DEPENDENCY = "VULNERABLE_DEPENDENCY"
    GIT_RISK = "GIT_RISK"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    UNSAFE_DESERIALIZATION = "UNSAFE_DESERIALIZATION"
    DANGEROUS_API = "DANGEROUS_API"
    TAINT_ANALYSIS = "TAINT_ANALYSIS"
    AUTHENTICATION = "AUTHENTICATION"
    FRAMEWORK = "FRAMEWORK"
    DYNAMIC_EXECUTION = "DYNAMIC_EXECUTION"
    DYNAMIC_IMPORT = "DYNAMIC_IMPORT"
    DYNAMIC_DISPATCH = "DYNAMIC_DISPATCH"
    REFLECTION = "REFLECTION"
    METAPROGRAMMING = "METAPROGRAMMING"
    CONCURRENCY_RISK = "CONCURRENCY_RISK"
    MALWARE_RISK = "MALWARE_RISK"
    API_SECURITY = "API_SECURITY"
    OTHER = "OTHER"




class ExposureType(str, Enum):
    """Attack surface exposure level."""

    INTERNET_FACING = "INTERNET_FACING"
    AUTHENTICATED = "AUTHENTICATED"
    INTERNAL = "INTERNAL"
    LOCAL = "LOCAL"
    UNKNOWN = "UNKNOWN"


class ReachabilityType(str, Enum):
    """Static reachability status of finding."""

    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    STATIC_REACHABILITY = "STATIC_REACHABILITY"
    UNKNOWN = "UNKNOWN"


class FindingLifecycleState(str, Enum):
    """Finding baseline and tracking lifecycle states."""

    NEW = "NEW"
    OPEN = "OPEN"
    EXISTING = "EXISTING"
    SUPPRESSED = "SUPPRESSED"
    ACCEPTED = "ACCEPTED"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"


class AttackPathType(str, Enum):
    """Correlated attack path category."""

    REMOTE_CODE_EXECUTION = "REMOTE_CODE_EXECUTION"
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    AUTHORIZATION_BYPASS = "AUTHORIZATION_BYPASS"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"


class FindingRelationType(str, Enum):
    """Relationship between security findings."""

    DUPLICATE = "DUPLICATE"
    RELATED = "RELATED"
    SUPPORTING_EVIDENCE = "SUPPORTING_EVIDENCE"
    CAUSED_BY = "CAUSED_BY"
    DEPENDS_ON = "DEPENDS_ON"
    ESCALATES = "ESCALATES"
    ATTACK_PATH_COMPONENT = "ATTACK_PATH_COMPONENT"


class AssetCriticality(str, Enum):
    """Asset or path criticality level."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class DataSensitivity(str, Enum):
    """Sensitivity of processed data."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SENSITIVE = "SENSITIVE"
    UNKNOWN = "UNKNOWN"


class SecretStatus(str, Enum):
    """Secret revocation and exposure state."""

    SECRET_EXPOSED = "SECRET_EXPOSED"
    SECRET_REVOKED = "SECRET_REVOKED"
    SECRET_UNKNOWN_STATUS = "SECRET_UNKNOWN_STATUS"


class VerificationStatus(str, Enum):
    """Exploitability verification outcome status."""

    VERIFIED = "VERIFIED"
    LIKELY_EXPLOITABLE = "LIKELY_EXPLOITABLE"
    NOT_VERIFIED = "NOT_VERIFIED"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    TEST_ERROR = "TEST_ERROR"
    NOT_TESTED = "NOT_TESTED"


class VerificationConfidence(str, Enum):
    """Confidence level of verification proof."""

    VERIFIED = "VERIFIED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VerificationMode(str, Enum):
    """Verification mode (passive static analysis vs active sandboxed execution)."""

    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"


class TestSafetyLevel(str, Enum):
    """Safety classification for security verification test cases."""

    PASSIVE_ONLY = "PASSIVE_ONLY"
    SAFE_LOCAL_NON_DESTRUCTIVE = "SAFE_LOCAL_NON_DESTRUCTIVE"
    DESTRUCTIVE_FORBIDDEN = "DESTRUCTIVE_FORBIDDEN"


