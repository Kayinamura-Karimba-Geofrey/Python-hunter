"""Git Security Rules Package."""

from python_hunter.rules.git.pyh_git_001_historical_secret import PYHGit001HistoricalSecret
from python_hunter.rules.git.pyh_git_002_sensitive_file import PYHGit002SensitiveFile
from python_hunter.rules.git.pyh_git_003_gitignore_omission import PYHGit003GitignoreOmission
from python_hunter.rules.git.pyh_git_004_remote_credential import PYHGit004RemoteCredential
from python_hunter.rules.git.pyh_git_005_cicd_security import PYHGit005CICDSecurity
from python_hunter.rules.git.pyh_git_006_mutable_action_ref import PYHGit006MutableActionRef
from python_hunter.rules.git.pyh_git_007_git_hook_risk import PYHGit007GitHookRisk
from python_hunter.rules.git.pyh_git_008_sensitive_config_change import PYHGit008SensitiveConfigChange


def get_all_git_rules() -> list[object]:
    """Return instances of all registered Git security rules."""
    return [
        PYHGit001HistoricalSecret(),
        PYHGit002SensitiveFile(),
        PYHGit003GitignoreOmission(),
        PYHGit004RemoteCredential(),
        PYHGit005CICDSecurity(),
        PYHGit006MutableActionRef(),
        PYHGit007GitHookRisk(),
        PYHGit008SensitiveConfigChange(),
    ]


__all__ = [
    "PYHGit001HistoricalSecret",
    "PYHGit002SensitiveFile",
    "PYHGit003GitignoreOmission",
    "PYHGit004RemoteCredential",
    "PYHGit005CICDSecurity",
    "PYHGit006MutableActionRef",
    "PYHGit007GitHookRisk",
    "PYHGit008SensitiveConfigChange",
    "get_all_git_rules",
]
