"""AST Security Rules Package."""

from python_hunter.domain.rules.registry import RuleRegistry
from python_hunter.rules.ast.pyh_ast_001_eval import PYHAST001Eval
from python_hunter.rules.ast.pyh_ast_002_exec import PYHAST002Exec
from python_hunter.rules.ast.pyh_ast_003_compile import PYHAST003Compile
from python_hunter.rules.ast.pyh_ast_004_os_system import PYHAST004OsSystem
from python_hunter.rules.ast.pyh_ast_005_subprocess_shell import PYHAST005SubprocessShell
from python_hunter.rules.ast.pyh_ast_006_pickle import PYHAST006Pickle
from python_hunter.rules.ast.pyh_ast_007_yaml import PYHAST007Yaml
from python_hunter.rules.ast.pyh_ast_008_dynamic_import import PYHAST008DynamicImport
from python_hunter.rules.ast.pyh_ast_009_hardcoded_credentials import PYHAST009HardcodedCredentials
from python_hunter.rules.ast.pyh_ast_010_os_popen import PYHAST010OsPopen


def get_default_registry() -> RuleRegistry:
    """Instantiate RuleRegistry populated with all default built-in AST security rules."""
    registry = RuleRegistry()
    registry.register(PYHAST001Eval())
    registry.register(PYHAST002Exec())
    registry.register(PYHAST003Compile())
    registry.register(PYHAST004OsSystem())
    registry.register(PYHAST005SubprocessShell())
    registry.register(PYHAST006Pickle())
    registry.register(PYHAST007Yaml())
    registry.register(PYHAST008DynamicImport())
    registry.register(PYHAST009HardcodedCredentials())
    registry.register(PYHAST010OsPopen())
    return registry


__all__ = [
    "PYHAST001Eval",
    "PYHAST002Exec",
    "PYHAST003Compile",
    "PYHAST004OsSystem",
    "PYHAST005SubprocessShell",
    "PYHAST006Pickle",
    "PYHAST007Yaml",
    "PYHAST008DynamicImport",
    "PYHAST009HardcodedCredentials",
    "PYHAST010OsPopen",
    "get_default_registry",
]
