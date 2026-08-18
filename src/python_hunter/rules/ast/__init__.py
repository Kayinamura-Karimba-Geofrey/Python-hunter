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
    from python_hunter.rules.frameworks.flask_rules import PYHFlask001Debug, PYHFlask002SecretKey
    from python_hunter.rules.frameworks.fastapi_rules import PYHFastAPI001Auth
    from python_hunter.rules.frameworks.django_rules import PYHDjango001Debug, PYHDjango002CSRFExempt
    from python_hunter.rules.frameworks.auth_rules import PYHJWT001VerifyDisabled

    from python_hunter.rules.dynamic.pyh_dynamic_001_eval_exec import PYHDynamic001EvalExec
    from python_hunter.rules.dynamic.pyh_dynamic_002_unsafe_pickle import PYHDynamic002UnsafePickle
    from python_hunter.rules.dynamic.pyh_dynamic_003_unsafe_yaml import PYHDynamic003UnsafeYAML

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
    registry.register(PYHFlask001Debug())
    registry.register(PYHFlask002SecretKey())
    registry.register(PYHFastAPI001Auth())
    registry.register(PYHDjango001Debug())
    registry.register(PYHDjango002CSRFExempt())
    registry.register(PYHJWT001VerifyDisabled())
    registry.register(PYHDynamic001EvalExec())
    registry.register(PYHDynamic002UnsafePickle())
    registry.register(PYHDynamic003UnsafeYAML())
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
