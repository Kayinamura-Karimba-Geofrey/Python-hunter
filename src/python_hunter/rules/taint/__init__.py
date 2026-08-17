"""Taint Security Rules Package."""

from python_hunter.rules.taint.pyh_taint_cmd_001 import PYHTaintCMD001
from python_hunter.rules.taint.pyh_taint_code_001 import PYHTaintCode001
from python_hunter.rules.taint.pyh_taint_path_001 import PYHTaintPath001
from python_hunter.rules.taint.pyh_taint_sql_001 import PYHTaintSQL001
from python_hunter.rules.taint.pyh_taint_ssrf_001 import PYHTaintSSRF001
from python_hunter.rules.taint.pyh_taint_template_001 import PYHTaintTemplate001


def get_all_taint_rules() -> list[object]:
    """Return instances of all registered taint security rules."""
    return [
        PYHTaintSQL001(),
        PYHTaintCMD001(),
        PYHTaintPath001(),
        PYHTaintSSRF001(),
        PYHTaintCode001(),
        PYHTaintTemplate001(),
    ]


__all__ = [
    "PYHTaintSQL001",
    "PYHTaintCMD001",
    "PYHTaintPath001",
    "PYHTaintSSRF001",
    "PYHTaintCode001",
    "PYHTaintTemplate001",
    "get_all_taint_rules",
]
