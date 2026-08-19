"""Web Security Rules Package Initialization."""

from python_hunter.rules.web_security.pyh_web_003_idor import PYHWeb003IDOR
from python_hunter.rules.web_security.pyh_web_004_jwt import PYHWeb004JWTWeakness
from python_hunter.rules.web_security.pyh_web_008_ssrf import PYHWeb008SSRF

__all__ = [
    "PYHWeb003IDOR",
    "PYHWeb004JWTWeakness",
    "PYHWeb008SSRF",
]
