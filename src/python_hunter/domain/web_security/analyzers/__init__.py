"""Web Security Analyzer Package Initialization."""

from python_hunter.domain.web_security.analyzers.base import BaseWebSecurityAnalyzer
from python_hunter.domain.web_security.analyzers.jwt_session_analyzer import JWTSessionAnalyzer
from python_hunter.domain.web_security.analyzers.route_analyzer import RouteAnalyzer

__all__ = [
    "BaseWebSecurityAnalyzer",
    "RouteAnalyzer",
    "JWTSessionAnalyzer",
]
