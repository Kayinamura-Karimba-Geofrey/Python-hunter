"""Framework Rules Package Initialization."""

from python_hunter.rules.frameworks.auth_rules import PYHJWT001VerifyDisabled
from python_hunter.rules.frameworks.django_rules import (
    PYHDjango001Debug,
    PYHDjango002CSRFExempt,
)
from python_hunter.rules.frameworks.fastapi_rules import PYHFastAPI001Auth
from python_hunter.rules.frameworks.flask_rules import (
    PYHFlask001Debug,
    PYHFlask002SecretKey,
)

__all__ = [
    "PYHFlask001Debug",
    "PYHFlask002SecretKey",
    "PYHFastAPI001Auth",
    "PYHDjango001Debug",
    "PYHDjango002CSRFExempt",
    "PYHJWT001VerifyDisabled",
]
