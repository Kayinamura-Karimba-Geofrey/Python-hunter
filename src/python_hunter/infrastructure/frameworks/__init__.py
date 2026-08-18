"""Framework Adapters Package Initialization."""

from python_hunter.domain.frameworks.registry import FrameworkRegistry
from python_hunter.infrastructure.frameworks.auth_adapter import AuthAdapter
from python_hunter.infrastructure.frameworks.celery_adapter import CeleryAdapter
from python_hunter.infrastructure.frameworks.django_adapter import DjangoAdapter
from python_hunter.infrastructure.frameworks.fastapi_adapter import FastAPIAdapter
from python_hunter.infrastructure.frameworks.flask_adapter import FlaskAdapter
from python_hunter.infrastructure.frameworks.jinja_adapter import JinjaAdapter
from python_hunter.infrastructure.frameworks.pydantic_adapter import PydanticAdapter
from python_hunter.infrastructure.frameworks.requests_adapter import RequestsAdapter
from python_hunter.infrastructure.frameworks.sqlalchemy_adapter import SQLAlchemyAdapter


def register_all_framework_adapters() -> None:
    """Register default framework adapters into FrameworkRegistry."""
    FrameworkRegistry.register(FlaskAdapter())
    FrameworkRegistry.register(FastAPIAdapter())
    FrameworkRegistry.register(DjangoAdapter())
    FrameworkRegistry.register(CeleryAdapter())
    FrameworkRegistry.register(SQLAlchemyAdapter())
    FrameworkRegistry.register(PydanticAdapter())
    FrameworkRegistry.register(JinjaAdapter())
    FrameworkRegistry.register(RequestsAdapter())
    FrameworkRegistry.register(AuthAdapter())


# Auto-register default adapters
register_all_framework_adapters()
