"""LanguageRegistry for registering and discovering language adapters."""

from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.models import Language
from python_hunter.domain.language.python_adapter import PlaceholderJavaScriptLanguageAdapter, PythonLanguageAdapter


class LanguageRegistry:
    """Central registry for discovering and querying language adapters."""

    def __init__(self) -> None:
        self._adapters: dict[Language, LanguageAdapter] = {}
        self.register_adapter(PythonLanguageAdapter())
        self.register_adapter(PlaceholderJavaScriptLanguageAdapter())

    def register_adapter(self, adapter: LanguageAdapter) -> None:
        self._adapters[adapter.language] = adapter

    def get_adapter(self, language: Language) -> LanguageAdapter | None:
        return self._adapters.get(language)

    def get_registered_languages(self) -> list[Language]:
        return list(self._adapters.keys())
