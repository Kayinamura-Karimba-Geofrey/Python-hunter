"""LanguageRegistry for registering and discovering multi-language adapters."""

from typing import Dict, List, Optional
from python_hunter.domain.language.adapter import LanguageAdapter
from python_hunter.domain.language.c_cpp_adapter import CLanguageAdapter, CPPLanguageAdapter
from python_hunter.domain.language.go_adapter import GoLanguageAdapter
from python_hunter.domain.language.java_adapter import JavaLanguageAdapter
from python_hunter.domain.language.javascript_adapter import JavaScriptLanguageAdapter, TypeScriptLanguageAdapter
from python_hunter.domain.language.models import Language, LanguageMetadata
from python_hunter.domain.language.php_adapter import PHPLanguageAdapter
from python_hunter.domain.language.python_adapter import PythonLanguageAdapter
from python_hunter.domain.language.ruby_adapter import RubyLanguageAdapter
from python_hunter.domain.language.rust_adapter import RustLanguageAdapter


from python_hunter.domain.language.csharp_adapter import CSharpLanguageAdapter
from python_hunter.domain.language.kotlin_adapter import KotlinLanguageAdapter
from python_hunter.domain.language.swift_adapter import SwiftLanguageAdapter


class LanguageRegistry:
    """Central registry for discovering, querying, and managing all language adapters."""

    def __init__(self) -> None:
        self._adapters: Dict[Language, LanguageAdapter] = {}
        # Register core built-in language adapters for all 13 languages
        self.register_adapter(PythonLanguageAdapter())
        self.register_adapter(JavaScriptLanguageAdapter())
        self.register_adapter(TypeScriptLanguageAdapter())
        self.register_adapter(JavaLanguageAdapter())
        self.register_adapter(GoLanguageAdapter())
        self.register_adapter(RustLanguageAdapter())
        self.register_adapter(CLanguageAdapter())
        self.register_adapter(CPPLanguageAdapter())
        self.register_adapter(CSharpLanguageAdapter())
        self.register_adapter(PHPLanguageAdapter())
        self.register_adapter(RubyLanguageAdapter())
        self.register_adapter(KotlinLanguageAdapter())
        self.register_adapter(SwiftLanguageAdapter())


    def register_adapter(self, adapter: LanguageAdapter) -> None:
        self._adapters[adapter.language] = adapter

    def get_adapter(self, language: Language) -> Optional[LanguageAdapter]:
        return self._adapters.get(language)

    def get_registered_languages(self) -> List[Language]:
        return list(self._adapters.keys())

    def list_metadata(self) -> List[LanguageMetadata]:
        return [adapter.metadata for adapter in self._adapters.values()]

    def discover_active_adapters(self, workspace_path: str) -> List[LanguageAdapter]:
        """Discover and return adapters for languages detected in the target workspace."""
        active = []
        for adapter in self._adapters.values():
            if adapter.detect(workspace_path):
                active.append(adapter)
        return active
