"""FrameworkRegistry for discovering and managing multi-language framework adapters."""

from dataclasses import dataclass
from typing import Dict, List, Optional
from python_hunter.domain.language.models import Language


@dataclass
class FrameworkMetadata:
    name: str
    language: Language
    display_name: str
    category: str  # WEB, API, ORM, CLI, MICROSERVICE
    description: str
    version: str = "1.0.0"


class FrameworkRegistry:
    """Central registry for multi-language framework adapters and detection."""

    def __init__(self) -> None:
        self._frameworks: Dict[str, FrameworkMetadata] = {}
        self._bootstrap_frameworks()

    def _bootstrap_frameworks(self) -> None:
        framework_list = [
            # Python
            FrameworkMetadata("django", Language.PYTHON, "Django", "WEB", "Full-stack Python web framework"),
            FrameworkMetadata("flask", Language.PYTHON, "Flask", "WEB", "Lightweight Python micro-framework"),
            FrameworkMetadata("fastapi", Language.PYTHON, "FastAPI", "API", "High-performance async Python API framework"),
            # JS/TS
            FrameworkMetadata("express", Language.JAVASCRIPT, "Express.js", "WEB", "Fast, unopinionated web framework for Node.js"),
            FrameworkMetadata("nestjs", Language.TYPESCRIPT, "NestJS", "API", "Progressive Node.js framework"),
            # Java
            FrameworkMetadata("spring", Language.JAVA, "Spring Framework", "WEB", "Enterprise Java framework"),
            FrameworkMetadata("spring-boot", Language.JAVA, "Spring Boot", "API", "Opinionated Spring application bootstrap"),
            # Go
            FrameworkMetadata("gin", Language.GO, "Gin", "API", "HTTP web framework written in Go"),
            FrameworkMetadata("echo", Language.GO, "Echo", "API", "High performance, extensible Go web framework"),
            FrameworkMetadata("fiber", Language.GO, "Fiber", "API", "Express-inspired Go web framework"),
            # Rust
            FrameworkMetadata("actix-web", Language.RUST, "Actix-web", "API", "Powerful, pragmatic web framework for Rust"),
            FrameworkMetadata("rocket", Language.RUST, "Rocket", "WEB", "Fast, type-safe web framework for Rust"),
            # C/C++
            FrameworkMetadata("boost", Language.CPP, "Boost", "MICROSERVICE", "Peer-reviewed C++ libraries"),
            FrameworkMetadata("qt", Language.CPP, "Qt", "WEB", "Cross-platform C++ application framework"),
            # PHP
            FrameworkMetadata("laravel", Language.PHP, "Laravel", "WEB", "PHP web framework for web artisans"),
            FrameworkMetadata("symfony", Language.PHP, "Symfony", "WEB", "High performance PHP framework"),
            # Ruby
            FrameworkMetadata("rails", Language.RUBY, "Ruby on Rails", "WEB", "Full-stack Ruby web framework"),
            FrameworkMetadata("sinatra", Language.RUBY, "Sinatra", "WEB", "DSL for quickly creating Ruby web applications"),
        ]

        for fw in framework_list:
            self._frameworks[fw.name.lower()] = fw

    def get_framework(self, name: str) -> Optional[FrameworkMetadata]:
        return self._frameworks.get(name.lower())

    def get_adapter(self, name: str) -> Optional[FrameworkMetadata]:
        return self.get_framework(name)

    def detect_all(self, workspace_path: str) -> List[FrameworkMetadata]:
        return self.list_frameworks()

    def list_frameworks(self, language: Optional[Language] = None) -> List[FrameworkMetadata]:
        if language is None:
            return list(self._frameworks.values())
        return [fw for fw in self._frameworks.values() if fw.language == language]
