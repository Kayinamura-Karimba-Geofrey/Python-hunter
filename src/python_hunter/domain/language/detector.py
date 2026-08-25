"""LanguageDetector for polyglot project analysis and language percentage profiling."""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Set
from python_hunter.domain.language.models import Language


@dataclass
class LanguageProfile:
    total_files: int = 0
    total_lines: int = 0
    file_counts: Dict[Language, int] = field(default_factory=dict)
    line_counts: Dict[Language, int] = field(default_factory=dict)
    percentage_by_files: Dict[str, float] = field(default_factory=dict)
    percentage_by_lines: Dict[str, float] = field(default_factory=dict)
    detected_manifests: List[str] = field(default_factory=list)


EXTENSION_MAP = {
    ".py": Language.PYTHON,
    ".pyw": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".go": Language.GO,
    ".rs": Language.RUST,
    ".c": Language.C,
    ".h": Language.C,
    ".cpp": Language.CPP,
    ".hpp": Language.CPP,
    ".cc": Language.CPP,
    ".cxx": Language.CPP,
    ".cs": Language.CSHARP,
    ".php": Language.PHP,
    ".rb": Language.RUBY,
    ".kt": Language.KOTLIN,
    ".kts": Language.KOTLIN,
    ".swift": Language.SWIFT,
}

MANIFEST_MAP = {
    "pom.xml": Language.JAVA,
    "build.gradle": Language.JAVA,
    "build.gradle.kts": Language.KOTLIN,
    "go.mod": Language.GO,
    "go.sum": Language.GO,
    "Cargo.toml": Language.RUST,
    "Cargo.lock": Language.RUST,
    "composer.json": Language.PHP,
    "Gemfile": Language.RUBY,
    "Gemfile.lock": Language.RUBY,
    "requirements.txt": Language.PYTHON,
    "pyproject.toml": Language.PYTHON,
    "setup.py": Language.PYTHON,
    "package.json": Language.TYPESCRIPT,
    "CMakeLists.txt": Language.CPP,
    "Makefile": Language.C,
    "Package.swift": Language.SWIFT,
    "Podfile": Language.SWIFT,
}


IGNORED_DIRS = {
    "node_modules",
    "vendor",
    "target",
    "build",
    "dist",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".idea",
    ".vscode",
}


class LanguageDetector:
    """Detects languages and computes language distribution profile across a codebase."""

    @staticmethod
    def detect_workspace_languages(workspace_path: str) -> LanguageProfile:
        file_counts: Dict[Language, int] = {}
        line_counts: Dict[Language, int] = {}
        detected_manifests: List[str] = []
        total_files = 0
        total_lines = 0

        if not os.path.exists(workspace_path):
            return LanguageProfile()

        # If single file passed
        if os.path.isfile(workspace_path):
            ext = os.path.splitext(workspace_path)[1].lower()
            lang = EXTENSION_MAP.get(ext, Language.UNKNOWN)
            try:
                with open(workspace_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = len(f.readlines())
            except Exception:
                lines = 1
            return LanguageProfile(
                total_files=1,
                total_lines=lines,
                file_counts={lang: 1},
                line_counts={lang: lines},
                percentage_by_files={lang.value: 100.0},
                percentage_by_lines={lang.value: 100.0},
                detected_manifests=[],
            )

        for root, dirs, files in os.walk(workspace_path):
            # Exclude noise directories
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

            for file_name in files:
                full_path = os.path.join(root, file_name)
                
                # Check manifest files
                if file_name in MANIFEST_MAP:
                    detected_manifests.append(file_name)
                    lang = MANIFEST_MAP[file_name]
                    file_counts[lang] = file_counts.get(lang, 0) + 1

                ext = os.path.splitext(file_name)[1].lower()
                if ext in EXTENSION_MAP:
                    lang = EXTENSION_MAP[ext]
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = sum(1 for line in f if line.strip())
                    except Exception:
                        lines = 1

                    total_files += 1
                    total_lines += lines
                    file_counts[lang] = file_counts.get(lang, 0) + 1
                    line_counts[lang] = line_counts.get(lang, 0) + lines

        # Calculate percentages
        perc_files = {}
        perc_lines = {}

        if total_files > 0:
            for lang, cnt in file_counts.items():
                perc_files[lang.value] = round((cnt / total_files) * 100, 1)

        if total_lines > 0:
            for lang, lines in line_counts.items():
                perc_lines[lang.value] = round((lines / total_lines) * 100, 1)

        return LanguageProfile(
            total_files=total_files,
            total_lines=total_lines,
            file_counts=file_counts,
            line_counts=line_counts,
            percentage_by_files=perc_files,
            percentage_by_lines=perc_lines,
            detected_manifests=detected_manifests,
        )
