"""Language Detector implementation."""

import os
from python_hunter.domain.language.models import Language


class LanguageDetector:
    """Detects languages present in a target repository based on packaging manifests and file extensions."""

    EXTENSION_MAP = {
        ".py": Language.PYTHON,
        ".js": Language.JAVASCRIPT,
        ".ts": Language.TYPESCRIPT,
        ".java": Language.JAVA,
        ".go": Language.GO,
    }

    MANIFEST_MAP = {
        "pyproject.toml": Language.PYTHON,
        "requirements.txt": Language.PYTHON,
        "setup.py": Language.PYTHON,
        "package.json": Language.JAVASCRIPT,
        "tsconfig.json": Language.TYPESCRIPT,
        "pom.xml": Language.JAVA,
        "build.gradle": Language.JAVA,
        "go.mod": Language.GO,
    }

    def detect_languages(self, workspace_path: str) -> list[Language]:
        """Scans workspace path to identify all programming languages present."""
        detected = set()

        if not os.path.exists(workspace_path):
            return [Language.UNKNOWN]

        if os.path.isfile(workspace_path):
            ext = os.path.splitext(workspace_path)[1].lower()
            if ext in self.EXTENSION_MAP:
                return [self.EXTENSION_MAP[ext]]
            return [Language.UNKNOWN]

        # Scan root files for manifests
        try:
            root_entries = os.listdir(workspace_path)
            for entry in root_entries:
                if entry in self.MANIFEST_MAP:
                    detected.add(self.MANIFEST_MAP[entry])
        except Exception:
            pass

        # Walk workspace tree for extensions
        for root, _, files in os.walk(workspace_path):
            if any(ignored in root for ignored in (".git", ".venv", "node_modules", "__pycache__")):
                continue
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in self.EXTENSION_MAP:
                    detected.add(self.EXTENSION_MAP[ext])

        return list(detected) if detected else [Language.PYTHON]
