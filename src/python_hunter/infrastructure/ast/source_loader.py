"""Safe Source Code Loader Adapter."""

import os
from python_hunter.domain.ast.interfaces import ASTSourceLoader
from python_hunter.domain.exceptions.base import ProjectError


class SafeSourceLoader(ASTSourceLoader):
    """Safely loads source content and lines with encoding fallback and file size guard."""

    def load_source(self, file_path: str, max_bytes: int = 2_000_000) -> tuple[str, list[str]]:
        """Load text content up to max_bytes, handling encodings safely."""
        if not os.path.exists(file_path):
            raise ProjectError(f"Source file '{file_path}' does not exist", {"path": file_path})

        st = os.stat(file_path)
        if st.st_size > max_bytes:
            raise ProjectError(
                f"Source file '{file_path}' exceeds max size of {max_bytes} bytes",
                {"path": file_path, "size": st.st_size},
            )

        content = ""
        # Try UTF-8 first, fallback to latin-1
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            with open(file_path, "r", encoding="latin-1", errors="replace") as f:
                content = f.read()

        lines = content.splitlines()
        return content, lines
