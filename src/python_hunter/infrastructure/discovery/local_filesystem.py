"""Safe Local FileSystem Implementation."""

from collections.abc import Iterator
import os
import pathlib
import stat
from python_hunter.domain.discovery.enums import FileCategory
from python_hunter.domain.discovery.interfaces import FileSystem
from python_hunter.domain.discovery.manifest import FileMetadata
from python_hunter.domain.exceptions.base import ProjectError


class LocalFileSystem(FileSystem):
    """Local filesystem adapter with strict path traversal guards, symlink limits, and special file filtering."""

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(path)

    def is_file(self, path: str) -> bool:
        return os.path.isfile(path)

    def is_symlink(self, path: str) -> bool:
        return os.path.islink(path)

    def normalize_path(self, path: str) -> str:
        return os.path.abspath(os.path.expanduser(path))

    def is_safe_path(self, base_root: str, target_path: str) -> bool:
        """Enforce path traversal guard ensuring target_path remains inside base_root."""
        real_root = os.path.realpath(self.normalize_path(base_root))
        try:
            real_target = os.path.realpath(self.normalize_path(target_path))
            return os.path.commonpath([real_root, real_target]) == real_root
        except (ValueError, OSError):
            return False

    def read_text_safe(self, path: str, max_bytes: int = 1_000_000) -> str:
        """Safely read text from file up to max_bytes without executing or memory overflow."""
        norm = self.normalize_path(path)
        if not self.is_file(norm):
            return ""
        try:
            with open(norm, "r", encoding="utf-8", errors="replace") as f:
                return f.read(max_bytes)
        except Exception as e:
            raise ProjectError(f"Failed to read file {path}: {e}", {"path": path}) from e

    def walk(self, root_path: str, max_depth: int = 20) -> Iterator[tuple[str, list[str], list[str]]]:
        """Safely walk directory tree up to max_depth."""
        norm_root = self.normalize_path(root_path)
        real_root = os.path.realpath(norm_root)

        for current_root, dirs, files in os.walk(norm_root, followlinks=False):
            # Compute depth
            rel = os.path.relpath(current_root, norm_root)
            depth = 0 if rel == "." else len(pathlib.Path(rel).parts)
            if depth > max_depth:
                dirs.clear()
                continue

            # Filter symlink directories pointing outside root or looping
            valid_dirs: list[str] = []
            for d in dirs:
                full_d = os.path.join(current_root, d)
                if os.path.islink(full_d):
                    real_d = os.path.realpath(full_d)
                    if not real_d.startswith(real_root):
                        continue
                valid_dirs.append(d)
            dirs[:] = valid_dirs

            yield current_root, dirs, files

    def get_file_metadata(self, root_path: str, relative_path: str) -> FileMetadata:
        """Construct safe FileMetadata for a relative file path under root_path."""
        full_path = os.path.join(root_path, relative_path)
        is_sym = os.path.islink(full_path)
        
        try:
            st = os.lstat(full_path)
            size = st.st_size
            mode = st.st_mode

            # Reject FIFO, socket, device files
            if not (stat.S_ISREG(mode) or stat.S_ISLNK(mode) or stat.S_ISDIR(mode)):
                raise ProjectError(f"Special filesystem object detected at {relative_path}", {"path": relative_path})
        except OSError:
            size = 0

        ext = os.path.splitext(relative_path)[1].lower()
        is_py = ext in (".py", ".pyw", ".pyi")
        is_hid = os.path.basename(relative_path).startswith(".")

        # Initial category heuristic
        if is_py:
            category = FileCategory.PYTHON_STUB if ext == ".pyi" else FileCategory.PYTHON_SOURCE
        elif ext in (".toml", ".yaml", ".yml", ".json", ".ini", ".cfg"):
            category = FileCategory.CONFIGURATION
        elif ext in (".md", ".rst", ".txt"):
            category = FileCategory.DOCUMENTATION
        else:
            category = FileCategory.OTHER

        return FileMetadata(
            relative_path=relative_path,
            size_bytes=size,
            category=category,
            extension=ext,
            is_python=is_py,
            is_hidden=is_hid,
            is_ignored=False,
            is_symlink=is_sym,
        )
