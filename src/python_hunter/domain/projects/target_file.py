"""Target File Value Object."""

from dataclasses import dataclass
from python_hunter.domain.exceptions.base import ValidationError


@dataclass(frozen=True)
class TargetFile:
    """Representation of a target file within a scannable project."""

    relative_path: str
    size_bytes: int
    mime_type: str = "text/plain"
    is_python: bool = True

    def __post_init__(self) -> None:
        if not self.relative_path or not self.relative_path.strip():
            raise ValidationError("relative_path cannot be empty")
        if self.size_bytes < 0:
            raise ValidationError("size_bytes cannot be negative", {"size_bytes": self.size_bytes})
