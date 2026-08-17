"""Project Entity."""

from dataclasses import dataclass, field
import uuid
from python_hunter.domain.exceptions.base import ValidationError


@dataclass
class Project:
    """Represents an analyzed project root (Git repo or directory)."""

    name: str
    root_path: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    repository_url: str | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValidationError("Project name cannot be empty")
        if not self.root_path or not self.root_path.strip():
            raise ValidationError("Project root_path cannot be empty")
