"""Secret Detector Registry."""

from python_hunter.domain.exceptions.base import ValidationError
from python_hunter.domain.secrets.models import SecretDetector, SecretType


class SecretDetectorRegistry:
    """Registry managing secret detectors, enforcing unique IDs and filtering by status."""

    def __init__(self) -> None:
        self._detectors: dict[str, SecretDetector] = {}

    def register(self, detector: SecretDetector) -> None:
        """Register a secret detector instance."""
        if not detector.id:
            raise ValidationError("Secret detector must have a non-empty ID")
        if detector.id in self._detectors:
            raise ValidationError(f"Detector ID '{detector.id}' is already registered", {"detector_id": detector.id})
        self._detectors[detector.id] = detector

    def unregister(self, detector_id: str) -> None:
        """Remove a detector from the registry."""
        if detector_id in self._detectors:
            del self._detectors[detector_id]

    def get(self, detector_id: str) -> SecretDetector | None:
        """Get registered detector by ID."""
        return self._detectors.get(detector_id)

    def get_all(self) -> list[SecretDetector]:
        """Return list of all registered secret detectors."""
        return list(self._detectors.values())

    def enabled_detectors(self) -> list[SecretDetector]:
        """Return list of enabled detectors."""
        return [d for d in self._detectors.values() if d.enabled]

    def find_by_type(self, secret_type: SecretType) -> list[SecretDetector]:
        """Find detectors matching specific secret type."""
        return [d for d in self._detectors.values() if d.secret_type == secret_type]
