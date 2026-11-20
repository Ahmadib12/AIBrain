"""Global Language Intelligence subsystem."""

from backend.app.agli.core import AGLI
from backend.app.agli.registry import language_registry

__all__ = ["AGLI", "language_registry"]
