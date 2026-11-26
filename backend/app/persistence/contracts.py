"""Structural contracts shared by persistence backends."""
from __future__ import annotations

from typing import Any, ContextManager, Protocol, runtime_checkable


class TransactionProtocol(Protocol):
    """Commit on success and roll back on exception."""

    def __enter__(self) -> Any: ...
    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool | None: ...


@runtime_checkable
class DatabaseProtocol(Protocol):
    """Minimum database surface consumed by persistence repositories.

    Implementations must provide safe connection ownership, enforce foreign
    keys, and roll back every statement when a transaction exits exceptionally.
    """

    def connect(self) -> Any:
        """Return the current unit-of-work connection."""

    def transaction(self, *, immediate: bool = False) -> ContextManager[Any]:
        """Open an atomic transaction.

        The immediate flag is a SQLite writer-lock hint. Other backends may map
        it to an equivalent serialization strategy, but may not weaken atomicity.
        """

    def shutdown(self) -> None:
        """Close all backend-owned resources."""


def require_database_protocol(database: object) -> DatabaseProtocol:
    """Validate the structural boundary at composition time."""
    if not isinstance(database, DatabaseProtocol):
        raise TypeError("Persistence backend does not implement DatabaseProtocol")
    return database
