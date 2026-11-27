"""Opt-in PostgreSQL connection adapter.

This adapter is deliberately not selected by AppState. It provides safe
connection ownership, qmark adaptation, hybrid rows, and ordinary transactions.
SQLite BEGIN IMMEDIATE has no silent PostgreSQL equivalent: immediate=True
fails closed until the affected repository operation is ported to explicit
PostgreSQL locking/conditional-update semantics.
"""
from __future__ import annotations

import threading
from collections.abc import Sequence
from typing import Any, Callable

from backend.app.persistence.postgres.compat import (
    adapt_qmark_placeholders,
    hybrid_row_factory,
)


class PostgresConnection:
    """Narrow connection facade matching the repository execute surface."""

    def __init__(self, connection) -> None:
        self._connection = connection

    def execute(self, sql: str, params: Sequence[Any] | None = None):
        adapted = adapt_qmark_placeholders(sql, params)
        if params is None:
            return self._connection.execute(adapted)
        return self._connection.execute(adapted, params)

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()


class PostgresDatabase:
    """Thread-owned psycopg connections behind the shared database protocol.

    Schema migration is intentionally separate; callers must run the
    PostgreSQL migration runner before using repositories with this adapter.
    """

    def __init__(
        self,
        database_url: str,
        *,
        connect_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not isinstance(database_url, str) or not database_url.startswith(
            ("postgresql://", "postgres://")
        ):
            raise ValueError("A PostgreSQL URL is required")
        self.database_url = database_url
        self._connect_factory = connect_factory
        self._local = threading.local()
        self._connections: set[Any] = set()
        self._connections_lock = threading.Lock()

    def _new_connection(self):
        factory = self._connect_factory
        if factory is None:
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError(
                    "PostgreSQL persistence requires the optional psycopg dependency"
                ) from exc
            factory = psycopg.connect
        return factory(
            self.database_url,
            autocommit=True,
            row_factory=hybrid_row_factory,
        )

    def connect(self) -> PostgresConnection:
        wrapper = getattr(self._local, "connection", None)
        if wrapper is not None:
            return wrapper
        raw = self._new_connection()
        wrapper = PostgresConnection(raw)
        self._local.connection = wrapper
        with self._connections_lock:
            self._connections.add(raw)
        return wrapper

    def transaction(self, *, immediate: bool = False):
        return _PostgresTransaction(self, immediate=immediate)

    def shutdown(self) -> None:
        with self._connections_lock:
            connections = tuple(self._connections)
            self._connections.clear()
        for connection in connections:
            connection.close()
        if hasattr(self._local, "connection"):
            del self._local.connection


class _PostgresTransaction:
    def __init__(self, database: PostgresDatabase, *, immediate: bool) -> None:
        self.database = database
        self.immediate = immediate
        self._context = None

    def __enter__(self):
        if self.immediate:
            raise NotImplementedError(
                "PostgreSQL immediate transactions require an explicit "
                "row-locking or conditional-update implementation"
            )
        raw = self.database.connect()._connection
        self._context = raw.transaction()
        self._context.__enter__()
        return self.database

    def __exit__(self, exc_type, exc, traceback):
        if self._context is None:
            return False
        return self._context.__exit__(exc_type, exc, traceback)
