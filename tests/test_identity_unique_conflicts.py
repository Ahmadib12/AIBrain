import sqlite3
from types import SimpleNamespace

import pytest

from backend.app.persistence.identity import _is_email_unique_violation


def test_recognizes_sqlite_users_email_unique_constraint():
    error = sqlite3.IntegrityError("UNIQUE constraint failed: users.email")
    assert _is_email_unique_violation(error) is True


def test_recognizes_postgres_users_email_unique_constraint():
    error = RuntimeError("duplicate key")
    error.sqlstate = "23505"
    error.diag = SimpleNamespace(constraint_name="users_email_key")
    assert _is_email_unique_violation(error) is True


@pytest.mark.parametrize(
    "sqlstate,constraint_name",
    [
        ("23505", "sessions_pkey"),
        ("23503", "users_email_key"),
        ("23505", None),
        (None, "users_email_key"),
    ],
)
def test_does_not_translate_unrelated_database_errors(sqlstate, constraint_name):
    error = RuntimeError("database failure")
    error.sqlstate = sqlstate
    error.diag = SimpleNamespace(constraint_name=constraint_name)
    assert _is_email_unique_violation(error) is False


def test_does_not_translate_other_sqlite_unique_constraints():
    error = sqlite3.IntegrityError("UNIQUE constraint failed: users.id")
    assert _is_email_unique_violation(error) is False
