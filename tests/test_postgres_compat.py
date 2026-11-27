from types import SimpleNamespace

import pytest

from backend.app.persistence.postgres.compat import (
    HybridRow,
    adapt_qmark_placeholders,
    hybrid_row_factory,
)


def test_qmark_adapter_skips_quoted_identifiers_strings_and_comments():
    sql = """SELECT ? AS value, '?' AS literal, "?" AS identifier
    -- ? is comment content
    /* outer ? /* nested ? */ still comment ? */
    WHERE account_id = ?"""
    adapted = adapt_qmark_placeholders(sql, ("value", "owner"))
    assert "SELECT %s AS value" in adapted
    assert "'?' AS literal" in adapted
    assert '"?" AS identifier' in adapted
    assert "-- ? is comment content" in adapted
    assert "/* outer ? /* nested ? */ still comment ? */" in adapted
    assert "WHERE account_id = %s" in adapted


def test_qmark_adapter_preserves_dollar_quoted_procedural_body():
    sql = "DO $body$ BEGIN RAISE NOTICE '?'; /* ? */ END $body$; SELECT ?"
    assert adapt_qmark_placeholders(sql, (1,)) == (
        "DO $body$ BEGIN RAISE NOTICE '?'; /* ? */ END $body$; SELECT %s"
    )


def test_qmark_adapter_handles_escaped_and_doubled_quotes():
    sql = r"SELECT E'it\\'s ?' AS escaped, 'it''s ?' AS doubled, ?"
    adapted = adapt_qmark_placeholders(sql, (7,))
    assert adapted.endswith(", %s")
    assert r"E'it\\'s ?'" in adapted
    assert "'it''s ?'" in adapted


def test_qmark_adapter_rejects_parameter_count_mismatch():
    with pytest.raises(ValueError, match="placeholder count"):
        adapt_qmark_placeholders("SELECT ?, ?", (1,))


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 'unterminated ?",
        'SELECT "unterminated ?',
        "SELECT 1 /* unterminated ?",
        "SELECT 1, $tag$unterminated ?",
    ],
)
def test_qmark_adapter_rejects_unterminated_sql_regions(sql):
    with pytest.raises(ValueError, match="unterminated SQL"):
        adapt_qmark_placeholders(sql)


def test_hybrid_row_supports_named_positional_and_mapping_access():
    row = HybridRow(("id", "email"), ("user-1", "user@example.test"))
    assert row[0] == "user-1"
    assert row["id"] == "user-1"
    assert row[1] == row["email"]
    assert dict(row) == {"id": "user-1", "email": "user@example.test"}
    assert tuple(row) == ("user-1", "user@example.test")
    assert row.keys() == ("id", "email")


def test_hybrid_row_uses_first_duplicate_column_name_like_sqlite_row():
    row = HybridRow(("id", "id"), ("first", "second"))
    assert row["id"] == "first"
    assert row[1] == "second"


def test_hybrid_row_factory_uses_cursor_column_names():
    cursor = SimpleNamespace(
        description=(
            SimpleNamespace(name="id"),
            SimpleNamespace(name="value"),
        )
    )
    make_row = hybrid_row_factory(cursor)
    row = make_row(("item-1", 42))
    assert row["id"] == "item-1"
    assert row[1] == 42


def test_hybrid_row_factory_supports_dbapi_tuple_descriptions():
    cursor = SimpleNamespace(description=(("id",), ("value",)))
    row = hybrid_row_factory(cursor)(("item-2", 84))
    assert row["value"] == 84
