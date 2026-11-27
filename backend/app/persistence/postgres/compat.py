"""Small compatibility primitives for future PostgreSQL repository work.

These helpers do not make SQLite SQL portable by themselves and are not wired
into AppState. They are isolated building blocks for an opt-in adapter.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, Callable


def adapt_qmark_placeholders(sql: str, params: Sequence[Any] | None = None) -> str:
    """Convert positional qmark bind markers to psycopg %s markers.

    Quoted strings/identifiers, line and nested block comments, and PostgreSQL
    dollar-quoted bodies are preserved. Marker count is checked when params
    are supplied. This does not rewrite SQLite-only SQL syntax or JSON1 calls.
    """
    output: list[str] = []
    index = 0
    length = len(sql)
    state = "normal"
    dollar_tag: str | None = None
    block_depth = 0
    escape_string = False
    placeholders = 0

    while index < length:
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < length else ""

        if state == "single":
            output.append(char)
            if escape_string and char == "\\" and next_char:
                output.append(next_char)
                index += 2
                continue
            if char == "'" and next_char == "'":
                output.append(next_char)
                index += 2
                continue
            if char == "'":
                state = "normal"
                escape_string = False
            index += 1
            continue

        if state == "double":
            output.append(char)
            if char == '"' and next_char == '"':
                output.append(next_char)
                index += 2
                continue
            if char == '"':
                state = "normal"
            index += 1
            continue

        if state == "line_comment":
            output.append(char)
            if char == "\n":
                state = "normal"
            index += 1
            continue

        if state == "block_comment":
            if char == "/" and next_char == "*":
                output.extend((char, next_char))
                block_depth += 1
                index += 2
                continue
            if char == "*" and next_char == "/":
                output.extend((char, next_char))
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "normal"
                continue
            output.append(char)
            index += 1
            continue

        if state == "dollar":
            if sql.startswith(dollar_tag or "", index):
                tag = dollar_tag or ""
                output.append(tag)
                index += len(tag)
                state = "normal"
                dollar_tag = None
            else:
                output.append(char)
                index += 1
            continue

        if char == "'":
            state = "single"
            escape_string = (
                index > 0
                and sql[index - 1] in "eE"
                and (index < 2 or not (sql[index - 2].isalnum() or sql[index - 2] == "_"))
            )
            output.append(char)
            index += 1
            continue
        if char == '"':
            state = "double"
            output.append(char)
            index += 1
            continue
        if char == "-" and next_char == "-":
            output.extend((char, next_char))
            state = "line_comment"
            index += 2
            continue
        if char == "/" and next_char == "*":
            output.extend((char, next_char))
            state = "block_comment"
            block_depth = 1
            index += 2
            continue
        if char == "$":
            match = re.match(r"\$[A-Za-z_][A-Za-z_0-9]*\$|\$\$", sql[index:])
            if match:
                dollar_tag = match.group(0)
                output.append(dollar_tag)
                state = "dollar"
                index += len(dollar_tag)
                continue
        if char == "?":
            output.append("%s")
            placeholders += 1
            index += 1
            continue

        output.append(char)
        index += 1

    if state in {"single", "double", "block_comment", "dollar"}:
        raise ValueError(f"unterminated SQL {state.replace('_', ' ')}")
    if params is not None and placeholders != len(params):
        raise ValueError(
            f"SQL placeholder count ({placeholders}) does not match "
            f"parameter count ({len(params)})"
        )
    return "".join(output)


class HybridRow(Sequence[Any]):
    """SQLite-Row-like values with both positional and named lookup."""

    __slots__ = ("_values", "_columns", "_first_index")

    def __init__(self, columns: Sequence[str], values: Sequence[Any]) -> None:
        if len(columns) != len(values):
            raise ValueError("row column and value counts differ")
        self._values = tuple(values)
        self._columns = tuple(columns)
        first_index: dict[str, int] = {}
        for index, name in enumerate(self._columns):
            first_index.setdefault(name, index)
        self._first_index = first_index

    def __getitem__(self, key: int | slice | str) -> Any:
        if isinstance(key, str):
            try:
                key = self._first_index[key]
            except KeyError:
                raise IndexError(f"No such column: {key}") from None
        return self._values[key]

    def __len__(self) -> int:
        return len(self._values)

    def __iter__(self):
        return iter(self._values)

    def keys(self) -> tuple[str, ...]:
        return self._columns

    def __repr__(self) -> str:
        return f"HybridRow({dict(self)!r})"


def hybrid_row_factory(cursor) -> Callable[[Sequence[Any]], HybridRow]:
    """Build a psycopg row factory preserving named and positional access."""
    description = cursor.description or ()
    columns = tuple(
        column.name if hasattr(column, "name") else column[0]
        for column in description
    )
    return lambda values: HybridRow(columns, values)
