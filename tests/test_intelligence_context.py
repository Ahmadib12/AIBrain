import pytest

from backend.app.intelligence.context import RequestContext
from backend.app.intelligence.schemas import ContextRole


def test_request_context_is_isolated_between_instances() -> None:
    first = RequestContext()
    second = RequestContext()

    first.add_turn(ContextRole.USER, "First request")

    assert first.context.turns[0].content == "First request"
    assert second.context.turns == ()
    assert first.context_id != second.context_id


def test_request_context_has_bounded_size() -> None:
    context = RequestContext(max_turns=3)

    for index in range(5):
        context.add_turn(ContextRole.USER, f"Turn {index}")

    assert len(context.context.turns) == 3
    assert context.context.turns[0].content == "Turn 2"


def test_request_context_rejects_invalid_max_turns() -> None:
    with pytest.raises(ValueError, match="between 1 and 20"):
        RequestContext(max_turns=21)


def test_request_context_clear_removes_turns() -> None:
    context = RequestContext()
    context.add_turn(ContextRole.USER, "Temporary")
    context.clear()

    assert context.context.turns == ()


def test_request_context_rejects_credentials() -> None:
    context = RequestContext()

    with pytest.raises(ValueError, match="Credentials"):
        context.add_turn(ContextRole.USER, "token=abcdefghijklmnop")
