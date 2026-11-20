from backend.app.intelligence.schemas import (
    ContextRole,
    ContextTurn,
    ConversationContext,
)


class RequestContext:
    """Request-scoped, bounded, in-memory conversation context."""

    def __init__(
        self,
        context_id: str | None = None,
        *,
        max_turns: int = 20,
    ) -> None:
        if max_turns < 1 or max_turns > 20:
            raise ValueError("Request context size must be between 1 and 20 turns")
        self.max_turns = max_turns
        self._context = (
            ConversationContext(context_id=context_id)
            if context_id
            else ConversationContext()
        )

    @property
    def context(self) -> ConversationContext:
        return self._context

    @property
    def context_id(self) -> str:
        return self._context.context_id

    def add_turn(
        self,
        role: ContextRole,
        content: str,
    ) -> ContextTurn:
        turn = ContextTurn(role=role, content=content)
        current = list(self._context.turns)
        current.append(turn)
        if len(current) > self.max_turns:
            current = current[-self.max_turns:]
        self._context = ConversationContext(
            context_id=self.context_id,
            turns=tuple(current),
        )
        return turn

    def clear(self) -> None:
        self._context = ConversationContext(context_id=self.context_id)
