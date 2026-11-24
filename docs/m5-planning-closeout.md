# M5 Closeout — Intent, Goals, and Planning

**Implementation status:** M5.10–M5.15 implementation is committed on
`dev/tool-authorization-lifecycle`. Local verification of the new lifecycle
work is pending; do not mark M5 closed until the commands below pass.

## Delivered scope

- Typed intent, goal, task, and bounded task-plan contracts.
- Deterministic intent inference and bounded task decomposition.
- Planning assessment for missing capabilities and authorization requirements.
- Planning metadata integrated into the Central Intelligence Core response.
- Bounded prior-turn context support and clarification for recognized follow-ups.
- Context-aware planning evaluation for intent, context presence, clarification,
  safety, and history non-disclosure.
- Explicit goal refinement proposals; only caller-supplied changes are applied.
- Multi-step plan composition with unique task IDs, ordered dependencies, and a
  hard limit of 20 tasks.
- Plan validation diagnostics for missing capabilities and unresolved ambiguity.
- Recovery recommendations for transient, invalid-output, missing-capability,
  ambiguous, dependency, and unknown failures.

## Security and correctness boundaries

1. A plan is a proposal, not permission.
2. Capability availability is not user authorization.
3. Goal refinement is not user acceptance; the result always requires separate
   confirmation.
4. Plan validation never authorizes execution.
5. Recovery recommendations never retry, replan, or execute automatically.
6. Consequential actions must continue through the Phase 1 authorization and
   guarded dispatch lifecycle.
7. Conversation history is bounded to 20 turns and must not be copied into
   public planning summaries or evaluation results.

## Known limitations

- Intent extraction and decomposition are deterministic heuristics, not
  semantic LLM planning.
- The current context flag means prior turns were supplied; it does not prove
  that the history is semantically relevant or resolve every pronoun/reference.
  Ambiguous follow-ups still require clarification.
- Multi-step composition appends explicitly supplied tasks; it does not invent
  a complete workflow from arbitrary natural-language requests.
- Recovery is advisory. No automatic retries, compensation, rollback, or
  external side effects are performed.
- The lifecycle APIs are provider-independent Python APIs. This closeout does
  not claim a new public HTTP endpoint, Android/desktop client, speech feature,
  local-model runtime, or production deployment.

## Verification required

Run from the repository root in the active virtual environment:

```bash
git pull --ff-only

python -m compileall -q backend tests scripts

pytest -q tests/test_intelligence_planning_lifecycle.py \
  tests/test_intelligence_planning_evaluation.py \
  tests/test_intelligence_planning_engine.py \
  tests/test_intelligence_planning_contracts.py \
  tests/test_intelligence_planning_integration.py

pytest -q
python -m pip check
```

Record the actual local test counts and dependency result in the release notes.
The existing Starlette/httpx test-client deprecation warning is non-blocking,
but should be addressed in a separate dependency-compatibility change.

## Exit criteria

M5 is closed only after the lifecycle tests, full suite, compilation, and
dependency check pass on the development branch. Phase 1 authorization
invariants must remain unchanged. Do not merge to `main` as part of this
milestone without explicit approval.
