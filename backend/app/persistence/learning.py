import hashlib
import json
import math
import uuid
from datetime import datetime, timedelta, timezone

from backend.app.persistence.database import Database
from backend.app.persistence.validation import validate_personal_payload


_ALLOWED_TRANSITIONS = {
    "pending": {"approved", "rejected", "expired"},
    "approved": {"suspended", "revoked", "expired"},
    "suspended": {"approved", "revoked", "expired"},
    "rejected": set(),
    "revoked": set(),
    "expired": set(),
}
_EVALUATION_OUTCOMES = {"improved", "no_change", "regressed", "inconclusive"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event(
    connection,
    *,
    user_id: str,
    adaptation_id: str,
    event_type: str,
    details: dict,
    created_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO learning_adaptation_events (
            id, user_id, adaptation_id, event_type, details_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            user_id,
            adaptation_id,
            event_type,
            json.dumps(details, ensure_ascii=False, sort_keys=True),
            created_at,
        ),
    )


class BehavioralLearningRepository:
    """Owner-scoped learning records; approvals never execute or grant permissions."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def record_observation(
        self,
        user_id: str,
        *,
        source: str,
        observation: object,
    ) -> dict:
        validate_personal_payload(observation)
        if not isinstance(source, str) or not source.strip() or len(source) > 100:
            raise ValueError("Invalid observation source")
        observation_id = str(uuid.uuid4())
        now = _utc_now()
        with self.database.transaction():
            self.database.connect().execute(
                "INSERT INTO observations "
                "(id, user_id, source, observation_json, status, created_at) "
                "VALUES (?, ?, ?, ?, 'observation', ?)",
                (
                    observation_id,
                    user_id,
                    source,
                    json.dumps(observation, ensure_ascii=False),
                    now,
                ),
            )
        return self.get_observation(user_id, observation_id)

    def get_observation(self, user_id: str, observation_id: str) -> dict:
        row = self.database.connect().execute(
            "SELECT * FROM observations WHERE id = ? AND user_id = ?",
            (observation_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Observation not found")
        return {
            "id": row["id"],
            "source": row["source"],
            "observation": json.loads(row["observation_json"]),
            "status": row["status"],
            "created_at": row["created_at"],
        }

    def list_observations(self, user_id: str) -> tuple[dict, ...]:
        rows = self.database.connect().execute(
            "SELECT * FROM observations WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return tuple({
            "id": row["id"],
            "source": row["source"],
            "observation": json.loads(row["observation_json"]),
            "status": row["status"],
            "created_at": row["created_at"],
        } for row in rows)

    def propose_adaptation(
        self,
        user_id: str,
        *,
        proposal: object,
        expires_in_days: int = 30,
    ) -> dict:
        validate_personal_payload(proposal)
        if not isinstance(expires_in_days, int) or not 1 <= expires_in_days <= 365:
            raise ValueError("Adaptation expiry must be between 1 and 365 days")
        adaptation_id = str(uuid.uuid4())
        now = _utc_now()
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat()
        with self.database.transaction():
            connection = self.database.connect()
            connection.execute(
                """
                INSERT INTO adaptations (
                    id, user_id, proposal_json, status, created_at, updated_at,
                    expires_at
                ) VALUES (?, ?, ?, 'pending', ?, ?, ?)
                """,
                (
                    adaptation_id, user_id,
                    json.dumps(proposal, ensure_ascii=False),
                    now, now, expires_at,
                ),
            )
            proposal_json = json.dumps(proposal, ensure_ascii=False, sort_keys=True)
            _event(
                connection,
                user_id=user_id,
                adaptation_id=adaptation_id,
                event_type="proposed",
                details={
                    "expires_at": expires_at,
                    "source": "user_submitted",
                    "proposal_sha256": hashlib.sha256(
                        proposal_json.encode("utf-8")
                    ).hexdigest(),
                },
                created_at=now,
            )
        return self.get_adaptation(user_id, adaptation_id)

    def _expire_if_due(self, user_id: str, adaptation_id: str) -> None:
        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
                """
                SELECT status, expires_at FROM adaptations
                WHERE id = ? AND user_id = ?
                """,
                (adaptation_id, user_id),
            ).fetchone()
            if (
                row is not None
                and row["status"] in {"pending", "approved", "suspended"}
                and row["expires_at"] is not None
                and row["expires_at"] <= now
            ):
                connection.execute(
                    """
                    UPDATE adaptations SET status = 'expired', updated_at = ?
                    WHERE id = ? AND user_id = ?
                    """,
                    (now, adaptation_id, user_id),
                )
                _event(
                    connection,
                    user_id=user_id,
                    adaptation_id=adaptation_id,
                    event_type="expired",
                    details={"reason": "proposal_expired"},
                    created_at=now,
                )

    def get_adaptation(self, user_id: str, adaptation_id: str) -> dict:
        self._expire_if_due(user_id, adaptation_id)
        row = self.database.connect().execute(
            "SELECT * FROM adaptations WHERE id = ? AND user_id = ?",
            (adaptation_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Adaptation not found")
        return {
            "id": row["id"],
            "proposal": json.loads(row["proposal_json"]),
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "expires_at": row["expires_at"],
            "execution_permitted": False,
        }

    def list_adaptations(self, user_id: str) -> tuple[dict, ...]:
        ids = self.database.connect().execute(
            "SELECT id FROM adaptations WHERE user_id = ?",
            (user_id,),
        ).fetchall()
        for row in ids:
            self._expire_if_due(user_id, row["id"])
        rows = self.database.connect().execute(
            "SELECT * FROM adaptations WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return tuple({
            "id": row["id"],
            "proposal": json.loads(row["proposal_json"]),
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "expires_at": row["expires_at"],
            "execution_permitted": False,
        } for row in rows)

    def update_adaptation(
        self,
        user_id: str,
        adaptation_id: str,
        *,
        status: str,
        reason: str = "",
    ) -> dict:
        if status not in {"approved", "rejected", "suspended", "revoked"}:
            raise ValueError("Unknown adaptation status")
        if not isinstance(reason, str) or len(reason) > 1000:
            raise ValueError("Invalid adaptation decision reason")
        self._expire_if_due(user_id, adaptation_id)
        now = _utc_now()
        with self.database.transaction(immediate=True):
            connection = self.database.connect()
            row = connection.execute(
                "SELECT status FROM adaptations WHERE id = ? AND user_id = ?",
                (adaptation_id, user_id),
            ).fetchone()
            if row is None:
                raise LookupError("Adaptation not found")
            current = row["status"]
            if status not in _ALLOWED_TRANSITIONS.get(current, set()):
                raise ValueError("Invalid adaptation state transition")
            connection.execute(
                "UPDATE adaptations SET status = ?, updated_at = ? "
                "WHERE id = ? AND user_id = ?",
                (status, now, adaptation_id, user_id),
            )
            _event(
                connection,
                user_id=user_id,
                adaptation_id=adaptation_id,
                event_type=status,
                details={"reason": reason.strip()},
                created_at=now,
            )
        return self.get_adaptation(user_id, adaptation_id)

    def record_evaluation(
        self,
        user_id: str,
        adaptation_id: str,
        *,
        outcome: str,
        metric: str,
        baseline_value: float,
        observed_value: float,
        confidence: float,
        evidence: object,
    ) -> dict:
        if outcome not in _EVALUATION_OUTCOMES:
            raise ValueError("Unknown evaluation outcome")
        if not isinstance(metric, str) or not metric.strip() or len(metric) > 120:
            raise ValueError("Invalid evaluation metric")
        numeric = (baseline_value, observed_value, confidence)
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in numeric):
            raise ValueError("Evaluation values must be numeric")
        if not all(math.isfinite(float(value)) for value in numeric):
            raise ValueError("Evaluation values must be finite")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Evaluation confidence must be between 0 and 1")
        validate_personal_payload(evidence)
        self._expire_if_due(user_id, adaptation_id)
        adaptation = self.database.connect().execute(
            "SELECT status FROM adaptations WHERE id = ? AND user_id = ?",
            (adaptation_id, user_id),
        ).fetchone()
        if adaptation is None:
            raise LookupError("Adaptation not found")
        if adaptation["status"] != "approved":
            raise ValueError("Evaluation requires an approved adaptation")
        evaluation_id = str(uuid.uuid4())
        now = _utc_now()
        with self.database.transaction():
            connection = self.database.connect()
            cursor = connection.execute(
                """
                INSERT INTO learning_evaluations (
                    id, user_id, adaptation_id, outcome, metric,
                    baseline_value, observed_value, confidence,
                    evidence_json, source, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'user_reported', ?)
                """,
                (
                    evaluation_id, user_id, adaptation_id, outcome,
                    metric.strip(), float(baseline_value), float(observed_value),
                    float(confidence),
                    json.dumps(evidence, ensure_ascii=False, sort_keys=True),
                    now,
                ),
            )
            _event(
                connection,
                user_id=user_id,
                adaptation_id=adaptation_id,
                event_type="evaluated",
                details={"evaluation_id": evaluation_id, "evaluation_outcome": outcome},
                created_at=now,
            )
        return self.get_evaluation(user_id, evaluation_id)

    def get_evaluation(self, user_id: str, evaluation_id: str) -> dict:
        row = self.database.connect().execute(
            """
            SELECT * FROM learning_evaluations
            WHERE id = ? AND user_id = ?
            """,
            (evaluation_id, user_id),
        ).fetchone()
        if row is None:
            raise LookupError("Evaluation not found")
        return {
            "id": row["id"],
            "adaptation_id": row["adaptation_id"],
            "outcome": row["outcome"],
            "metric": row["metric"],
            "baseline_value": row["baseline_value"],
            "observed_value": row["observed_value"],
            "confidence": row["confidence"],
            "evidence": json.loads(row["evidence_json"]),
            "source": row["source"],
            "created_at": row["created_at"],
        }

    def list_evaluations(
        self,
        user_id: str,
        adaptation_id: str,
    ) -> tuple[dict, ...]:
        owner = self.database.connect().execute(
            "SELECT 1 FROM adaptations WHERE id = ? AND user_id = ?",
            (adaptation_id, user_id),
        ).fetchone()
        if owner is None:
            raise LookupError("Adaptation not found")
        rows = self.database.connect().execute(
            """
            SELECT id FROM learning_evaluations
            WHERE user_id = ? AND adaptation_id = ?
            ORDER BY created_at DESC
            """,
            (user_id, adaptation_id),
        ).fetchall()
        return tuple(self.get_evaluation(user_id, row["id"]) for row in rows)

    def list_adaptation_events(
        self,
        user_id: str,
        adaptation_id: str,
    ) -> tuple[dict, ...]:
        if self.database.connect().execute(
            "SELECT 1 FROM adaptations WHERE id = ? AND user_id = ?",
            (adaptation_id, user_id),
        ).fetchone() is None:
            raise LookupError("Adaptation not found")
        rows = self.database.connect().execute(
            """
            SELECT * FROM learning_adaptation_events
            WHERE user_id = ? AND adaptation_id = ?
            ORDER BY rowid
            """,
            (user_id, adaptation_id),
        ).fetchall()
        return tuple({
            "id": row["id"],
            "event_type": row["event_type"],
            "details": json.loads(row["details_json"]),
            "created_at": row["created_at"],
        } for row in rows)

    def delete_all(self, user_id: str) -> None:
        with self.database.transaction():
            connection = self.database.connect()
            connection.execute("DELETE FROM observations WHERE user_id = ?", (user_id,))
            connection.execute("DELETE FROM learning_evaluations WHERE user_id = ?", (user_id,))
            connection.execute("DELETE FROM learning_adaptation_events WHERE user_id = ?", (user_id,))
            connection.execute("DELETE FROM adaptations WHERE user_id = ?", (user_id,))
