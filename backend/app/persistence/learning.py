import json
import uuid
from datetime import datetime, timezone

from backend.app.persistence.database import Database
from backend.app.persistence.validation import validate_personal_payload


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class BehavioralLearningRepository:
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
        if len(source) > 100:
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
            "SELECT * FROM observations "
            "WHERE id = ? AND user_id = ?",
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
            "SELECT * FROM observations "
            "WHERE user_id = ? ORDER BY created_at DESC",
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
    ) -> dict:
        validate_personal_payload(proposal)
        adaptation_id = str(uuid.uuid4())
        now = _utc_now()
        with self.database.transaction():
            self.database.connect().execute(
                "INSERT INTO adaptations "
                "(id, user_id, proposal_json, status, created_at, updated_at) "
                "VALUES (?, ?, ?, 'pending', ?, ?)",
                (
                    adaptation_id,
                    user_id,
                    json.dumps(proposal, ensure_ascii=False),
                    now,
                    now,
                ),
            )
        return self.get_adaptation(user_id, adaptation_id)

    def get_adaptation(self, user_id: str, adaptation_id: str) -> dict:
        row = self.database.connect().execute(
            "SELECT * FROM adaptations "
            "WHERE id = ? AND user_id = ?",
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
        }

    def list_adaptations(self, user_id: str) -> tuple[dict, ...]:
        rows = self.database.connect().execute(
            "SELECT * FROM adaptations "
            "WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return tuple({
            "id": row["id"],
            "proposal": json.loads(row["proposal_json"]),
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        } for row in rows)

    def update_adaptation(
        self,
        user_id: str,
        adaptation_id: str,
        *,
        status: str,
    ) -> dict:
        if status not in {"approved", "rejected", "suspended", "revoked"}:
            raise ValueError("Unknown adaptation status")
        now = _utc_now()
        with self.database.transaction():
            cursor = self.database.connect().execute(
                "UPDATE adaptations SET status = ?, updated_at = ? "
                "WHERE id = ? AND user_id = ?",
                (status, now, adaptation_id, user_id),
            )
            if cursor.rowcount != 1:
                raise LookupError("Adaptation not found")
        return self.get_adaptation(user_id, adaptation_id)

    def delete_all(self, user_id: str) -> None:
        with self.database.transaction():
            connection = self.database.connect()
            connection.execute(
                "DELETE FROM observations WHERE user_id = ?",
                (user_id,),
            )
            connection.execute(
                "DELETE FROM adaptations WHERE user_id = ?",
                (user_id,),
            )
