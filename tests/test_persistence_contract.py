from backend.app.persistence.contracts import (
    DatabaseProtocol,
    require_database_protocol,
)
from backend.app.persistence.database import Database


def test_sqlite_database_implements_structural_persistence_contract():
    database = Database("sqlite:///:memory:")
    try:
        assert isinstance(database, DatabaseProtocol)
        assert require_database_protocol(database) is database
        with database.transaction(immediate=True):
            database.connect().execute(
                "CREATE TABLE persistence_contract_probe (value TEXT NOT NULL)"
            )
        assert database.connect().execute(
            "SELECT name FROM sqlite_master WHERE name=?",
            ("persistence_contract_probe",),
        ).fetchone() is not None
    finally:
        database.shutdown()


def test_persistence_contract_rolls_back_failed_transactions():
    database = Database("sqlite:///:memory:")
    try:
        with database.transaction():
            database.connect().execute(
                "CREATE TABLE rollback_contract_probe (value TEXT NOT NULL)"
            )
        try:
            with database.transaction(immediate=True):
                database.connect().execute(
                    "INSERT INTO rollback_contract_probe(value) VALUES (?)",
                    ("must-roll-back",),
                )
                raise RuntimeError("force rollback")
        except RuntimeError:
            pass
        count = database.connect().execute(
            "SELECT COUNT(*) AS total FROM rollback_contract_probe"
        ).fetchone()["total"]
        assert count == 0
    finally:
        database.shutdown()
