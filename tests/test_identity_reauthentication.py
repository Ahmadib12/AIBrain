from backend.app.persistence.database import Database
from backend.app.persistence.identity import IdentityRepository


def create_identity(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'identity-reauth.db'}")
    identity = IdentityRepository(
        database,
        session_ttl_seconds=86400,
    )
    return database, identity


def test_password_verification_does_not_create_session(tmp_path):
    database, identity = create_identity(tmp_path)

    try:
        user = identity.register(
            email="reauth@example.com",
            password="safe-password-123",
            display_name="Reauthentication Test",
        )

        before = database.connect().execute(
            "SELECT COUNT(*) FROM sessions"
        ).fetchone()[0]

        assert identity.verify_password(
            user_id=user["id"],
            password="safe-password-123",
        ) is True

        after = database.connect().execute(
            "SELECT COUNT(*) FROM sessions"
        ).fetchone()[0]

        assert before == after == 0
    finally:
        database.shutdown()


def test_password_verification_rejects_incorrect_password(tmp_path):
    database, identity = create_identity(tmp_path)

    try:
        user = identity.register(
            email="wrong-password@example.com",
            password="safe-password-123",
            display_name=None,
        )

        assert identity.verify_password(
            user_id=user["id"],
            password="incorrect-password",
        ) is False
    finally:
        database.shutdown()


def test_password_verification_rejects_unknown_user(tmp_path):
    database, identity = create_identity(tmp_path)

    try:
        assert identity.verify_password(
            user_id="unknown-user",
            password="safe-password-123",
        ) is False
    finally:
        database.shutdown()


def test_password_verification_rejects_deleted_user(tmp_path):
    database, identity = create_identity(tmp_path)

    try:
        user = identity.register(
            email="deleted-reauth@example.com",
            password="safe-password-123",
            display_name=None,
        )

        identity.delete_user(user["id"])

        assert identity.verify_password(
            user_id=user["id"],
            password="safe-password-123",
        ) is False
    finally:
        database.shutdown()
