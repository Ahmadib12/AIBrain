"""Real PostgreSQL WebAuthn concurrency acceptance tests.

Set AIBRAIN_POSTGRES_TEST_URL to a dedicated PostgreSQL test database.
"""
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from uuid import uuid4

import pytest

from backend.app.persistence.postgres.database import PostgresDatabase
from backend.app.persistence.postgres.migrations import PostgresMigrationRunner
from backend.app.persistence.webauthn import WebAuthnRepository


def _database_url():
    value = os.getenv("AIBRAIN_POSTGRES_TEST_URL")
    if not value:
        pytest.skip(
            "set AIBRAIN_POSTGRES_TEST_URL for a dedicated PostgreSQL test database"
        )
    pytest.importorskip("psycopg")
    return value


def _create_user(database_url):
    import psycopg

    user_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with psycopg.connect(database_url) as connection:
        connection.execute(
            """
            INSERT INTO users (
                id, email, password_salt, password_hash, created_at
            ) VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, f"webauthn-{user_id}@example.invalid", "salt", "hash", now),
        )
    return user_id


def _delete_user(database_url, user_id):
    import psycopg

    with psycopg.connect(database_url) as connection:
        # Test-only cleanup of the rows created by these isolated fixtures.
        connection.execute(
            "DELETE FROM webauthn_challenges WHERE user_id=%s", (user_id,)
        )
        connection.execute(
            "DELETE FROM webauthn_recovery_codes WHERE user_id=%s", (user_id,)
        )
        connection.execute(
            "DELETE FROM webauthn_credentials WHERE user_id=%s", (user_id,)
        )
        connection.execute("DELETE FROM users WHERE id=%s", (user_id,))


def _challenge(repository, user_id, purpose="authentication"):
    return repository.create_challenge(
        user_id=user_id,
        challenge_hash=hashlib.sha256(uuid4().bytes).hexdigest(),
        purpose=purpose,
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    )


def test_real_postgres_concurrent_authentication_preserves_monotonic_sign_counter():
    database_url = _database_url()
    assert PostgresMigrationRunner(database_url).migrate() == 36
    user_id = _create_user(database_url)
    database = PostgresDatabase(database_url)
    repository = WebAuthnRepository(database)
    credential = repository.create_credential(
        user_id=user_id,
        credential_id=f"credential-{uuid4()}",
        public_key=b"test-public-key",
        sign_count=0,
    )
    challenges = [_challenge(repository, user_id) for _ in range(2)]
    barrier = Barrier(2)

    def authenticate(index, sign_count):
        barrier.wait(timeout=10)
        try:
            return repository.commit_verified_authentication(
                user_id=user_id,
                challenge_record_id=challenges[index]["id"],
                credential_record_id=credential["id"],
                verified_sign_count=sign_count,
            )
        except PermissionError as error:
            return error

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(authenticate, 0, 1),
                executor.submit(authenticate, 1, 2),
            ]
            outcomes = [future.result(timeout=30) for future in futures]

        successes = [item for item in outcomes if not isinstance(item, Exception)]
        assert len(successes) in (1, 2)
        current = repository.get_credential(user_id, credential["id"])
        assert current["sign_count"] == 2
    finally:
        database.shutdown()
        _delete_user(database_url, user_id)


def test_real_postgres_challenge_is_consumed_by_only_one_concurrent_authentication():
    database_url = _database_url()
    assert PostgresMigrationRunner(database_url).migrate() == 36
    user_id = _create_user(database_url)
    database = PostgresDatabase(database_url)
    repository = WebAuthnRepository(database)
    credential = repository.create_credential(
        user_id=user_id,
        credential_id=f"credential-{uuid4()}",
        public_key=b"test-public-key",
        sign_count=0,
    )
    challenge = _challenge(repository, user_id)
    barrier = Barrier(2)

    def authenticate():
        barrier.wait(timeout=10)
        try:
            return repository.commit_verified_authentication(
                user_id=user_id,
                challenge_record_id=challenge["id"],
                credential_record_id=credential["id"],
                verified_sign_count=1,
            )
        except PermissionError as error:
            return error

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = [future.result(timeout=30) for future in (
                executor.submit(authenticate),
                executor.submit(authenticate),
            )]
        assert sum(not isinstance(item, Exception) for item in outcomes) == 1
        assert sum(isinstance(item, PermissionError) for item in outcomes) == 1
        current = repository.get_credential(user_id, credential["id"])
        assert current["sign_count"] == 1
        assert repository.get_challenge(user_id, challenge["id"])["consumed_at"]
    finally:
        database.shutdown()
        _delete_user(database_url, user_id)


def test_real_postgres_concurrent_recovery_rotation_keeps_one_complete_generation():
    database_url = _database_url()
    assert PostgresMigrationRunner(database_url).migrate() == 36
    user_id = _create_user(database_url)
    database = PostgresDatabase(database_url)
    repository = WebAuthnRepository(database)
    generations = [
        [hashlib.sha256(f"{uuid4()}-{index}".encode()).hexdigest() for index in range(3)]
        for _ in range(2)
    ]
    barrier = Barrier(2)

    def rotate(digests):
        barrier.wait(timeout=10)
        return repository.replace_recovery_codes(user_id, digests)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = [
                executor.submit(rotate, generations[0]),
                executor.submit(rotate, generations[1]),
            ]
            assert [future.result(timeout=30) for future in outcomes] == [3, 3]

        rows = database.connect().execute(
            """
            SELECT code_hash FROM webauthn_recovery_codes
            WHERE user_id = ? AND used_at IS NULL
            ORDER BY code_hash
            """,
            (user_id,),
        ).fetchall()
        active = {row["code_hash"] for row in rows}
        assert active in (set(generations[0]), set(generations[1]))
    finally:
        database.shutdown()
        _delete_user(database_url, user_id)
