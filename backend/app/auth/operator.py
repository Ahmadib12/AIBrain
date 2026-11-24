import hmac

from fastapi import Depends, Header, HTTPException

from backend.app.config import get_settings
from backend.app.api.v1.auth import get_current_user


def require_provider_operator(
    token: str | None = Header(
        default=None,
        alias="X-AIBrain-Operator-Token",
    ),
) -> None:
    configured_token = get_settings().provider_operator_token

    if configured_token is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "OPERATOR_AUTH_NOT_CONFIGURED",
                "message": "Provider operator access is not configured",
            },
        )

    expected = configured_token.get_secret_value()
    supplied = token or ""

    if not hmac.compare_digest(
        supplied.encode("utf-8"),
        expected.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "OPERATOR_UNAUTHORIZED",
                "message": "A valid provider operator token is required",
            },
        )



def require_trusted_runner_ingest(
    token: str | None = Header(
        default=None,
        alias="X-AIBrain-Runner-Token",
    ),
) -> None:
    """Authenticate the isolated runner ingestion channel.

    This credential cannot register/revoke signing keys or approve adapter
    certifications; those operations use the separate operator credential.
    """
    configured_token = get_settings().trusted_runner_ingest_token
    if configured_token is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "RUNNER_INGEST_AUTH_NOT_CONFIGURED",
                "message": "Trusted runner ingestion is not configured",
            },
        )
    expected = configured_token.get_secret_value()
    supplied = token or ""
    if not hmac.compare_digest(
        supplied.encode("utf-8"),
        expected.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "RUNNER_INGEST_UNAUTHORIZED",
                "message": "A valid trusted runner token is required",
            },
        )



def require_security_operator(
    user: dict = Depends(get_current_user),
) -> dict:
    """Authorize an individually authenticated account on the security-operator allowlist."""
    configured = get_settings().security_operator_emails
    allowed = {
        item.strip().lower()
        for item in configured.split(",")
        if item.strip()
    }
    email = user.get("email")
    if not isinstance(email, str) or email.strip().lower() not in allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "SECURITY_OPERATOR_FORBIDDEN",
                "message": "This authenticated account is not a security operator",
            },
        )
    return user
