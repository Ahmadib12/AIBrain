import hmac

from fastapi import Header, HTTPException

from backend.app.config import get_settings


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
