import sqlite3

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from backend.app.app_state import get_app_state
from backend.app.config import get_settings
from backend.app.auth.rate_limit import LoginRateLimiter


router = APIRouter(prefix="/auth", tags=["auth"])
_settings = get_settings()
_login_rate_limiter = LoginRateLimiter(
    _settings.login_rate_limit_attempts,
    _settings.login_rate_limit_window_seconds,
)
_registration_rate_limiter = LoginRateLimiter(
    _settings.login_rate_limit_attempts,
    _settings.login_rate_limit_window_seconds,
)
_reauth_rate_limiter = LoginRateLimiter(
    _settings.login_rate_limit_attempts,
    _settings.login_rate_limit_window_seconds,
)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=128)
    display_name: str | None = Field(default=None, max_length=150)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)


class AuthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    user: dict


class PasskeyAuthenticationOptionsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)


class PasskeyAuthenticationVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)
    challenge_record_id: str = Field(min_length=1, max_length=128)
    assertion: dict


class PasskeyRegistrationOptionsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=128)


class PasskeyRegistrationVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_record_id: str = Field(min_length=1, max_length=128)
    credential: dict
    name: str | None = Field(default=None, max_length=128)


def get_current_user(
    authorization: str | None = Header(default=None),
) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "UNAUTHORIZED",
                "message": "A valid bearer token is required",
            },
        )
    token = authorization[len("Bearer "):].strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "UNAUTHORIZED",
                "message": "A valid bearer token is required",
            },
        )
    try:
        return get_app_state().identity.resolve_token(token)
    except LookupError:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "UNAUTHORIZED",
                "message": "The session is invalid or expired",
            },
        ) from None


@router.post("/register", response_model=dict)
async def register(
    request: RegisterRequest,
    http_request: Request,
) -> dict:
    client = http_request.client
    if client is None or not client.host:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "CLIENT_ADDRESS_UNAVAILABLE",
                "message": "Registration is temporarily unavailable",
            },
        )

    rate_limit_key = client.host
    if not _registration_rate_limiter.check_and_record(rate_limit_key):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "REGISTRATION_RATE_LIMITED",
                "message": "Too many registration attempts",
            },
        )


    try:
        user = get_app_state().identity.register(
            email=request.email,
            password=request.password,
            display_name=request.display_name,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_REGISTRATION",
                "message": str(error),
            },
        ) from None
    return {"user": user}


@router.post("/login", response_model=AuthResponse)
async def login(request: LoginRequest) -> AuthResponse:
    key = request.email.strip().lower()
    if not _login_rate_limiter.check_and_record(key):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "LOGIN_RATE_LIMITED",
                "message": "Too many login attempts",
            },
        )
    try:
        user, token = get_app_state().identity.authenticate(
            email=request.email,
            password=request.password,
        )
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "INVALID_CREDENTIALS",
                "message": "Invalid email or password",
            },
        ) from None
    _login_rate_limiter.reset(key)
    return AuthResponse(access_token=token, user=user)


@router.post("/passkeys/registration/options", response_model=dict)
async def create_passkey_registration_options(
    request: PasskeyRegistrationOptionsRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    key = user["email"].strip().lower()

    if not _reauth_rate_limiter.check_and_record(key):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "REAUTHENTICATION_RATE_LIMITED",
                "message": "Too many password confirmation attempts",
            },
        )

    state = get_app_state()
    if not state.identity.verify_password(
        user_id=user["id"],
        password=request.password,
    ):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "REAUTHENTICATION_REQUIRED",
                "message": "Password confirmation failed",
            },
        )

    _reauth_rate_limiter.reset(key)
    service = state.webauthn_service
    try:
        return service.create_registration_options(
            user_id=user["id"],
            user_name=user["email"],
            user_display_name=user.get("display_name") or user["email"],
        )
    except PermissionError as error:
        if str(error) == "WebAuthn is not enabled or configured":
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "WEBAUTHN_UNAVAILABLE",
                    "message": "Passkey registration is not currently available",
                },
            ) from None
        raise HTTPException(
            status_code=400,
            detail={
                "code": "WEBAUTHN_REGISTRATION_REJECTED",
                "message": "Passkey registration could not be started",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_PASSKEY_REGISTRATION",
                "message": "Passkey registration details are invalid",
            },
        ) from None


@router.post("/passkeys/registration/verify", response_model=dict)
async def verify_passkey_registration(
    request: PasskeyRegistrationVerifyRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    service = get_app_state().webauthn_service
    try:
        credential = service.verify_registration(
            user_id=user["id"],
            challenge_record_id=request.challenge_record_id,
            credential=request.credential,
            name=request.name,
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "WEBAUTHN_CHALLENGE_NOT_FOUND",
                "message": "The passkey registration challenge was not found",
            },
        ) from None
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "PASSKEY_ALREADY_REGISTERED",
                "message": "This passkey is already registered",
            },
        ) from None
    except PermissionError as error:
        if str(error) == "WebAuthn is not enabled or configured":
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "WEBAUTHN_UNAVAILABLE",
                    "message": "Passkey registration is not currently available",
                },
            ) from None
        raise HTTPException(
            status_code=400,
            detail={
                "code": "WEBAUTHN_REGISTRATION_REJECTED",
                "message": "Passkey registration could not be verified",
            },
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_PASSKEY_REGISTRATION",
                "message": "Passkey registration details are invalid",
            },
        ) from None

    # Never expose credential IDs, public keys, or internal user identifiers.
    return {
        "passkey": {
            "id": credential["id"],
            "name": credential["name"],
            "device_type": credential["device_type"],
            "backed_up": credential["backed_up"],
            "created_at": credential["created_at"],
            "transports": credential["transports"],
        }
    }


@router.post(
    "/passkeys/authentication/options",
    response_model=dict,
)
async def create_passkey_authentication_options(
    request: PasskeyAuthenticationOptionsRequest,
) -> dict:
    key = request.email.strip().lower()

    if not _login_rate_limiter.check_and_record(key):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "LOGIN_RATE_LIMITED",
                "message": "Too many login attempts",
            },
        )

    state = get_app_state()
    user = state.identity.get_user_by_email(key)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "INVALID_PASSKEY_CREDENTIALS",
                "message": "Passkey sign-in could not be started",
            },
        )

    try:
        options = state.webauthn_service.create_authentication_options(
            user_id=user["id"],
        )
        return options
    except PermissionError as error:
        if str(error) == "WebAuthn is not enabled or configured":
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "WEBAUTHN_UNAVAILABLE",
                    "message": "Passkey sign-in is not currently available",
                },
            ) from None

        raise HTTPException(
            status_code=401,
            detail={
                "code": "INVALID_PASSKEY_CREDENTIALS",
                "message": "Passkey sign-in could not be started",
            },
        ) from None
    except (ValueError, LookupError):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "INVALID_PASSKEY_CREDENTIALS",
                "message": "Passkey sign-in could not be started",
            },
        ) from None


@router.post(
    "/passkeys/authentication/verify",
    response_model=AuthResponse,
)
async def verify_passkey_authentication(
    request: PasskeyAuthenticationVerifyRequest,
) -> AuthResponse:
    key = request.email.strip().lower()

    if not _login_rate_limiter.check_and_record(key):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "LOGIN_RATE_LIMITED",
                "message": "Too many login attempts",
            },
        )

    state = get_app_state()
    user = state.identity.get_user_by_email(key)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "INVALID_PASSKEY_CREDENTIALS",
                "message": "Invalid passkey credentials",
            },
        )

    try:
        state.webauthn_service.verify_authentication(
            user_id=user["id"],
            challenge_record_id=request.challenge_record_id,
            assertion=request.assertion,
        )
        authenticated_user, token = state.identity.create_session(user["id"])
    except PermissionError as error:
        if str(error) == "WebAuthn is not enabled or configured":
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "WEBAUTHN_UNAVAILABLE",
                    "message": "Passkey sign-in is not currently available",
                },
            ) from None

        raise HTTPException(
            status_code=401,
            detail={
                "code": "INVALID_PASSKEY_CREDENTIALS",
                "message": "Invalid passkey credentials",
            },
        ) from None
    except (LookupError, ValueError):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "INVALID_PASSKEY_CREDENTIALS",
                "message": "Invalid passkey credentials",
            },
        ) from None

    _login_rate_limiter.reset(key)
    return AuthResponse(access_token=token, user=authenticated_user)


@router.post("/logout")
async def logout(
    authorization: str | None = Header(default=None),
) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "UNAUTHORIZED",
                "message": "A valid bearer token is required",
            },
        )
    token = authorization[len("Bearer "):].strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "UNAUTHORIZED",
                "message": "A valid bearer token is required",
            },
        )
    get_app_state().identity.revoke_token(token)
    return {"status": "logged_out"}


@router.get("/me", response_model=dict)
async def me(user: dict = Depends(get_current_user)) -> dict:
    return {"user": user}


@router.delete("/me")
async def delete_account(
    user: dict = Depends(get_current_user),
) -> dict:
    get_app_state().identity.delete_user(user["id"])
    return {"deleted": True}
