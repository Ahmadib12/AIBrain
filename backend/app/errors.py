import logging
from inspect import signature

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


_SAFE_VALIDATION_LOCATION_PARTS = frozenset({
    "body",
    "query",
    "path",
    "header",
    "cookie",
    "messages",
    "role",
    "content",
    "context_id",
    "task_type",
    "language_code",
    "provider",
    "model",
    "allow_fallback",
    "metadata",
    "code",
    "provider_id",
})


def _safe_validation_location(location: tuple[object, ...]) -> list[str | int]:
    return [
        part
        if isinstance(part, int)
        else part
        if isinstance(part, str) and part in _SAFE_VALIDATION_LOCATION_PARTS
        else "<field>"
        for part in location
    ]


def _safe_validation_details(
    exc: RequestValidationError,
) -> list[dict[str, str | list[str | int]]]:
    error_method = exc.errors
    available_options = signature(error_method).parameters
    excluded_options = {
        option: False
        for option in ("include_input", "include_context", "include_url")
        if option in available_options
    }
    return [
        {
            "type": str(error.get("type", "validation_error")),
            "loc": _safe_validation_location(tuple(error.get("loc", ()))),
        }
        for error in error_method(**excluded_options)
    ]


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def http_error_handler(
        request: Request, exc: HTTPException
    ) -> JSONResponse:
        if isinstance(exc.detail, dict):
            code = exc.detail.get("code", "HTTP_ERROR")
            message = exc.detail.get("message", str(exc.detail))
            details = {
                key: value
                for key, value in exc.detail.items()
                if key not in {"code", "message"}
            }
        else:
            code = "HTTP_ERROR"
            message = str(exc.detail)
            details = {}
        error = {
            "code": code,
            "message": message,
            "path": str(request.url.path),
        }
        error.update(details)
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": error},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details = _safe_validation_details(exc)
        logging.getLogger("aibrain.errors").warning(
            "Request validation failed: %s",
            details,
        )
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Request validation failed",
                    "details": details,
                }
            },
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logging.getLogger("aibrain.errors").error(
            "Unhandled application error (%s)",
            type(exc).__name__,
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected error occurred",
                    "path": str(request.url.path),
                }
            },
        )
