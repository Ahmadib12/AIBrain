from fastapi import APIRouter, Depends, HTTPException

from backend.app.agli.contracts import (
    LanguageDetectionRequest,
    LanguageDetectionResult,
    TranslationRequest,
    TranslationResult,
)
from backend.app.agli.core import AGLI
from backend.app.agli.execution import (
    LanguageCapabilityUnavailableError,
    LanguageEngineExecutionError,
    LanguageEngineExecutor,
)
from backend.app.agli.registry import language_registry
from backend.app.agli.schemas import LanguageEntry
from backend.app.api.v1.auth import get_current_user
from backend.app.app_state import get_app_state
from backend.app.concurrency import require_ai_capacity


router = APIRouter(tags=["agli"])
agli = AGLI(language_registry)


@router.get("/languages", response_model=list[LanguageEntry])
async def list_languages() -> list[LanguageEntry]:
    return list(agli.list_languages())


@router.get("/languages/{code}", response_model=LanguageEntry)
async def get_language(code: str) -> LanguageEntry:
    language = agli.lookup(code)
    if language is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "LANGUAGE_NOT_FOUND",
                "message": f"Language '{code}' is not registered",
            },
        )
    return language


@router.post("/language/detect", response_model=LanguageDetectionResult)
async def detect_language(
    request: LanguageDetectionRequest,
    _user: dict = Depends(get_current_user),
    _capacity: None = Depends(require_ai_capacity, scope="request"),
) -> LanguageDetectionResult:
    executor = LanguageEngineExecutor(get_app_state().agli_engines)
    try:
        return await executor.detect(request)
    except LanguageCapabilityUnavailableError:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "LANGUAGE_DETECTION_UNAVAILABLE",
                "message": "No available engine satisfies the request policy",
            },
        ) from None
    except LanguageEngineExecutionError:
        raise HTTPException(
            status_code=502,
            detail={
                "code": "LANGUAGE_DETECTION_FAILED",
                "message": "The language detection engine failed its result contract",
            },
        ) from None


@router.post("/language/translate", response_model=TranslationResult)
async def translate_text(
    request: TranslationRequest,
    _user: dict = Depends(get_current_user),
    _capacity: None = Depends(require_ai_capacity, scope="request"),
) -> TranslationResult:
    executor = LanguageEngineExecutor(get_app_state().agli_engines)
    try:
        return await executor.translate(request)
    except LanguageCapabilityUnavailableError:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "TEXT_TRANSLATION_UNAVAILABLE",
                "message": "No available engine satisfies the request policy",
            },
        ) from None
    except LanguageEngineExecutionError:
        raise HTTPException(
            status_code=502,
            detail={
                "code": "TEXT_TRANSLATION_FAILED",
                "message": "The translation engine failed its result contract",
            },
        ) from None
