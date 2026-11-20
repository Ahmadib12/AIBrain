from fastapi import APIRouter, HTTPException

from backend.app.agli.core import AGLI
from backend.app.agli.registry import language_registry
from backend.app.agli.schemas import LanguageEntry


router = APIRouter(prefix="/languages", tags=["agli"])
agli = AGLI(language_registry)


@router.get("", response_model=list[LanguageEntry])
async def list_languages() -> list[LanguageEntry]:
    return list(agli.list_languages())


@router.get("/{code}", response_model=LanguageEntry)
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
