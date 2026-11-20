from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def versioned_health() -> dict[str, str]:
    return {"status": "ok", "api_version": "v1"}
