from fastapi import APIRouter

from backend.app.api.v1.agli import router as agli_router
from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.intelligence import router as intelligence_router
from backend.app.api.v1.providers import router as providers_router


api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(agli_router, prefix="/agli")
api_router.include_router(providers_router)
api_router.include_router(intelligence_router)
