from fastapi import APIRouter

from backend.app.api.v1.agli import router as agli_router
from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.intelligence import router as intelligence_router
from backend.app.api.v1.providers import router as providers_router
from backend.app.api.v1.auth import router as auth_router
from backend.app.api.v1.personal import router as personal_router
from backend.app.api.v1.tools import router as tools_router


api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(agli_router, prefix="/agli")
api_router.include_router(providers_router)
api_router.include_router(intelligence_router)
api_router.include_router(auth_router)
api_router.include_router(personal_router)
api_router.include_router(tools_router)
