"""Liveness and readiness."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from envelock.config import get_settings

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    version: str
    env: str


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(status="ok", version="0.1.0", env=settings.env)
