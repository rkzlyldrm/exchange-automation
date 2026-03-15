"""
Service-to-service API key authentication middleware.
"""
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from src.config import settings

logger = logging.getLogger(__name__)


class ServiceKeyMiddleware(BaseHTTPMiddleware):
    """Validate X-Service-Key header on all /api/* requests."""

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        expected_key = settings.SERVICE_API_KEY
        if not expected_key:
            logger.warning("SERVICE_API_KEY not configured — allowing request without auth")
            return await call_next(request)

        provided_key = request.headers.get("X-Service-Key", "")
        if not provided_key:
            return JSONResponse(
                status_code=403,
                content={"detail": "Missing X-Service-Key header"},
            )
        if provided_key != expected_key:
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid service key"},
            )

        return await call_next(request)
