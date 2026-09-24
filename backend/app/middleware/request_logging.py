"""Request logging middleware."""

import logging
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.constants import HEADER_REQUEST_ID

logger = logging.getLogger("asoc.request")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get(HEADER_REQUEST_ID, str(uuid.uuid4()))

        logger.info("--> %s %s [%s]", request.method, request.url.path, request_id)

        response = await call_next(request)

        logger.info(
            "<-- %s %s [%s] status=%s",
            request.method,
            request.url.path,
            request_id,
            response.status_code,
        )
        response.headers[HEADER_REQUEST_ID] = request_id
        return response
