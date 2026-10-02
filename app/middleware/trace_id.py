from collections.abc import Awaitable, Callable
from typing import Final

from fastapi import Request, Response
from opentelemetry import trace
from starlette.middleware.base import BaseHTTPMiddleware

HEADER_NAME: Final[str] = "x-trace-id"


class TraceIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)

        span_context = trace.get_current_span().get_span_context()
        if span_context.is_valid:
            response.headers[HEADER_NAME] = trace.format_trace_id(span_context.trace_id)

        return response
