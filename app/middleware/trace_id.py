import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

HEADER_NAME = "x-trace-id"


class TraceIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        trace_id = request.headers.get(HEADER_NAME) or str(uuid.uuid4())
        request.state.trace_id = trace_id
        response: Response = await call_next(request)
        response.headers[HEADER_NAME] = trace_id
        return response
