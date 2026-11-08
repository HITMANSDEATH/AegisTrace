"""Explicit browser-origin policy, including unhandled error responses."""
from contextlib import asynccontextmanager
import logging
import os
from urllib.parse import urlsplit

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

DEFAULT_ORIGINS = (
    "http://localhost:3000,http://127.0.0.1:3000,"
    "http://localhost:5173,http://127.0.0.1:5173,"
    "http://localhost:8080,http://127.0.0.1:8080"
)
logger = logging.getLogger("uvicorn.error")


def allowed_origins():
    value = os.getenv("ALLOWED_ORIGINS", DEFAULT_ORIGINS).strip()
    if value == "*":
        return ["*"]
    origins = []
    for item in value.split(","):
        origin = item.strip().rstrip("/")
        if not origin:
            continue
        try:
            parsed = urlsplit(origin)
            valid = (
                parsed.scheme in ("http", "https")
                and parsed.hostname
                and parsed.username is None
                and parsed.password is None
                and not parsed.path
                and not parsed.query
                and not parsed.fragment
                and not any(char.isspace() for char in origin)
                and "*" not in origin
            )
            parsed.port  # Reject malformed ports without logging the input.
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("ALLOWED_ORIGINS must contain scheme://host[:port] origins only")
        if origin not in origins:
            origins.append(origin)
    return origins


class BrowserAPI(FastAPI):
    """Keep the FastAPI interface while wrapping its entire error stack in CORS."""

    def __init__(self, *args, **kwargs):
        self.browser_origins = allowed_origins()
        service_lifespan = kwargs.pop("lifespan", None)

        @asynccontextmanager
        async def lifespan(app):
            logger.info("Allowed browser origins: %s", self.browser_origins)
            if self.browser_origins == ["*"]:
                logger.warning("ALLOWED_ORIGINS=* permits every browser origin; credentials remain disabled")
            if service_lifespan is None:
                yield
            else:
                async with service_lifespan(app):
                    yield

        super().__init__(*args, lifespan=lifespan, **kwargs)

    def build_middleware_stack(self):
        # Outside ServerErrorMiddleware so even an unhandled 500 retains CORS.
        return CORSMiddleware(
            super().build_middleware_stack(),
            allow_origins=self.browser_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization"],
            expose_headers=[],
            max_age=600,
        )
