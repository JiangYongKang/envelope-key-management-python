"""uvicorn entry point: ``uv run uvicorn main:app``.

The envelope-encryption capability is only enabled when explicit *local*
configuration is provided (EKM_CONFIG_FILE or EKM_INLINE_KEYS). Missing or
incomplete configuration aborts application startup with ConfigurationError
instead of silently using a default key.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import build_manager, load_settings
from app.manager import KeyManager
from app.service import create_app

_holder: dict[str, KeyManager] = {}


def _manager_provider() -> KeyManager:
    return _holder["manager"]


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Raises ConfigurationError on missing/incomplete config -> startup aborts.
    _holder["manager"] = build_manager(load_settings())
    yield


app: FastAPI = create_app(_manager_provider, lifespan=lifespan)
