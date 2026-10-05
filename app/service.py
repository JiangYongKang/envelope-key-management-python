"""FastAPI HTTP entry point exposing the KeyManager with consistent errors.

Every failure is rendered as::

    {"error": {"code": "<ERROR_CODE>", "message": "...", "key_version": "..."}}

with a stable HTTP status, so HTTP callers see the same classification that
library callers do. No key material or plaintext is ever returned.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .errors import ErrorCode, KeyManagementError
from .manager import KeyManager

ManagerProvider = Callable[[], KeyManager]

# Every classified error has an explicit, intentional HTTP status.
_STATUS_BY_CODE: dict[ErrorCode, int] = {
    ErrorCode.CONFIG_INVALID: 503,
    ErrorCode.KEY_ID_MISMATCH: 409,
    ErrorCode.KEY_VERSION_NOT_FOUND: 404,
    ErrorCode.KEY_REVOKED: 409,
    ErrorCode.KEY_DEACTIVATED: 409,
    ErrorCode.CONTEXT_MISMATCH: 409,
    ErrorCode.CIPHERTEXT_INVALID: 400,
    ErrorCode.CIPHERTEXT_TAMPERED: 409,
    ErrorCode.ROTATION_RACE: 409,
    ErrorCode.AUDIT_WRITE_FAILED: 500,
    ErrorCode.STATE_PERSIST_FAILED: 500,
    ErrorCode.STATE_INCONSISTENT: 503,
    ErrorCode.NO_ACTIVE_KEY: 503,
    ErrorCode.INVALID_LIFECYCLE_TRANSITION: 409,
}


class EncryptRequest(BaseModel):
    plaintext: str = Field(min_length=0, description="UTF-8 plaintext to encrypt")
    context: dict[str, str] = Field(default_factory=dict)
    encoding: str = Field(default="utf-8", description="plaintext text encoding (always utf-8)")


class DecryptRequest(BaseModel):
    ciphertext: str = Field(min_length=1, description="envelope token from /encrypt")
    context: dict[str, str] = Field(default_factory=dict)


class RotateRequest(BaseModel):
    expected_version: str | None = Field(
        default=None, description="optimistic guard: current must equal this"
    )


class VersionAction(BaseModel):
    version: str = Field(min_length=1)


class MigrateRequest(BaseModel):
    ciphertexts: list[str] = Field(
        min_length=1, description="envelope tokens to re-encrypt onto the current version"
    )
    context: dict[str, str] | None = Field(
        default=None,
        description="optional guard: items whose bound context differs fail "
                    "with CONTEXT_MISMATCH; omitted keeps each token's context",
    )


def create_app(
    manager_provider: ManagerProvider,
    *,
    lifespan: Any | None = None,
) -> FastAPI:
    """Create the HTTP application backed by a fully configured manager."""
    app = FastAPI(
        title="Local Envelope Key Management",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.exception_handler(KeyManagementError)
    async def _classified_error_handler(_request, exc: KeyManagementError):
        status = _STATUS_BY_CODE.get(exc.code, 500)
        return JSONResponse(
            status_code=status,
            content={
                "error": {
                    "code": exc.code.value,
                    "message": exc.message,
                    "key_version": exc.key_version,
                }
            },
        )

    @app.get("/health")
    async def health():
        manager = manager_provider()
        return {
            "status": "ok",
            "key_id": manager.key_id,
            "current_version": manager.current_version(),
        }

    @app.get("/keys/versions")
    async def list_versions():
        manager = manager_provider()
        return {
            "key_id": manager.key_id,
            "current_version": manager.current_version(),
            "versions": [
                {
                    "version": v.version,
                    "state": v.state.value,
                    "is_current": v.is_current,
                    "created_at": v.created_at,
                }
                for v in manager.list_versions()
            ],
        }

    @app.post("/keys/rotate", status_code=201)
    async def rotate(body: RotateRequest):
        manager = manager_provider()
        version = manager.rotate(expected_version=body.expected_version)
        return {"current_version": version}

    @app.post("/keys/deactivate")
    async def deactivate(body: VersionAction):
        manager = manager_provider()
        manager.deactivate(body.version)
        return {"version": body.version, "state": "DEACTIVATED"}

    @app.post("/keys/revoke")
    async def revoke(body: VersionAction):
        manager = manager_provider()
        manager.revoke(body.version)
        return {"version": body.version, "state": "REVOKED"}

    @app.post("/keys/migrate")
    async def migrate(body: MigrateRequest):
        """Re-encrypt a batch of tokens onto the current ACTIVE version.

        Always 200 with a per-item report: every input token is classified
        as MIGRATED / ALREADY_CURRENT / FAILED (with its error code), so a
        partially failing batch is never reported as uniformly successful.
        """
        manager = manager_provider()
        report = manager.migrate(body.ciphertexts, body.context)
        return report.to_dict()

    @app.post("/encrypt")
    async def encrypt(body: EncryptRequest):
        manager = manager_provider()
        token = manager.encrypt(body.plaintext, body.context)
        return {"ciphertext": token, "key_version": manager.current_version()}

    @app.post("/decrypt")
    async def decrypt(body: DecryptRequest):
        manager = manager_provider()
        plaintext = manager.decrypt(body.ciphertext, body.context)
        return {"plaintext": plaintext.decode("utf-8")}

    return app
