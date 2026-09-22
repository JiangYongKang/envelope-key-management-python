"""HTTP 入口：FastAPI 路由与统一错误响应。

所有业务错误经 :class:`app.errors.KMSError` 统一转换为
``{"error": {code,message,key_version}}`` 与稳定 HTTP 状态码，使 HTTP 入口
与直接调用 SDK 的结论完全一致。
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import (
    Settings,
    build_manager,
    build_settings_from_env,
)
from app.errors import (
    ConfigInvalidError,
    KMSError,
    KeyStoreEmptyError,
    http_status_for,
)
from app.manager import KeyManager
from app.models import Envelope, KeyStatus

app = FastAPI(title="local-envelope-kms", version="0.1.0")


@asynccontextmanager
async def lifespan(_: FastAPI):
    # 显式调用 configure() 优先；否则按环境变量装配。
    if getattr(app.state, "manager", None) is None:
        configure(build_settings_from_env())
    yield


app.router.lifespan_context = lifespan


def configure(settings: Settings) -> KeyManager:
    """在应用启动时装配 Manager（配置非法将直接抛出，拒绝启用）。"""
    manager = build_manager(settings)
    app.state.manager = manager
    return manager


def get_manager() -> KeyManager:
    manager = getattr(app.state, "manager", None)
    if manager is None:
        raise KMSError("密钥能力尚未启用：缺少本地密钥配置")
    return manager


@app.exception_handler(KMSError)
def _kms_error_handler(_: Request, exc: KMSError) -> JSONResponse:
    return JSONResponse(
        status_code=http_status_for(exc.code),
        content={"error": exc.to_dict()},
    )


@app.exception_handler(Exception)
def _unexpected_error_handler(_: Request, exc: Exception) -> JSONResponse:
    # 不泄露内部细节；审计日志中已有具体信息。
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "内部错误",
                "key_version": None,
            }
        },
    )


from pydantic import BaseModel  # noqa: E402


class EncryptRequest(BaseModel):
    plaintext: str
    context: dict[str, str] = {}
    key_version: int | None = None


class DecryptRequest(BaseModel):
    envelope: dict
    context: dict[str, str] = {}


class StatusRequest(BaseModel):
    version: int
    status: str  # enabled / disabled / revoked


@app.post("/encrypt")
def encrypt(req: EncryptRequest) -> dict:
    manager = get_manager()
    envelope = manager.encrypt(
        req.plaintext.encode("utf-8"),
        context=req.context,
        key_version=req.key_version,
    )
    return {"envelope": envelope.to_dict()}


@app.post("/decrypt")
def decrypt(req: DecryptRequest) -> dict:
    manager = get_manager()
    envelope = Envelope.from_dict(req.envelope)
    plaintext = manager.decrypt(envelope, expected_context=req.context)
    return {"plaintext": plaintext.decode("utf-8")}


@app.post("/rotate")
def rotate() -> dict:
    manager = get_manager()
    kv = manager.rotate()
    return {"key_version": kv.version, "status": kv.status.value}


@app.post("/keys/status")
def set_key_status(req: StatusRequest) -> dict:
    try:
        status = KeyStatus(req.status)
    except ValueError:
        raise ConfigInvalidError(f"未知密钥状态: {req.status!r}")
    manager = get_manager()
    kv = manager.set_status(req.version, status)
    return {"key_version": kv.version, "status": kv.status.value}


@app.get("/keys")
def list_keys() -> dict:
    manager = get_manager()
    versions = manager.versions
    if not versions:
        raise KeyStoreEmptyError("密钥库为空：尚未配置或引导任何密钥版本")
    return {
        "latest_version": max(manager.versions),
        "versions": [
            {
                "version": kv.version,
                "status": kv.status.value,
                "created_at": kv.created_at,
            }
            for kv in sorted(manager.versions.values(), key=lambda k: k.version)
        ],
    }
