"""本地启动入口：uvicorn main:app。"""

from app.service import app

__all__ = ["app"]
