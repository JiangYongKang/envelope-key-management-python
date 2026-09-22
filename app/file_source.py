"""基于本地 JSON 文件的密钥来源（原子写入，密钥材料仅落本地磁盘）。"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import tempfile

from app.errors import ConfigInvalidError, KeySourceFailureError
from app.keystore import KEK_SIZE
from app.models import KeyStatus, KeyVersion


class FileKeySource:
    """从本地 JSON 文件读取/写入全部密钥版本。

    - 文件不存在时 :meth:`load` 返回空字典；“空库是否允许启动”由配置层
      显式决定（默认拒绝，绝不使用隐式默认密钥）。
    - 文件存在但内容缺失/不完整/无法解析时，抛出 :class:`ConfigInvalidError`，
      服务拒绝启用。
    - 写入采用临时文件 + fsync + 原子 rename，轮换不会产生半写文件。
    """

    def __init__(self, path: str | pathlib.Path) -> None:
        self.path = pathlib.Path(path)

    def load(self) -> dict[int, KeyVersion]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KeySourceFailureError(
                f"无法读取本地密钥文件 {self.path}: {exc}"
            ) from exc

        if not isinstance(raw, dict) or "versions" not in raw:
            raise ConfigInvalidError(
                f"密钥文件 {self.path} 结构不完整：缺少 versions 字段"
            )

        result: dict[int, KeyVersion] = {}
        for item in raw["versions"]:
            try:
                version = int(item["version"])
                material = base64.b64decode(item["material"], validate=True)
                status = KeyStatus(str(item["status"]))
                created_at = str(item["created_at"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ConfigInvalidError(
                    f"密钥文件 {self.path} 中版本记录不完整或非法: {exc}"
                ) from exc
            if version < 1:
                raise ConfigInvalidError("密钥版本号必须 >= 1")
            if len(material) != KEK_SIZE:
                raise ConfigInvalidError(
                    f"版本 {version} 的密钥材料长度必须为 {KEK_SIZE} 字节"
                )
            if version in result:
                raise ConfigInvalidError(f"版本 {version} 重复定义")
            result[version] = KeyVersion(
                version=version,
                material=material,
                status=status,
                created_at=created_at,
            )
        return result

    def save(self, versions: dict[int, KeyVersion]) -> None:
        payload = {
            "versions": [
                {
                    "version": kv.version,
                    "material": base64.b64encode(kv.material).decode("ascii"),
                    "status": kv.status.value,
                    "created_at": kv.created_at,
                }
                for kv in sorted(versions.values(), key=lambda k: k.version)
            ]
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
                    fh.write("\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_name, self.path)
            except BaseException:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass
                raise
        except OSError as exc:
            raise KeySourceFailureError(
                f"无法写入本地密钥文件 {self.path}: {exc}"
            ) from exc
