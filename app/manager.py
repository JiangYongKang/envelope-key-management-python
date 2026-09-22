"""密钥管理核心：版本化信封加密、轮换与生命周期、并发控制、审计一致性。

并发模型
--------
- ``_lock``（RLock）保护全部状态变更（轮换、停用、撤销、启用）与加载；
- 状态字典采用 copy-on-write：变更时构造新字典再整体替换引用，因此并发
  解密拿到的永远是某一个一致快照，轮换进行中也不会读到“半套”密钥；
- 轮换额外使用 ``_rotate_guard`` 做并发收敛：同一时刻发起的多个轮换请求
  只会产生一个新版本，其余调用等待并共享该结果，杜绝重复轮换。

审计一致性
----------
每个操作只有在有了确定结论后才写一条审计：成功记 success，拒绝/失败记
success=False 与对应错误码。审计落盘是操作完成的必要条件：审计写失败时，
加密/解密直接按失败返回；变更类操作回滚状态后按失败返回。
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from app import crypto
from app.audit import Auditer
from app.errors import (
    AuditFailureError,
    ConfigInvalidError,
    KeyDisabledError,
    KeyRevokedError,
    KeyStoreEmptyError,
    KeyVersionNotFoundError,
)
from app.keystore import (
    KeySource,
    generate_version,
    next_version,
    transition,
)
from app.models import Envelope, KeyStatus, KeyVersion


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class _RotationFlight:
    """一次在途轮换：跟随者登记并共享领队的成功结果或失败异常。

    领队在真正执行轮换前开启一个固定注册窗口 ``_REGISTER_WINDOW``，
    让同时到达（例如由同一屏障释放）的调用方都登记为跟随者，从而保证
    一批并发轮换只产生一个新版本。轮换是低频管理操作，固定窗口可接受。
    """

    _REGISTER_WINDOW = 0.05

    def __init__(self) -> None:
        self.result: KeyVersion | None = None
        self.error: BaseException | None = None
        self.settled = False
        self.joiners = 0

    def settle(self, *, result: KeyVersion | None = None,
               error: BaseException | None = None) -> None:
        self.result = result
        self.error = error
        self.settled = True


class KeyManager:
    """线程安全的本地信封加密管理器（copy-on-write 状态快照）。"""

    def __init__(self, source: KeySource, auditer: Auditer) -> None:
        self._source = source
        self._auditer = auditer
        self._lock = threading.RLock()
        self._versions: dict[int, KeyVersion] = {}
        # 轮换收敛：条件变量保护在途轮换；跟随者登记后等待并共享结果。
        self._rotate_cond = threading.Condition()
        self._rotate_in_flight: "_RotationFlight | None" = None

    # ------------------------------------------------------------------
    # 生命周期装配
    # ------------------------------------------------------------------

    def load(self) -> None:
        """从本地来源加载密钥版本并校验完整性。"""
        with self._lock:
            loaded = self._source.load()
            self._validate_bundle(loaded)
            # 整体替换引用：读者要么看到旧快照，要么看到新快照。
            self._versions = loaded

    @staticmethod
    def _validate_bundle(versions: dict[int, KeyVersion]) -> None:
        if not versions:
            return
        if set(versions) != set(range(1, max(versions) + 1)):
            raise ConfigInvalidError(
                f"密钥版本集合必须从 1 起连续，实际版本: {sorted(versions)}"
            )
        for kv in versions.values():
            if kv.version < 1 or len(kv.material) != 32:
                raise ConfigInvalidError(
                    f"版本 {kv.version} 非法：版本号 >= 1 且材料为 32 字节"
                )

    def bootstrap(self) -> KeyVersion:
        """在空库中创建第一个密钥版本（仅显式调用时）。"""
        with self._lock:
            if self._versions:
                return self._versions[max(self._versions)]
            return self._create_locked()

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    @property
    def versions(self) -> dict[int, KeyVersion]:
        return dict(self._versions)

    def latest_version(self) -> int:
        snapshot = self._versions
        if not snapshot:
            raise KeyStoreEmptyError("密钥库为空：尚未配置或引导任何密钥版本")
        return max(snapshot)

    # ------------------------------------------------------------------
    # 内部：取版本与状态判定
    # ------------------------------------------------------------------

    def _require_version(self, version: int) -> KeyVersion:
        snapshot = self._versions
        kv = snapshot.get(version)
        if kv is None:
            # 绝不回退到其它版本继续尝试。
            raise KeyVersionNotFoundError(
                f"密钥版本 {version} 不存在", key_version=version
            )
        return kv

    @staticmethod
    def _require_operational(kv: KeyVersion, operation: str) -> None:
        if kv.status is KeyStatus.REVOKED:
            raise KeyRevokedError(
                f"密钥版本 {kv.version} 已撤销：禁止{operation}",
                key_version=kv.version,
            )
        if kv.status is KeyStatus.DISABLED:
            raise KeyDisabledError(
                f"密钥版本 {kv.version} 已停用：禁止{operation}",
                key_version=kv.version,
            )

    # ------------------------------------------------------------------
    # 加解密
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: bytes, *, context: dict[str, str],
                key_version: int | None = None) -> Envelope:
        """用指定版本（默认最新）加密；密钥不可用或缺失时拒绝并审计。"""
        ctx = {str(k): str(v) for k, v in context.items()}
        pt_hash = crypto.digest(plaintext)
        ctx_hash = crypto.digest_context(ctx)

        target = key_version
        try:
            if target is None:
                target = self.latest_version()
            kv = self._require_version(target)
            self._require_operational(kv, "加密")
            envelope = crypto.seal(
                plaintext, kek=kv.material, key_version=kv.version, context=ctx
            )
        except Exception as exc:
            self._deny("encrypt", target, ctx_hash, pt_hash, exc)
            raise

        self._auditer.record(
            operation="encrypt",
            success=True,
            key_version=kv.version,
            context_hash=ctx_hash,
            plaintext_hash=pt_hash,
            detail="使用最新密钥版本" if key_version is None else "使用指定版本",
        )
        return envelope

    def decrypt(self, envelope: Envelope, *,
                expected_context: dict[str, str]) -> bytes:
        """严格按密文绑定的版本与上下文解密，绝不回退其它版本。"""
        ctx = {str(k): str(v) for k, v in expected_context.items()}
        ctx_hash = crypto.digest_context(ctx)
        version = envelope.key_version
        pt_hash: str | None = None

        try:
            kv = self._require_version(version)
            self._require_operational(kv, "解密")
            plaintext = crypto.open_envelope(
                envelope, kek=kv.material, expected_context=ctx
            )
        except Exception as exc:
            self._deny("decrypt", version, ctx_hash, pt_hash, exc)
            raise

        pt_hash = crypto.digest(plaintext)
        self._auditer.record(
            operation="decrypt",
            success=True,
            key_version=version,
            context_hash=ctx_hash,
            plaintext_hash=pt_hash,
            detail="按密文绑定版本解密成功",
        )
        return plaintext

    def _deny(self, operation: str, version: int | None, ctx_hash: str | None,
              pt_hash: str | None, exc: Exception) -> None:
        """为明确失败落唯一一条失败审计；审计再失败则以审计失败为准。"""
        from app.errors import KMSError

        if isinstance(exc, KMSError):
            code, detail = exc.code.value, exc.message
        else:
            code, detail = "INTERNAL_ERROR", repr(exc)
        self._auditer.record(
            operation=operation,
            success=False,
            key_version=version,
            context_hash=ctx_hash,
            plaintext_hash=pt_hash,
            error_code=code,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # 轮换
    # ------------------------------------------------------------------

    def rotate(self) -> KeyVersion:
        """新增一个 ENABLED 版本；并发调用收敛为同一次轮换，绝不重复。

        - 窗口期间到达：登记为跟随者，等待并共享领队结果；
        - 轮换完成后到达：看到在途对象已结束，等待其结果后返回；
        - 在途被清空后到达：合法地成为下一轮换的领队。
        """
        import time as _time

        with self._rotate_cond:
            flight = self._rotate_in_flight
            if flight is not None:
                # 已有在途轮换：登记为跟随者，在 cond 上等待并共享结果。
                flight.joiners += 1
                while not flight.settled:
                    self._rotate_cond.wait()
                if flight.error is not None:
                    raise flight.error
                assert flight.result is not None
                return flight.result

            # 成为领队：创建在途对象，并在“同一个临界区”内度过注册窗口。
            # cond.wait 会释放锁，使同时到达的跟随者得以进入并登记；窗口
            # 结束领队释放锁后，尚未进入的跟随者仍可登记（对象仍在途）。
            flight = _RotationFlight()
            self._rotate_in_flight = flight
            window_end = _time.monotonic() + _RotationFlight._REGISTER_WINDOW
            while _time.monotonic() < window_end:
                self._rotate_cond.wait(window_end - _time.monotonic())

        # 在途对象保留，执行真正的轮换（不持 cond，避免阻塞跟随者登记）。
        try:
            result = self._rotate_locked()
        except BaseException as exc:
            with self._rotate_cond:
                self._rotate_in_flight = None
                flight.settle(error=exc)
                self._rotate_cond.notify_all()
            raise
        with self._rotate_cond:
            self._rotate_in_flight = None
            flight.settle(result=result)
            self._rotate_cond.notify_all()
        return result

    def _rotate_locked(self) -> KeyVersion:
        with self._lock:
            snapshot = self._versions
            previous = dict(snapshot)
            try:
                new_kv = self._create_locked()
            except Exception as exc:
                self._deny("rotate", None, None, None, exc)
                raise
            try:
                self._auditer.record(
                    operation="rotate",
                    success=True,
                    key_version=new_kv.version,
                    detail=f"轮换产生新版本 {new_kv.version}，历史版本保留可解密",
                )
            except AuditFailureError:
                # 回滚内存与本地存储，保证“未审计成功”即“未发生轮换”。
                self._rollback_locked(previous)
                raise
            return new_kv

    def _create_locked(self) -> KeyVersion:
        snapshot = self._versions
        version = next_version(snapshot)
        kv = generate_version(version, _utc_now_iso())
        new_snapshot = dict(snapshot)
        new_snapshot[version] = kv
        self._source.save(new_snapshot)   # 持久化成功后才切换内存状态
        self._versions = new_snapshot
        return kv

    # ------------------------------------------------------------------
    # 生命周期管理
    # ------------------------------------------------------------------

    def set_status(self, version: int, status: KeyStatus) -> KeyVersion:
        """停用/撤销/启用指定版本，非法迁移被拒绝。"""
        op = status.value
        with self._lock:
            previous = dict(self._versions)
            try:
                kv = self._require_version(version)
                transition(kv.status, status)
                updated = KeyVersion(
                    version=kv.version,
                    material=kv.material,
                    status=status,
                    created_at=kv.created_at,
                )
                new_snapshot = dict(self._versions)
                new_snapshot[version] = updated
                self._source.save(new_snapshot)
                self._versions = new_snapshot
            except Exception as exc:
                self._deny(op, version, None, None, exc)
                raise

            try:
                self._auditer.record(
                    operation=op,
                    success=True,
                    key_version=version,
                    detail=f"版本 {version} 状态置为 {status.value}",
                )
            except AuditFailureError:
                self._rollback_locked(previous)
                raise
            return updated

    def disable(self, version: int) -> KeyVersion:
        return self.set_status(version, KeyStatus.DISABLED)

    def revoke(self, version: int) -> KeyVersion:
        return self.set_status(version, KeyStatus.REVOKED)

    def enable(self, version: int) -> KeyVersion:
        return self.set_status(version, KeyStatus.ENABLED)

    def _rollback_locked(self, previous: dict[int, KeyVersion]) -> None:
        try:
            self._source.save(previous)
            self._versions = previous
        except Exception as exc:  # pragma: no cover - 极端故障路径
            raise AuditFailureError(
                "审计失败后的状态回滚也失败，本地密钥存储可能处于不一致状态"
            ) from exc
