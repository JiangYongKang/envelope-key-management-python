# 架构与设计说明

## 1. 组件与数据流

```
            ┌──────────────────────────── FastAPI (app/service.py) ───────────────────────────┐
            │  /encrypt /decrypt /keys/rotate /keys/deactivate /keys/revoke /keys/migrate      │
            │  /keys/versions                                                                  │
HTTP  ───▶  │  统一异常处理：KeyManagementError -> {error:{code,message,key_version}} + status   │
            └───────────────────────────────────┬──────────────────────────────────────────────┘
                                                 │
                          ┌──────────────────────▼───────────────────────┐
                          │              KeyManager (manager.py)          │
                          │  RLock 串行化：密钥环字典 + current 指针       │
                          │  - 加解密编排与状态判定（确定性失败顺序）     │
                          │  - rotate/deactivate/revoke 事务式提交+回滚   │
                          │  - migrate：锁内原子“校验目标→解密→重加密”   │
                          └───┬───────────────┬───────────────┬───────────┘
                              │               │               │
                  ┌───────────▼─────┐ ┌───────▼────────┐ ┌────▼────────────┐
                  │ crypto.py       │ │ key_source.py  │ │ audit.py         │
                  │ AES-256-GCM     │ │ inline / file  │ │ JSONL + fsync    │
                  │ AAD 绑定版本+ctx│ │ 仅本地来源      │ │ 成功/失败留痕     │
                  └─────────────────┘ └────────────────┘ └──────────────────┘
                              │
                  ┌───────────▼──────────┐
                  │ state_store.py        │
                  │ 密钥环快照原子落盘     │
                  │ (temp+fsync+replace)  │
                  └───────────────────────┘
```

配置入口 `app/config.py` 仅解析本地环境变量 / 本地 JSON，装配 `KeyManager`；
`main.py` 在 FastAPI lifespan 中构建，缺配置在启动阶段抛出 `CONFIG_INVALID`。

## 2. 信封令牌格式

明文令牌为 base64url(JSON, 无填充)，JSON 字段：

| 字段 | 含义 |
| --- | --- |
| `m` | 固定魔数 `EKM` |
| `v` | 信封格式版本（当前 `1`） |
| `kid` | 密钥环 id |
| `ver` | 加密所用密钥版本 |
| `iv`  | 12 字节 96-bit nonce（base64url） |
| `ct`  | AES-GCM 密文（base64url） |
| `tag` | 16 字节 GCM 认证标签（base64url） |
| `ctx` | 加密上下文对象（`{str: str}`） |

AES-GCM 的附加认证数据（AAD）使用长度前缀编码：

```
b"EKM-v1" | u16(len(kid)) | kid | u16(len(ver)) | ver | canonical(ctx)
```

`canonical(ctx)` 为按 key 排序、紧凑分隔、UTF-8 的 JSON，因此上下文与插入顺序无关。

## 3. 解密判定顺序（不回退原则）

1. `CIPHERTEXT_INVALID`：base64/JSON/魔数/格式版本/字段缺失或类型错误。
2. `KEY_ID_MISMATCH`：令牌 `kid` 不属于本服务管理的密钥环。
3. `CONTEXT_MISMATCH`：调用提供的上下文与令牌绑定上下文不相等。
4. `KEY_VERSION_NOT_FOUND`：`ver` 在密钥环中不存在（到此即拒绝，不尝试别的版本）。
5. `KEY_REVOKED` / `KEY_DEACTIVATED`：按版本状态判定（停用态可解密）。
6. `CIPHERTEXT_TAMPERED`：AES-GCM 校验 `InvalidTag`（密文/tag/nonce 或 AAD 被改）。

> 说明：把 `ver` 改成环内存在的另一个版本会因 AAD 不符在第 6 步报
> `CIPHERTEXT_TAMPERED`；改成环内不存在的版本则在第 4 步报
> `KEY_VERSION_NOT_FOUND`。两种情况都不会返回明文。

## 4. 密钥状态机

```
                 rotate()                revoke()
   ACTIVE ─────────────────▶ DEACTIVATED ─────────────▶ REVOKED
     │  (仅旧 current)            │                        │
     └────────── revoke() ────────┴────────────────────────┘
```

- 每次 `rotate()`：新键置 `ACTIVE` 并成为 current；旧 current 置 `DEACTIVATED`。
- 同一时刻恰好一个 current ACTIVE 版本；启动时源中 0 个或 >1 个 ACTIVE 都拒绝启动。
- `REVOKED` 为终态；对 current 直接 revoke / deactivate 均为非法迁移。
- 重复 `revoke()` 幂等（记录“already in target state”的成功审计，不重复改状态）。

## 5. 并发模型

- `threading.RLock` 保护 `ring: dict[str, KeyVersion]`、`current_version`、
  `sequence`。
- rotate 采用“先暂存新键、再切 current、持久化+审计成功后提交；任一步失败整体回滚”
  的方式，保证任何时刻都存在一个可用 current，且审计事实、磁盘状态与内存状态一致。
- 普通 encrypt/decrypt 的 AES-GCM 计算在锁外执行（纯 CPU、不可变密钥快照），
  不影响状态一致性。
- `rotate(expected_version=)` 实现乐观锁；并发的两个 CAS 轮换恰好一个成功，
  另一个收到 `ROTATION_RACE`。

## 6. 密文迁移（re-encrypt 到当前版本）

`migrate(tokens, context=None)` 把一批历史令牌重加密到当前 ACTIVE 版本：

- 每条令牌的处理**整体在锁内**：解析 → key id / 上下文守卫 → 源版本可解密性 →
  目标（当前）版本 ACTIVE 校验 → 解密 → 用目标版本重加密。因此迁移与
  rotate/deactivate/revoke 并发时，不会出现“目标版本刚被撤销却仍产出新密文”的
  中间态——目标不可用的条目明确失败（`KEY_DEACTIVATED` / `KEY_REVOKED`）。
- 源版本 == 目标版本时为幂等空操作（`ALREADY_CURRENT`），但先做 AEAD 校验，
  不为伪造令牌背书；重复迁移同一批结果可解释且令牌不变。
- 每条结果独立分类（`MIGRATED` / `ALREADY_CURRENT` / `FAILED` + 错误码），
  报告计数与条目列表严格一致；明文只存在于方法栈内，报告与审计只含摘要。
- 每条迁移各写一条 `MIGRATE` 审计记录；成功记录的持久化先于该条结果返回成功。

## 7. 状态持久化与重启语义

`KeyStateStore`（`state_store.py`）保存整个密钥环的快照：

- `FileStateStore.save()`：写临时文件 → fsync → `os.replace` → 目录 fsync，
  保证崩溃不留下半写的快照；文件权限 0600。
- 启动顺序：`load()` 有快照 → 校验 `key_id` 一致后以快照为准（密钥来源不再参与）；
  无快照 → 从密钥来源引导并立即落盘初始快照（落盘失败拒绝启动）。
- 重启一致性校验（`KeyManager._validate_snapshot_invariants`，对任意
  `KeyStateStore` 实现生效）：快照必须满足“恰有一个 ACTIVE 版本且它就是当前
  版本”——与首次从密钥来源引导时的校验（无 ACTIVE 或多个 ACTIVE 均拒绝）同源。
  多个 ACTIVE、零个 ACTIVE、或当前版本指针与唯一 ACTIVE 版本不符时，启动期抛
  `STATE_INCONSISTENT`（`PersistedStateInconsistentError`，`ConfigurationError`
  的子类，可与普通配置错误区分）并整次拒绝启动：不静默加载、不自动修复、
  不回退旧版本，落盘文件保持原样，需人工修复或删除快照。`FileStateStore`
  解析阶段的“当前版本必须 ACTIVE”检查同样以该错误码报告。合法历史状态
  （当前 ACTIVE、历史 DEACTIVATED/REVOKED）照常启动，当前版本不回退。
- rotate/deactivate/revoke 的提交流程：改内存 → `save()` 落盘 → 写审计；
  落盘失败回滚内存并抛 `STATE_PERSIST_FAILED`；审计失败回滚内存并尽力把旧快照
  重新落盘。任何情况下“返回成功”都意味着磁盘上已是新状态。
- 未配置 `state_path` 时使用 `InMemoryStateStore`：行为一致但重启后回到来源配置，
  仅建议测试/临时部署。

## 8. 本地密钥来源与配置

- `InlineKeySource`：来自本地应用配置的 `versions` 列表。
- `FileKeySource`：来自本地 JSON 文件 `{"versions": [...]}`。
- 每个条目必须包含非空 `version` 与可解码为 32 字节的 base64url `key_material`；
  `state` 可选（默认 `ACTIVE`）。任何不完整都抛 `CONFIG_INVALID`。
- 明确不提供网络/KMS 来源；未知 `type` 直接拒绝。

环境变量：

| 变量 | 说明 |
| --- | --- |
| `EKM_CONFIG_FILE` | 完整 JSON 配置（含 key_id / key_source / 可选 audit_path） |
| `EKM_KEY_FILE` | 直接指向本地 `{"versions": [...]}` 文件 |
| `EKM_INLINE_KEYS_JSON_FILE` | 指向本地 JSON 数组形式的版本列表 |
| `EKM_KEY_ID` | 密钥环 id（默认 `primary`） |
| `EKM_AUDIT_PATH` | 审计 JSONL 路径；不设置则使用内存 sink（仅建议测试） |
| `EKM_STATE_PATH` | 密钥环状态快照路径；不设置则使用内存态（重启后回到来源配置） |

## 9. 审计记录字段

```json
{
  "timestamp": "2026-09-23T...Z",
  "operation": "ENCRYPT|DECRYPT|ROTATE|DEACTIVATE|REVOKE|MIGRATE",
  "result": "SUCCESS|FAILURE",
  "key_version": "v2",
  "context_digest": "<sha256-hex>",
  "input_digest": "<sha256-hex>",
  "error_code": "CIPHERTEXT_TAMPERED|null",
  "detail": "human readable basis"
}
```

## 10. 安全注意事项

- 本地密钥文件由 `app.cli` 以 `0600` 权限写出；部署时需自行保护文件系统权限。
- nonce 由 `os.urandom(12)` 生成；同一 256-bit 密钥下 GCM 随机 nonce 冲突概率可忽略，
  轮换进一步限制了单密钥加密量。
- 令牌本身不隐藏 `kid/ver/ctx`（只保证完整性与保密性的是明文载荷）；
  若上下文敏感，应在放入上下文前做哈希/脱敏。
