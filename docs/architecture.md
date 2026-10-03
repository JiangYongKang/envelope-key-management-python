# 架构与设计说明

## 1. 组件与数据流

```
            ┌──────────────────────────── FastAPI (app/service.py) ───────────────────────────┐
HTTP  ───▶  │  /encrypt /decrypt /keys/rotate /keys/deactivate /keys/revoke /keys/migrate      │
            │  /keys/versions；统一异常处理：KeyManagementError -> {error:{code,message,...}}   │
            └───────────────────────────────────┬──────────────────────────────────────────────┘
                                                 │
                          ┌──────────────────────▼───────────────────────┐
                          │              KeyManager (manager.py)          │
                          │  RLock 串行化：密钥环字典 + current 指针       │
                          │  - 加解密编排与状态判定（确定性失败顺序）     │
                          │  - rotate/deactivate/revoke 事务式提交+回滚   │
                          │  - migrate 批量重加密：两段式快照 + 提交门    │
                          └───┬───────────────┬───────────────┬───────────┘
                              │               │               │
                  ┌───────────▼─────┐ ┌───────▼────────┐ ┌────▼────────────┐
                  │ crypto.py       │ │ key_source.py  │ │ audit.py         │
                  │ AES-256-GCM     │ │ inline / file  │ │ JSONL + fsync    │
                  │ AAD 绑定版本+ctx│ │ 仅本地来源      │ │ 迁移逐件留痕      │
                  └─────────────────┘ └────────────────┘ └──────────────────┘
                          │
                  ┌───────▼────────┐
                  │ state.py        │ 本地原子快照（临时文件+fsync+rename）
                  │ ekm-state-v1    │ 轮换/停用/撤销重启后仍成立
                  └─────────────────┘
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
- rotate 采用“先暂存新键、再切 current、成功后提交审计；审计失败整体回滚”的方式，
  保证任何时刻都存在一个可用 current，且审计事实与状态一致。
- AES-GCM 计算在锁外执行（纯 CPU、不可变密钥快照），不影响状态一致性。
- `rotate(expected_version=)` 实现乐观锁；并发的两个 CAS 轮换恰好一个成功，
  另一个收到 `ROTATION_RACE`。

## 5.1 批量迁移（re-encryption）的并发与失败模型

`migrate(items)` 对每件密文顺序执行，但单条采用**两段式**，避免与轮换/撤销互相制造死密文：

1. 锁内读取并校验：目标版本 = 批次开始时的 current；源版本存在且可解密
   （REVOKED → `KEY_REVOKED`）；目标版本自身仍 ACTIVE（REVOKED → `KEY_REVOKED`，
   DEACTIVATED → `KEY_DEACTIVATED`，优先级高于“current 已移动”）。快照源/目标密钥材料。
2. 锁外执行 AES-GCM：旧钥解密 → 新钥重封装（复用令牌内绑定上下文，明文不出进程）。
3. **提交门**：返回新令牌前再次锁内复核目标版本仍是 current 且 ACTIVE。若在此窗口内
   发生轮换（目标变 DEACTIVATED）或撤销，该条返回 FAILED 且**不给出新令牌**——
   绝不会产出一个谁都解不开的密文。

判定顺序与解密一致：结构合法 → key id 一致 →（仅当调用方提供 context 时）上下文一致 →
版本存在/状态允许 → AEAD 认证。任何一条失败只影响该条，其余条目照常处理。

- 已在目标版本的条目：仍先做 AEAD 认证（防止把垃圾当“已最新”保留），通过后返回
  `ALREADY_CURRENT` 与原令牌，因此整批可安全重复执行（幂等）。
- 成功记录在 SUCCESS 审计落盘后才把新令牌计入结果；审计写失败按 AUDIT_WRITE_FAILED
  中止整批（调用方重试不会得到双重成功）。失败条目 best-effort 记 FAILURE。
- 迁移不修改密钥环状态，因此不需要状态快照写入；它的持久性来自“源/目标版本与令牌本身
  都已在既有的持久化状态/静态配置中”。

## 5.2 状态持久化（重启一致性）

配置 `state_path` 后，每次成功的 rotate/deactivate/revoke 提交点执行：

```
内存改好 → FileStateStore.save() 原子快照 → 审计 SUCCESS 落盘 → 返回成功
```

- 快照为 `ekm-state-v1` JSON：`key_id / current_version / sequence /
  versions[{version,key_material(b64),state,created_at}]`。
- 原子写：同目录临时文件 → `flush + fsync` → `chmod 0600` → `os.replace` →
  目录 fsync。崩溃后只会留下上一份或新一份完整快照。
- 任一步失败：先回滚内存，rotate/审计失败时再把**上一份快照重新原子写回**，
  然后抛 `STATE_PERSIST_FAILED`；调用方不可能在变更未持久化时收到成功。
- 启动时：若快照存在则**优先恢复**（校验格式、恰好一个 ACTIVE 且其为 current、
  `key_id` 一致、与静态源中同名版本的材料一致）；快照损坏/不兼容 → 启动期
  `STATE_INVALID`。无快照时从静态本地源引导并立即写首份快照。
- 不配置 `state_path` 使用 `InMemoryStateStore`，行为与历史纯内存模式一致。

## 6. 本地密钥来源与配置

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
| `EKM_STATE_PATH` | 密钥环快照路径；设置后启用轮换/停用/撤销的重启持久化，不设置为纯内存 |

## 7. 审计记录字段

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

迁移逐件各产生一条 MIGRATE 记录：成功 `detail` 以 `REENCRYPTED:` /
`ALREADY_CURRENT:` 开头，失败以 `FAILED: <原因>` 开头；只含上下文/输入摘要，
绝无明文或密钥材料。

## 8. 安全注意事项

- 本地密钥文件由 `app.cli` 以 `0600` 权限写出；部署时需自行保护文件系统权限。
- nonce 由 `os.urandom(12)` 生成；同一 256-bit 密钥下 GCM 随机 nonce 冲突概率可忽略，
  轮换进一步限制了单密钥加密量。
- 令牌本身不隐藏 `kid/ver/ctx`（只保证完整性与保密性的是明文载荷）；
  若上下文敏感，应在放入上下文前做哈希/脱敏。
