# 本地信封加密与密钥轮换服务（Python）

纯本地的信封加密（Envelope Encryption）与密钥版本生命周期管理服务。
密钥材料只来自**本地配置**或**本地文件存储**，不依赖任何外部 KMS / 网络密钥服务。

- 加解密：AES-256-GCM，密文在认证数据中**绑定密钥版本与加密上下文**。
- 生命周期：`ACTIVE / DEACTIVATED / REVOKED`，支持轮换、停用、撤销。
- **批量迁移**：把一批历史密文在服务端整体重加密到当前版本（`POST /keys/migrate`），
  调用方无需给明文、服务也不返回明文；逐条给出 `REENCRYPTED / ALREADY_CURRENT /
  FAILED` 结果，幂等可重跑，部分失败绝不统一报成功。
- **重启一致性（可选落盘）**：配置 `state_path` / `EKM_STATE_PATH` 后，轮换、停用、
  撤销的结果以原子快照落盘，重启后当前版本不回退；落盘失败则本次操作整体失败并回滚。
- 并发：单把锁串行化状态迁移；迁移与轮换/撤销并发时，不会产生谁都解不开的密文、
  不会重复迁移、版本状态不会错乱。
- 审计：JSONL 落盘，审计结论与实际操作结果严格一致；迁移逐件留痕。
- 失败可解释：每个失败路径都有稳定的 `ERROR_CODE`，HTTP 与库调用一致。

## 1. 目录结构

```
app/
  errors.py      # 错误分类（稳定错误码）与异常类型
  models.py      # 密钥状态、密钥版本、密文信封、审计记录、上下文
  key_source.py  # 本地密钥来源：inline 配置 / 本地文件（无网络来源）
  crypto.py      # AES-256-GCM 信封加解密（version + context 作为 AAD）
  audit.py       # 审计落盘（fsync）与内存测试 sink
  state.py       # 密钥环快照的本地原子持久化（重启一致性）
  manager.py     # 线程安全的密钥环、生命周期、加解密、批量迁移编排
  config.py      # 环境变量 / 本地 JSON 配置加载与服务装配
  service.py     # FastAPI 入口与错误码 -> HTTP 状态映射
  cli.py         # 本地密钥文件生成：python -m app.cli
main.py          # uvicorn 入口（缺配置时启动期明确拒绝）
tests/           # 118 个 pytest 用例，含迁移/重启一致性/并发场景
examples/        # 配置示例
docs/            # 架构与密钥层级说明
```

## 2. 密钥层级

> 本服务刻意保持**单层 DEK + 版本化密钥环**，因为所有密钥材料都在本地：
> 不引入本地 KEK 去包装远端 DEK。信封的“信封”体现在“数据密钥 + 元数据头 +
> 认证标签”这一自描述令牌，而非“KEK 包 DEK”。

- **主密钥标识 `key_id`**：一个服务实例管理一个密钥环（key ring）。
- **密钥版本 `KeyVersion`**：环中的每个版本都有独立的 32 字节 AES-256 密钥材料、
  单调版本号（`v1`、`v2` …）与生命周期状态。
- **信封令牌 `EnvelopeCiphertext`**：base64url(JSON)，结构见
  [`docs/architecture.md`](docs/architecture.md)。其中 `kid / ver / ctx`
  同时写入 AES-GCM 的附加认证数据（AAD），因此：
  - 改写版本号 / key id → 认证失败或版本查找失败，**绝不会**回退到其它密钥；
  - 替换上下文 → 认证失败（`CONTEXT_MISMATCH` / `CIPHERTEXT_TAMPERED`）。

## 3. 轮换与停用规则

| 状态 | 加密（新写入） | 解密（历史密文） |
| --- | --- | --- |
| `ACTIVE`（当前版本，唯一） | ✅ | ✅ |
| `DEACTIVATED`（轮换后的历史版本） | ❌ `KEY_DEACTIVATED` | ✅ |
| `REVOKED`（永久撤销） | ❌ `KEY_REVOKED` | ❌ `KEY_REVOKED` |

- **轮换 `POST /keys/rotate`**：生成新的 `ACTIVE` 版本，旧当前版本自动转为
  `DEACTIVATED`；新写入只使用最新版本，历史密文仍可用旧版本解密。
- **不回退**：解密严格使用令牌内嵌的 `ver`。版本不存在 → `KEY_VERSION_NOT_FOUND`，
  不会尝试其它版本。
- **并发安全**：所有状态迁移在同一把锁内串行完成；并发轮换产生互不重复的单调版本。
- **乐观轮换（CAS）**：`rotate(expected_version=...)` 在当前版本已被他人推进时
  返回 `ROTATION_RACE`，避免重复/叠加轮换。
- **撤销当前版本被禁止**（须先轮换再撤销）：`INVALID_LIFECYCLE_TRANSITION`；
  `REVOKED` 是终态，不可恢复。

## 3.1 批量迁移与版本退役

轮换之后老版本会一直以 `DEACTIVATED` 挂着（仍能解密历史密文）。要安全撤销老版本，
先用迁移把存量密文整体升级到当前版本：

- **接口**：`POST /keys/migrate`；库调用 `KeyManager.migrate(items, default_context=None)`。
- **输入**：`items` 为数组，元素可以是
  - 裸令牌字符串 `"EKM..."`：纯服务端升级，直接复用令牌内绑定的上下文，
    **调用方不需要提供明文，也不需要提供上下文**；
  - 或对象 `{"ciphertext": "EKM...", "context": {...}, "item_id": "可选"}`：
    提供 `context` 时会像解密一样校验它与绑定上下文一致，不一致该条记
    `CONTEXT_MISMATCH`。
  - 顶层 `context` 可作为整批默认上下文。
- **明文边界**：明文只在服务进程内短暂存在（旧钥解出 → 新钥重封装），从不出现在
  返回值、日志或审计里；返回的只有新令牌。
- **逐条结果**：每件都有独立结论，**不会有的成功有的失败却统一报成功，也不会静默跳过**：

  | status | 含义 |
  | --- | --- |
  | `REENCRYPTED` | 从旧版本重加密到当前版本，`ciphertext` 为新令牌 |
  | `ALREADY_CURRENT` | 幂等：本来就在当前版本，令牌原样返回 |
  | `FAILED` | 未升级，`error_code`/`reason` 说明具体类别 |

  失败类别复用既有错误码：`CIPHERTEXT_INVALID`（条目本身非法）、`KEY_ID_MISMATCH`、
  `CONTEXT_MISMATCH`（上下文对不上）、`KEY_VERSION_NOT_FOUND`、`KEY_REVOKED`
  （源版本或目标版本已撤销）、`KEY_DEACTIVATED`（目标已停用）、`CIPHERTEXT_TAMPERED`。
- **响应语义**：全部成功 HTTP 200；只要有一条失败即 HTTP 409
  `MIGRATION_INCOMPLETE`，但响应体里仍带同一份逐件 `report`。
- **正确性**：迁移后的密文必须能用**原来的上下文**解密，明文与迁移前逐字节相同。
  迁移本身不改变任何密钥状态（不会顺手停用/撤销旧版本）。
- **幂等**：同一批密文重复迁移是安全的；已在当前版本的条目返回 `ALREADY_CURRENT`，
  结果可解释，令牌不变。
- **退役流程（推荐）**：`rotate` → `migrate`（确认 `failed=0`）→ 视需要再次
  `migrate` 复查（全部 `ALREADY_CURRENT`）→ `revoke <旧版本>`。

> 重要保证：迁移采用“锁内取源/目标密钥快照 → 锁外 AEAD → 提交前再次锁内复核目标仍为
> 当前 ACTIVE”两段式。若重加密完成、返回结果前目标版本被轮换（变为 DEACTIVATED）或
> 被撤销，该条**明确失败并给出原因，绝不返回一个谁都解不开的密文**。

## 3.2 重启后的行为与兼容范围

- 配置 `state_path`（或环境变量 `EKM_STATE_PATH`）后，密钥环快照会以
  `ekm-state-v1` JSON 原子落盘（临时文件 + fsync + `os.replace` + 目录 fsync，
  权限 `0600`）。
- 轮换/停用/撤销**只有在快照落盘成功后才算提交成功**；落盘失败抛
  `STATE_PERSIST_FAILED`，内存改动连同已落盘内容一起回滚——宁可整体失败，也不会
  “运行期以为成功、重启后没生效”。
- 重启时**已持久化快照优先于静态密钥文件**：当前版本不回退、轮换产生的新密钥材料
  仍在；未迁移的历史密文继续按内嵌旧版本解密（旧版本为 DEACTIVATED 时仍可解密，
  REVOKED 时按规则拒绝），迁移过的密文用新版本解密。
- 状态文件与本地密钥文件属于同一信任边界；状态文件中的 `key_id` 必须与配置一致，
  快照损坏/格式不符在**启动期**直接 `STATE_INVALID`，绝不静默使用部分状态。
- **不配置 `state_path` 时为纯内存模式**（与历史行为兼容）：轮换等改动重启后不保留。

## 4. 错误分类

| 错误码 | 含义 | HTTP |
| --- | --- | --- |
| `CONFIG_INVALID` | 本地配置缺失/不完整（拒绝启用，不使用默认密钥） | 503 |
| `KEY_ID_MISMATCH` | 密文属于另一个密钥环（kid 不符） | 409 |
| `KEY_VERSION_NOT_FOUND` | 内嵌版本在本密钥环中不存在，且不回退 | 404 |
| `KEY_REVOKED` | 版本已撤销，加密/解密均禁止 | 409 |
| `KEY_DEACTIVATED` | 版本已停用，禁止加密（解密仍允许） | 409 |
| `CONTEXT_MISMATCH` | 调用方上下文与密文绑定上下文不一致 | 409 |
| `CIPHERTEXT_INVALID` | 令牌结构非法（base64/JSON/格式/字段） | 400 |
| `CIPHERTEXT_TAMPERED` | AEAD 认证失败（密文/tag/nonce 被篡改、AAD 被改写） | 409 |
| `ROTATION_RACE` | 乐观轮换发现当前版本已被推进 | 409 |
| `INVALID_LIFECYCLE_TRANSITION` | 非法状态迁移（如撤销当前版本、复活已撤销密钥） | 409 |
| `NO_ACTIVE_KEY` | 无可用的当前 ACTIVE 版本用于加密 | 503 |
| `AUDIT_WRITE_FAILED` | 审计无法持久化；成功操作因此不返回成功 | 500 |
| `STATE_PERSIST_FAILED` | 生命周期变更无法落盘；操作整体失败并回滚 | 500 |
| `STATE_INVALID` | 状态快照损坏/格式或 key id 不符；启动期拒绝 | 503 |
| `MIGRATION_INCOMPLETE` | 批量迁移至少一条失败（响应仍含逐件 report） | 409 |

判定顺序（解密）：**结构合法 → key id 一致 → 上下文一致 → 版本存在/状态允许 →
AEAD 认证**。每一环节失败都给出对应错误码，且立即终止。

## 5. 审计一致性

- 审计文件为每行一个 JSON 对象（JSONL），写入时 `flush + fsync`。
- 操作成功仅在 SUCCESS 记录持久化**之后**返回；审计写失败会把本次调用变为
  `AUDIT_WRITE_FAILED`（并回滚尚未提交的轮换/迁移），不存在“记成功却实际失败”。
- 失败操作的 FAILURE 记录采用 best-effort 写入，不改变原始失败分类。
- 审计只记录上下文/输入的 SHA-256 摘要，绝不写入明文或密钥材料。

## 6. 本地验证方法

```bash
# 安装依赖（使用项目内 uv 镜像配置）
uv sync

# 生成本地密钥文件（0600 权限，纯本地 os.urandom）
uv run python -m app.cli --output local-keys.json

# 方式 A：文件式配置启动
export EKM_KEY_FILE="$PWD/local-keys.json"
export EKM_KEY_ID="primary"
export EKM_AUDIT_PATH="$PWD/audit.jsonl"
export EKM_STATE_PATH="$PWD/ekm-state.json"   # 启用轮换/停用/撤销的重启持久化
uv run uvicorn main:app --reload

# 方式 B：完整配置文件
export EKM_CONFIG_FILE="$PWD/examples/config.example.json"
uv run uvicorn main:app
```

未提供任何本地密钥来源时，**启动期**直接失败：

```text
[CONFIG_INVALID] no local key source configured: set EKM_CONFIG_FILE, ...
```

### HTTP 快速验证

```bash
curl -s localhost:8000/health
TOK=$(curl -s -XPOST localhost:8000/encrypt \
  -H 'content-type: application/json' \
  -d '{"plaintext":"hello","context":{"tenant":"acme"}}' | python -c 'import sys,json;print(json.load(sys.stdin)["ciphertext"])')
curl -s -XPOST localhost:8000/decrypt -H 'content-type: application/json' \
  -d "{\"ciphertext\":\"$TOK\",\"context\":{\"tenant\":\"acme\"}}"
curl -s -XPOST localhost:8000/keys/rotate -H 'content-type: application/json' -d '{}'
# 批量迁移历史密文到当前版本（裸令牌即可，无需明文/上下文）：
curl -s -XPOST localhost:8000/keys/migrate -H 'content-type: application/json' \
  -d "{\"items\":[\"$TOK\"]}"
# 全部成功 200；部分失败 409 MIGRATION_INCOMPLETE，items[] 里逐件给出原因。
```

验证重启一致性：保持同一 `EKM_KEY_FILE` + `EKM_STATE_PATH`，重启后
`/health` 的 `current_version` 不回退，迁移过/未迁移的密文都按各自版本规则可解密。

### 测试

```bash
uv run pytest                                   # 全部用例
uv run pytest --log-cli-level=DEBUG             # 打印输入摘要 + 判定依据
uv run pytest tests/test_migration.py           # 批量迁移与逐条失败分类/幂等
uv run pytest tests/test_persistence.py         # 重启一致性 / 落盘失败回滚 / 损坏拒绝
uv run pytest tests/test_migration_concurrency.py  # 迁移 × 轮换/撤销并发
uv run pytest tests/test_rotation_concurrency.py
```

测试覆盖：批量迁移（升级、明文不出服务、逐条失败分类、不统一报成功、不静默跳过、
幂等重跑、源版本撤销）、重启一致性（轮换/停用/撤销/迁移落盘后重建、当前版本不回退、
新老密文按规则解密、落盘失败整体回滚、状态损坏/key id 不符启动期拒绝）、迁移与轮换/
撤销并发（提交窗口目标失效不产生死密文、并发迁移幂等、混合负载版本状态不错乱），以及
轮换期间并发解密、并行轮换去重、乐观 CAS 轮换、密文篡改、上下文不匹配、版本缺失、
跨密钥环、已撤销密钥、非法生命周期迁移、审计与真实结果一致性、配置缺失/不完整拒绝启用。
日志中 `CASE ... inputs=...` 为场景与输入摘要，`decision MIGRATE/DECRYPT ... reason=...`
为判定依据。
