# 本地信封加密与密钥轮换服务（Python）

纯本地的信封加密（Envelope Encryption）与密钥版本生命周期管理服务。
密钥材料只来自**本地配置**或**本地文件存储**，不依赖任何外部 KMS / 网络密钥服务。

- 加解密：AES-256-GCM，密文在认证数据中**绑定密钥版本与加密上下文**。
- 生命周期：`ACTIVE / DEACTIVATED / REVOKED`，支持轮换、停用、撤销。
- 并发：单把锁串行化状态迁移；轮换与解密并发不丢数据、不重复轮换。
- 审计：JSONL 落盘，审计结论与实际操作结果严格一致。
- 失败可解释：每个失败路径都有稳定的 `ERROR_CODE`，HTTP 与库调用一致。

## 1. 目录结构

```
app/
  errors.py      # 错误分类（稳定错误码）与异常类型
  models.py      # 密钥状态、密钥版本、密文信封、审计记录、上下文
  key_source.py  # 本地密钥来源：inline 配置 / 本地文件（无网络来源）
  crypto.py      # AES-256-GCM 信封加解密（version + context 作为 AAD）
  audit.py       # 审计落盘（fsync）与内存测试 sink
  manager.py     # 线程安全的密钥环、生命周期、加解密编排
  config.py      # 环境变量 / 本地 JSON 配置加载与服务装配
  service.py     # FastAPI 入口与错误码 -> HTTP 状态映射
  cli.py         # 本地密钥文件生成：python -m app.cli
main.py          # uvicorn 入口（缺配置时启动期明确拒绝）
tests/           # 73 个 pytest 用例，含并发轮换/解密场景
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
```

### 测试

```bash
uv run pytest                                   # 全部用例
uv run pytest --log-cli-level=DEBUG             # 打印输入摘要 + 判定依据
uv run pytest tests/test_rotation_concurrency.py
```

测试覆盖：轮换期间并发解密、并行轮换去重、乐观 CAS 轮换、密文篡改、上下文不匹配、
版本缺失、跨密钥环、已撤销密钥、非法生命周期迁移、审计与真实结果一致性，以及
配置缺失/不完整拒绝启用。日志中 `CASE ... inputs=...` 为输入摘要，
`decision ... reason=...` 为判定依据。
