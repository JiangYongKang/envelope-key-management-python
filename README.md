# 本地信封加密与密钥轮换服务（envelope-key-management-python）

一个**完全本地化**的信封加密（Envelope Encryption）与密钥轮换服务：
密钥材料只来自本地配置或本地存储，不依赖任何外部密钥服务（KMS/HSM/网络）。
提供版本化加解密、密钥生命周期管理、并发轮换收敛、可区分的错误分类，
以及与实际操作结果严格一致的审计记录。

---

## 1. 密钥层级

采用标准的两层信封结构：

```
应用明文
   │  AES-256-GCM（随机 DEK，每条消息独立）
   ▼
密文 ciphertext + 认证标签 tag
   ▲
   │  AES-256-GCM（KEK[版本号]，包装随机 DEK）
加密后的 DEK encrypted_dek
```

- **KEK（Key Encryption Key，主密钥）**：32 字节（AES-256），按整数版本号
  管理，是真正需要保护的“根密钥”。材料由本地 CSPRNG（`os.urandom`）生成，
  仅存在于本地内存或本地密钥文件中。
- **DEK（Data Encryption Key，数据密钥）**：每次加密随机生成 32 字节，
  随密文一起以被 KEK 包装（加密）的形式存储；本身不以明文落盘。
- 解密时：先用密文**绑定的那个 KEK 版本**解包得到 DEK，再用 DEK 解密明文。

### 密文格式（自描述，JSON）

| 字段 | 含义 |
| --- | --- |
| `format_version` | 信封格式版本，当前为 `1` |
| `key_version` | 本密文所属的 **KEK 版本号**（解密时严格按此版本，不回退） |
| `context` | 加密时绑定的使用上下文（字符串键值对） |
| `iv` | 明文加密的随机 IV |
| `wrap_iv` | KEK 包装 DEK 的随机 IV |
| `encrypted_dek` | KEK 加密后的 DEK（内含 GCM 标签） |
| `ciphertext` / `tag` | 密文与明文层认证标签 |

**上下文绑定（AAD）**：格式版本、密钥版本与规范化（键排序）后的上下文，
同时作为两层 AES-GCM 的 Additional Authenticated Data。因此：

- 换一个 KEK 版本 / 换一份密钥材料解包 DEK → 认证失败；
- 用不同上下文解密 → 在密码学运算之前即判定为上下文不匹配；
- 篡改 `ciphertext`、`tag`、`iv`、`wrap_iv`、`encrypted_dek` 或密文中的
  上下文字段 → 认证失败。

---

## 2. 轮换与停用规则

### 密钥状态（生命周期）

| 状态 | 加密 | 解密 | 说明 |
| --- | :---: | :---: | --- |
| `enabled` | ✅ | ✅ | 正常可用 |
| `disabled`（已停用） | ❌ `KEY_DISABLED` | ❌ `KEY_DISABLED` | 保留材料，可重新启用或撤销 |
| `revoked`（已撤销） | ❌ `KEY_REVOKED` | ❌ `KEY_REVOKED` | **终态**，不可恢复 |

合法迁移：

```
enabled  ──► disabled ──► enabled
   │            │
   └────────► revoked（终态，任何迁出都被拒绝）
disabled ──► revoked
```

已停用与已撤销**都不允许解密**——不会为了“能解开旧数据”而放宽，
且两类失败分别返回 `KEY_DISABLED` / `KEY_REVOKED`，判定结果可解释。
因此在停用或撤销某个仍承载历史密文的版本前，应先用新版本对历史密文
完成再封装（re-encrypt/re-wrap）迁移；未迁移的密文在对应版本停用或
撤销后将按规则被拒绝解密。

### 轮换语义

- `rotate()` 生成新的 `enabled` 版本，版本号单调递增（从 1 起、连续）。
- **轮换后新写入一律使用最新版本**；历史密文仍携带其 `key_version`，
  由对应旧版本正常解密——旧版本材料被保留。
- **并发轮换收敛（single-flight）**：同一时刻并发到达的多个轮换请求只产生
  **一个**新版本，其余调用共享同一结果，杜绝重复轮换。轮换结束后的后续
  调用才会产生下一个版本。
- **轮换与解密并发**：状态字典采用 copy-on-write，解密永远读取某个一致快照，
  不会读到“半套”密钥，不会出现数据不可读或密钥状态错乱。
- 持久化采用“临时文件 + fsync + 原子 rename”，轮换不会产生半写文件。
- 审计落盘是变更完成的必要条件：若轮换审计写入失败，会回滚内存与本地文件，
  即“未审计成功”等于“轮换未发生”。

### 空库策略

密钥库为空时，加解密返回 `KEY_STORE_EMPTY`；只有显式 `bootstrap`/`init`
才会创建首个版本。**绝不使用隐式默认密钥继续运行。**

---

## 3. 错误分类

所有业务错误都是 `app.errors.KMSError` 的子类，携带稳定的 `code`，
在 SDK 调用与 HTTP 入口下结论一致：

| `code` | 含义 | HTTP |
| --- | --- | --- |
| `CONFIG_INVALID` | 配置缺失/不完整、非法生命周期迁移、未知状态值 | 500 |
| `KEY_STORE_EMPTY` | 密钥库为空且未引导 | 503 |
| `KEY_VERSION_NOT_FOUND` | 指定版本不存在，**不回退**到其它版本 | 404 |
| `CONTEXT_MISMATCH` | 解密上下文与密文绑定上下文不一致 | 409 |
| `CIPHERTEXT_INVALID` | 密文格式损坏、版本不支持、认证失败（版本材料不符或任一字段被篡改） | 422 |
| `KEY_DISABLED` | 已停用密钥被用于加密/解密 | 423 |
| `KEY_REVOKED` | 已撤销密钥被用于加密/解密 | 423 |
| `ROTATION_CONFLICT` | 轮换冲突（默认并发收敛，不对外暴露） | 409 |
| `KEY_SOURCE_FAILURE` | 本地密钥文件无法读取/写入 | 500 |
| `AUDIT_FAILURE` | 审计记录写入失败 | 500 |

HTTP 错误响应统一为：

```json
{"error": {"code": "CONTEXT_MISMATCH", "message": "...", "key_version": 2}}
```

关键判定顺序（解密）：版本存在性 → 版本状态（revoked/disabled）→
格式版本 → 上下文一致性 → KEK 解包 DEK 认证 → DEK 解密明文认证。

---

## 4. 审计

- 每次 `encrypt` / `decrypt` / `rotate` / `enable` / `disable` / `revoke`
  在结论确定后写**恰好一条** JSON Lines 审计事件到本地 `EKM_AUDIT_FILE`。
- 审计与实际结果一致：成功记 `"success": true`；被拒绝/失败记
  `"success": false` 且 `error_code` 为上表中的精确代码。
- 只记录**摘要**，不记录明文：`plaintext_hash`、`context_hash` 均为
  SHA-256 短摘要（前 32 个十六进制字符）。
- 同时通过日志打印输入摘要与判定依据，例如：

```
op=decrypt verdict=DENIED(KEY_REVOKED) key_version=1 ctx=b951… pt=None reason=密钥版本 1 已撤销：禁止解密
op=encrypt verdict=SUCCESS             key_version=2 ctx=b951… pt=3a6e… reason=使用最新密钥版本
```

---

## 5. 配置（仅本地来源）

通过环境变量装配服务：

| 变量 | 说明 |
| --- | --- |
| `EKM_KEY_FILE` | 本地密钥 JSON 文件路径（未设置且未声明内存模式时**拒绝启动**） |
| `EKM_AUDIT_FILE` | 本地审计 JSON Lines 文件路径 |
| `EKM_BOOTSTRAP=1` | 允许在空库中自动引导首个版本（仅初始化时使用） |
| `EKM_IN_MEMORY=1` | 进程内密钥来源（仅限测试/演示，重启即失效） |

密钥文件缺失字段、材料长度不是 32 字节、版本不从 1 起连续、JSON 损坏等，
都会在加载时以 `CONFIG_INVALID` / `KEY_SOURCE_FAILURE` **拒绝启用**。

---

## 6. 本地验证方法

### 6.1 安装与初始化

```bash
uv sync

# 引导首个本地密钥版本（材料仅写入本地 data/keys.json）
mkdir -p data
.venv/bin/python -m app.cli init --key-file data/keys.json --audit-file data/audit.jsonl

# 轮换 / 停用 / 撤销 / 查看
.venv/bin/python -m app.cli rotate     --key-file data/keys.json --audit-file data/audit.jsonl
.venv/bin/python -m app.cli set-status --version 1 --status disabled --key-file data/keys.json --audit-file data/audit.jsonl
.venv/bin/python -m app.cli list       --key-file data/keys.json
```

### 6.2 启动 HTTP 服务

```bash
EKM_KEY_FILE=data/keys.json EKM_AUDIT_FILE=data/audit.jsonl \
  .venv/bin/uvicorn main:app --reload
```

接口：`POST /encrypt`、`POST /decrypt`、`POST /rotate`、
`POST /keys/status`、`GET /keys`（交互式文档见 `/docs`）。

```bash
# 加密
curl -s localhost:8000/encrypt -H 'content-type: application/json' \
  -d '{"plaintext":"hello","context":{"tenant":"acme"}}'

# 解密（用返回的 envelope 原样回传，并提供相同上下文）
curl -s localhost:8000/decrypt -H 'content-type: application/json' \
  -d '{"envelope":{...},"context":{"tenant":"acme"}}'
```

### 6.3 运行测试

```bash
.venv/bin/python -m pytest
```

测试覆盖（38 个用例）：

- 加解密往返、序列化往返；
- **轮换期间 20 路并发解密全部可读**、3 路同时轮换收敛为单一新版本；
- 16 路同时轮换只产生一个版本，后续串行轮换继续递增；
- 密文各字段（`ciphertext`/`tag`/`iv`/`wrap_iv`/`encrypted_dek`/上下文字段）
  被篡改 → 统一归类为 `CIPHERTEXT_INVALID`；
- 上下文不匹配 → `CONTEXT_MISMATCH`；
- 版本不存在 → `KEY_VERSION_NOT_FOUND`，且不回退；
- 已停用 → `KEY_DISABLED`（加解密均拒），已撤销 → `KEY_REVOKED`（终态）；
- 配置缺失/损坏/不连续版本 → 拒绝启用；
- **审计落盘失败时操作按失败处理、轮换/状态变更回滚**，审计可用时成功如实记录；
- 审计记录与实际成功/失败一一对应，且不含明文。

加 `-s` 可在单测日志中查看每次操作的输入摘要（`ctx`/`pt`）与判定依据
（`SUCCESS` / `DENIED(code)` + 原因）：

```bash
.venv/bin/python -m pytest -s
```

---

## 7. 代码结构

```
app/
  errors.py      # 错误码、异常层级、HTTP 状态映射
  models.py      # KeyStatus / KeyVersion / Envelope / AuditEvent
  crypto.py      # 无状态密码学原语（AES-256-GCM 两层信封、摘要）
  keystore.py    # 本地 KeySource 协议、内存来源、版本生成、状态迁移规则
  file_source.py # 本地 JSON 文件密钥来源（严格校验 + 原子写入）
  audit.py       # 审计事件构建、JSONL 落盘、摘要日志
  manager.py     # 核心：版本选择、状态判定、并发轮换收敛、审计一致性
  config.py      # 配置装配与环境变量（配置不完整即拒绝）
  service.py     # FastAPI HTTP 入口与统一错误响应
  cli.py         # 本地 init/rotate/set-status/list 命令行
tests/           # pytest 套件
main.py          # uvicorn 入口（main:app）
```
