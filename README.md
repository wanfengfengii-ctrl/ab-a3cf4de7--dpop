# Calibration Bundle Service

计量实验室校准证据包下发服务。合作方凭**短效访问令牌 + DPoP 持有证明**下载证据包：
即使令牌泄漏，没有绑定私钥也无法复制使用。

## 接口

```
GET /api/calibration-bundles/{bundleId}
Authorization: DPoP <access-token JWT>
DPoP: <proof JWT>
```

成功 `200`：

- 响应体：证据包**原始字节**（启动时校验过摘要、只读挂载的同一批字节，多次下载完全一致）
- `X-Content-SHA256: <64 位小写十六进制>` 摘要响应头
- `Cache-Control: no-store`

失败：JSON `{"error": <稳定错误码>, "error_description": <说明>}`，401 时附
`WWW-Authenticate: DPoP ...`。

## 安全模型

**访问令牌**（注册签发方 ES256 签署的 JWT）校验：

- 签名（签发方 P-256 公钥，Compose 挂载）与 `alg == ES256`
- `iss` 签发者、`aud` 受众、`sub` 主体（必须存在）
- `scope` 含 `bundles:read`（否则 403）
- `exp`/`nbf` 有效期（可配置时钟偏差）
- `cnf.jkt`：DPoP 公钥的 RFC 7638 拇指印（发送方约束）

**DPoP 证明**（ES256）校验：

- 头 `typ == "dpop+jwt"`、`alg == ES256`、内嵌公开 `jwk`（EC P-256，不含私钥成员）
- 用内嵌 jwk 验签；jwk 拇指印必须等于令牌的 `cnf.jkt`（**密钥绑定**）
- `jti` 存在且**一次性**：SQLite 主键原子占位，并发下同一证明只放行一次；
  数据库在命名卷上，**重启后仍不可重放**
- `iat` 在短窗口内（默认 120s，Compose 设 300s）
- `htm == GET`
- `htu` 必须等于 `PUBLIC_ORIGIN` + 请求路径拼出的**完整公开 URL**（不依赖 Host 头）
- `ath == base64url(SHA-256(access token))`（证明与令牌互锁）

### 稳定错误码

| 类别 | 错误码 |
|---|---|
| 令牌缺失/结构 | `missing_token`, `malformed_token`, `invalid_token_type`, `invalid_token_alg` |
| 签名 | `invalid_token_signature`, `invalid_dpop_signature` |
| 注册信息 | `invalid_issuer`, `invalid_audience`, `missing_subject` |
| 权限 | `insufficient_scope` (403) |
| 时效 | `token_expired`, `token_not_yet_valid`, `dpop_proof_expired` |
| 绑定 | `missing_cnf`, `invalid_cnf`, `dpop_key_binding_mismatch`, `invalid_ath` |
| 证明结构 | `missing_dpop_proof`, `malformed_dpop_proof`, `invalid_dpop_typ`, `invalid_dpop_alg`, `invalid_dpop_jwk`, `invalid_htm`, `invalid_htu`, `missing_jti` |
| 重放 | `dpop_replay_detected` |
| 证据包 | `bundle_not_found` (404) |

## 运行（Docker Compose）

```bash
# 一键验证：构建 -> 健康检查 -> 代码测试 + 构建 + 下载/篡改/并发重放冒烟
docker compose up --build --exit-code-from verify verify
echo $?   # 0 = 全部通过；verify 报告后自行退出

# 仅启动服务（宿主机端口可配置）
HOST_PORT=9000 PUBLIC_ORIGIN=http://localhost:9000 docker compose up --build app
```

服务组成：

- **keygen**（一次性）：生成演示用 ES256 签发方密钥对与 DPoP 密钥对；公钥进
  `keys-public` 卷（应用只读挂载），私钥进 `keys-private` 卷（仅 verify 可见）。
  幂等，重启不轮换。生产环境应换成真实签发方公钥。
- **app**：FastAPI + uvicorn，非 root 运行，镜像内置 `HEALTHCHECK`（`/healthz`），
  端口映射 `${HOST_PORT:-8080}:8000`。
- **verify**（一次性）：`depends_on: service_healthy` 后执行
  ① pytest 代码测试 ② `compileall` 构建检查 ③ 冒烟：合法下载（字节与摘要头比对、
  二次下载字节一致）、20 项篡改矩阵（逐一断言稳定错误码）、16 路并发重放
  （恰好一次 200，其余 `dpop_replay_detected`）；挂载 docker.sock 时还会重启
  app 容器验证重放库跨重启持久（无 socket 则跳过该项）。以退出码报告结果后退出。

## 配置（Compose 环境变量）

| 变量 | 说明 |
|---|---|
| `HOST_PORT` | 宿主机端口（默认 8080） |
| `PUBLIC_ORIGIN` | 对外公开源，用于拼 `htu`（默认 `http://localhost:${HOST_PORT}`） |
| `TOKEN_ISSUER` / `TOKEN_AUDIENCE` | 令牌签发者 / 受众 |
| `ISSUER_PUBLIC_KEY_FILE` | 签发方 ES256 公钥 PEM 路径 |
| `BUNDLE_<1..8>_FILE` / `BUNDLE_<1..8>_SHA256` | 编号证据包（只读挂载）+ 小写 SHA-256；两者须成对，启动时校验文件实际摘要，不符拒绝启动 |
| `DPOP_IAT_WINDOW_SECONDS` | DPoP `iat` 短窗口（默认 120） |
| `TOKEN_CLOCK_SKEW_SECONDS` | 令牌时钟偏差（默认 30） |
| `REPLAY_DB_PATH` / `REPLAY_RETENTION_SECONDS` | 重放库路径（卷上）/ 保留期 |

## 本地开发

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest                                   # 单元/集成测试（33 项）
python scripts/gen_bundles.py bundles 3            # 重新生成示例证据包并打印摘要
```

## 布局

```
app/        config(启动校验) / security(令牌+DPoP) / replay(SQLite jti) / main(路由) / keygen
client/     参考客户端：铸造令牌与证明（tests 与 verify 共用）
tests/      pytest：33 项，含并发重放（真实 uvicorn）与重放库重开持久化
verify/     一次性验证服务入口 verify.run
bundles/    示例证据包（确定性生成）
Dockerfile  多阶段：base / app / verify
```
