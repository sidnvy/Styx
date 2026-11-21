# Gateway MCP 接入

Gateway 在同一套设备目录和工具后端上提供 `/mcp`。OpenAI Private Tunnel 和 Public HTTPS 是客户端接入方式。Public HTTPS 由部署提供域名、证书和反向代理，Gateway 继续使用原监听地址及设备信任。

Streamable HTTP 由锁定的 rmcp SDK 提供。当前使用有初始化与会话的 MCP 语义，协商版本为 `2024-10-07`（旧客户端兼容）、`2024-11-05`、`2025-03-26`、`2025-06-18` 和 `2025-11-25`。JSON 和 SSE、取消通知、会话关闭均沿用现有行为。客户端断连或会话关闭时，Host 按现有规则保留其 Exec 任务和 Browser profile。取消请求后，已派发操作仍可能产生效果。

## Public HTTPS

在 Gateway 私有状态目录中配置 `public-mcp.json`。Gateway 启动时读取，使用受保护的文件访问。外部 URL 使用规范 HTTPS URL，路径为 `/mcp`，外部 Host 与本地 Gateway authority 分开。代理保留该外部 `Host`，配置上游 TLS 验证，并且只转发 `/mcp` 和 OAuth 模式所需的元数据路径。保留认证、MCP 协议版本、会话和 SSE 重连 headers。转发工具结果时关闭缓存并允许持续流式传输。

静态 Bearer 示例：

```json
{
  "url": "https://styx.example.com/mcp",
  "authentication": { "type": "bearer" }
}
```

普通客户端使用 Gateway 的 model bearer。默认接受省略 Origin 的请求。如果客户端发送 Origin，在 `allowed_origins` 中列出确切的 HTTPS Origin。Gateway 按实际 Host 和 Origin 准入，转发 header 或 JSON-RPC metadata 不授予身份。

## OAuth 资源服务

```json
{
  "url": "https://styx.example.com/mcp",
  "authentication": {
    "type": "oauth_introspection",
    "issuer": "https://identity.example.com/realms/styx",
    "introspection_url": "https://identity.example.com/realms/styx/protocol/openid-connect/token/introspect",
    "client_id": "styx-mcp-resource",
    "allowed_subjects": ["subject-issued-for-the-allowed-operator"]
  }
}
```

将 introspection client secret 的原始 UTF-8 内容写入同一私有状态目录的 `mcp-oauth-client-secret`，文件权限与其他 Gateway 凭据相同。Gateway 使用 `client_secret_basic` 调用已配置的 HTTPS introspection URL。外部入口在此模式仅接受通过 OAuth 验证的 access token。静态 bearer 和 Tunnel 转发凭据不能在该入口通过认证。

OAuth 客户端通过 `401` 响应的 `WWW-Authenticate` 或 `GET /.well-known/oauth-protected-resource/mcp` 发现授权服务器。部署方配置授权服务器登录、客户端注册和 access token 发放。Gateway 对每个 MCP HTTP 请求调用 introspection，并要求 `active`、有效的 `exp`、匹配的 `iss`、`Bearer` token 类型、有效的 `sub`，以及包含完整外部 MCP URL 的 `aud`。若返回 `nbf`，必须已经生效。JWT 和不透明 access token 都通过同一 introspection 契约验证。配置允许的主体仍然拥有本部署完整 MCP 管理权限。

同一 issuer 和 subject 在 token 刷新后保持相同 principal。每个新 MCP 会话仍有自己的 Gateway owner。该约定基于 [MCP 2025-11-25 Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)、[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) 和 [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html)。

## 设置与验收

首次配置 Gateway 时，在 App 或 styx setup 中选择 Public HTTPS 或 OpenAI Private Tunnel。若已配置 Gateway，使用 App 的连接设置，或在 Gateway 停止时运行 styx gateway public-mcp configure，传入保护好的配置文件和对应的私有密钥文件。命令帮助列出参数。重新启动后用 styx gateway public-mcp status 查看已保存的 URL 与认证方式。由命令和 App 保存时，配置绑定到一个私有密钥文件版本，完整配置提交后替换旧版本。

从客户端网络发起无凭据请求。HTTP 401 和资源发现响应验证 HTTPS 及挑战的可达性。在目标 MCP 客户端配置所选认证，发现工具后列出配对设备，再对目标 Host 发起一次获准的低影响调用。记录实际网络、认证、工具发现和 Host 效果。用于 OAuth 验收的 Keycloak 26.8.1 配置为预注册的 PKCE 客户端，以及向 introspection 返回完整 MCP 资源 URL 的 audience。公开部署可选能满足同一契约的授权服务。

已有 Tunnel 可以与显式 Public HTTPS 配置共用一个 Gateway。已配置 Public HTTPS 时，导出选择 Public HTTPS。插件 ZIP 只声明连接和认证类型并附带 skills。Custom MCP 连接在客户端单独建立。旧桥接只有在替代入口通过实际账户和 Host 验收后才进入迁移停用步骤。

## 替换旧入口

1. 从已经合并到 main 的新版本生成正式 GitHub Release。记录 Gateway 和受测 Host 选中的 Runtime manifest 与实际进程版本。
2. 在隔离环境配置候选 HTTPS URL，逐项核对 OAuth 发现、授权、工具发现、Host 调用与断开后的生命周期，再验证 Private Tunnel 原路径。复用原设备身份与 Browser profile。
3. 共享 Gateway 切换前，检查在用连接和运行任务，保留旧路由、可恢复配置和上一套签名资产。让新路径使用独立外部 authority，先验证新路径，再迁移客户端。
4. 独立客户端确认新入口的实际工具调用、显示名和图标。若结果不确定，检查该入口的原始请求和 Host 效果。确认替代入口服务正常后，才停用临时 bridge、撤下旧 DNS/Access 接入并删除源码中的遗留 forwarding 特例；每项对准实际部署对象。
