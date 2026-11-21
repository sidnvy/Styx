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
