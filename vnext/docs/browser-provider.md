# Browser provider 开发验收

2026-10-20。本文记录独立 Browser 开发分支的实现，不代表已发布的 Styx App 已包含 Browser。

## 实际调用链与边界

模型调用一个 Gateway 的 `browser_*` 工具 → Gateway 核对设备授权、owner 和当前引用 → 已认证的 Host Browser WebSocket → Host 持有的 Playwright MCP 实例 → Styx 专用 Chromium context。

Browser 与 Exec、Cua 并列。Gateway 仅按工具名转发，不解释任务语义、不自动改用 Cua、不重放失败操作。没有 Browser 授权的设备不接受 Browser lane；撤销或代次变化后旧引用不能继续使用。Gateway-only 的签名源码闭包包含小型工具契约，不包含 Playwright 运行时或 Chromium，不准备 Exec/Cua。

`deployment.json` 中可选的 `host.browser={enabled,headless?,executablePath?}` 表达期望；默认缺省为关闭。现有 enrollment 签名覆盖 Browser 请求，主台另行明确批准。`requested` 不等于已授权。Host 私有 `host.json` 保存获批能力及派生的 `baseDir/browser`；不增加角色配置文件。headless Browser 不要求 GUI，也不表示 Cua、辅助功能或录屏已就绪。

## 上游接口

锁定 [Playwright MCP 0.0.83](https://github.com/microsoft/playwright-mcp/tree/f183dad4a52965583e3cc1d59b88cdc279e2e57d)，以及该包依赖的 `playwright` / `playwright-core` **1.64.0-alpha-1790635538000**。后者版本带 alpha 标签；这不是稳定版 Playwright 的验收承诺。版本、tarball integrity、完整工具 schema 存在 package lock 和 `playwright-contract-0.0.83.json`，运行时与上游实际目录逐项核对，不跟随 latest。

复用24个原生工具及完整 schema，只增加现有 `environment_id`。保留 `target`、`startTarget`、`endTarget` 和表单字段中的 `target` 名称，不另造 page/session 操作接口。未暴露 `browser_run_code_unsafe`；该上游版本没有单独 `browser_install` / `browser_download` 工具，安装由 Core 管理，下载由正常网页操作触发。仍允许上游的页面内 `browser_evaluate`，它不提供 Node 运行环境。

Gateway 将显式内联 `browser_snapshot` 的原生引用值改为不透明 `styx-…`，绑定聊天 owner、设备、代次和当前观察。快照更新、导航（包括网页自行跳转）、切标签、操作和重连使旧引用失效；另一聊天的引用以及裸 `eN` / `fNeN` 被拒绝。上游 locator 字符串仍由同 owner 的 context 处理。保存到文件的快照保留上游文件内容，不作为可直接使用的引用来源；下一次操作先取无 filename 的快照。

上游 schema、截图图像及文件结果保持原生结构。超过既有8MiB传输帧的结果返回紧凑 `browser_frame_limit`；过大请求在发送前拒绝，不伪报已执行。

## Context、资料和生命周期

每个 MCP HTTP owner 与设备组合对应独立 Host context、当前标签及专用 profile/output。资料与 Exec 工作目录必须按真实路径互不包含，symlink 重叠也拒绝；文件工具沿用上游的真实路径校验。直接 `file:` 导航拒绝。此处隔离防止聊天互相使用 profile，并不将同一 OS 用户下的 Exec 变成文件系统沙箱。

同一个 Host WebSocket 重连复用真实 context，不清除登录资料，不重建设备身份。主动 `browser_close` 确认真实 context 关闭后释放运行资源，同 owner 再打开可保留网站存储。不同 MCP HTTP owner 使用不同 profile：**不承诺新聊天自动继承原聊天登录**。没有自动导入日常 Chrome/Edge 资料。HTTP 会话 DELETE 或无活动15分钟回收 context，保留 profile；活跃及排队操作不被闲置回收。没有新增 MCP 会话数或累计 Browser 操作数上限。

SDK 超时或连接结果不确定不等于原生操作已停止。Host 将 lease 标为 unknown，拒绝后续操作，直到明确 `browser_close` 确认关闭；关闭不会声称上一步没有生效，也不会自动重试。停止等待进行中的启动以及真实 context 关闭；关闭失败保留句柄与 unknown 状态。Gateway 停止先取消未完成握手，再等候连接清理。Host Browser 准备或连接失败独立重试，不令 Exec 退出。

实际进程状态、连接状态、页面操作结果、系统权限与聊天账号验收分开。被动状态读取与工具发现不启动浏览器；Browser lane connected 不会变成页面 ready。实际原生结果通知才记录 ready_observed；重连后未再观察时保持 unknown。

## 自动准备与同一 Core API

Host 已获批准且缺省未指定 executablePath 时，使用固定版本 Playwright CLI 在私有 runtime cache 准备 Chromium；不安装系统包，不修改系统权限，不使用用户日常资料。可在启动前通过同一 Core 提前准备：

```sh
node onboarding/cli.mjs browser /private/setup-state
node onboarding/cli.mjs browser-prepare /private/setup-state --authorize
```

App 后端对应 `GET /api/browser` 与 `POST /api/browser/prepare`。无收据且准备锁仍在时显示 `preparation_blocked`，不显示已准备；`browser-prepare STATE --recover --authorize` 或同一 POST 的 `{authorize:true,recover:true}` 显式请求恢复。锁记录准备者、下载子进程及POSIX进程组；确认都不存活后才回收。存活/身份不明的准备者、未记录完成的spawn窗口、残留恢复claim、Windows缺少进程树退出证明时保留阻塞。更上层遗留的Core管理锁也需要原有对账流程，本命令不会删除它。Core 校验既有设备身份、凭据、发布者和当前签名 Host release，仅从该 release 导入准备模块。旧 bundle 缺 Browser 时明确要求更新 bundle，不重新配对。`prepared` 仅表示版本、平台、私有收据及实际可执行文件 SHA256 通过校验，**不是 Browser 可操作或聊天可用**。浏览器启动显式开启 Chromium sandbox。

Browser-enabled Host 构建使用 `buildHostRelease({browserRuntime:true,...})`，复制精确锁定依赖并纳入既有签名 manifest。构建器CLI也接受末尾 `--browser-runtime`。默认 Host bundle 保持原闭包。没有把浏览器 profile 或现有安装资料放进包。

## 验收与尚未完成

真实 Linux 浏览器测试使用新建临时 profile、loopback HTTP Gateway、已认证 Host WebSocket、两个真实 SDK MCP 客户端。已覆盖独立页面/标签及 localStorage、跨 owner 和过期引用拒绝、断连后不重放点击、截图、文件上传/下载、关闭再打开保留测试网页存储、删除一方会话不影响另一方，以及撤销后拒绝调用。另用固定版本下载的托管 Chromium 跑同一测试。没有用模拟浏览器结果宣称这些原生操作通过。

Core 有独立 Browser challenge：同 owner、设备与代次成功导航固定无凭据 data URL，再以真实 snapshot 读回唯一 heading，才记为 Browser verified。Exec、Cua 及目标聊天的用户确认仍独立要求。通过本机 SDK 测试不能证明 ChatGPT 账号已创建/安装/连接插件。

以下仍待集成或验收：

- 旧部署开启/关闭 Browser 的完整 Core 迁移与回滚。底层已支持保持身份的独立签名 Browser 授权变更；产品管理 API 当前明确阻止缺少事务的迁移，不自动修改 deployment/host 或重装身份。
- 原生 macOS/Windows App 打包、首次安装、登录/注销/重启、升级/回滚及交互式网站登录。
- 官方 Chrome/Edge 扩展接入、受控 CDP、已有日常浏览器关联；当前不提供这些模式。
- 普通 onboarding 的 Browser 选择、准备和失败恢复界面；独立 UX thread 负责后续产品界面集成。
- 真实 ChatGPT/Codex 账号插件调用、动态工具目录刷新及选择效率评测。

未部署到 piermini、NAB 或 Pilot Mac；没有改动它们的服务、配置、安装应用或权限。本分支提供源码、Core/Host/Gateway 接线与隔离测试结果，尚不是完整正式产品或可首装的 App 安装包。

## 复现

在 `vnext` 中按锁文件安装 JS 依赖，Browser 运行时依赖在独立包内安装；系统浏览器例子只用于明确选定的测试二进制，不继承日常 profile。

```sh
npm ci --ignore-scripts
npm ci --ignore-scripts --prefix packages/styx-browser-provider
python3 packages/styx-exec-adapter/prepare-runtime.py
npm run test:all
STYX_BROWSER_NATIVE_TEST=1 STYX_BROWSER_EXECUTABLE=/absolute/chrome node --test gateway/test/browser-native.test.mjs
STYX_LIVE_BROWSER_TEST=1 STYX_TEST_BROWSER_BINARY=/absolute/chrome node --test onboarding/test/account-acceptance.test.mjs
```

未设置 opt-in 的原生用例标为 skipped；协议 fixture、签名构建 fixture 和 SDK 超时测试不属于原生平台或账号验收。
