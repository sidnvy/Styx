# Styx 本机设置引导

普通用户按七个步骤完成本机准备、系统权限、后台偏好、账号平台入口、ChatGPT 插件创建／复用与安装、真实工具请求、目标聊天来源确认。侧栏和顶部位置来自共享 Core 的 journey 投影；本机运行、系统授权、MCP 请求证明和用户来源确认分别显示。

完整 App 自动带入软件包、公钥、发布者信息和本机连接默认值。设备名、能力选择和明确同意构成普通路径；目录、Team ID、端口及网络开放选项放在默认折叠的高级详情中。缺少内置组件会说明原因，不能把任意路径视为已验证的安装包。

“加入已有 Styx”要求独立核对邀请中的 Gateway 与证书。保存后只依次授权既有 Core 的 Host prepare/request/claim/doctor 步骤；等待主台独立审批，再由用户检查审批并继续。不会创建 Gateway、自动信任网络发现、创建第二条账号隧道或要求新设备取得主台管理凭据。新设备的账号验收回到已有主台的聊天完成。

## 生命周期与权限

前台按钮先将偏好保存到同一 Core，再明确调用 `/api/foreground` 启动或恢复本次连接。Core 负责复用已有身份和已运行的系统服务，避免重复启动；设置服务关闭时清理自己拥有的前台进程。登录后台另行选择和授权。偏好保存本身不显示为连接已运行。

系统权限由用户亲自完成。辅助功能、屏幕录制和显式应用脚本的 Automation 分开说明。macOS 设置链接仅在用户点击时由原生设置窗口转交系统处理；页面不授予权限、不改系统数据库。终端连接可以先使用，桌面能力保留独立的授权、观察和实际操作验收。

## 账号连接与真实验收

每次安装都检查“首次创建”还是“复用已有插件”。首次允许自定义名称、简短描述、详细描述和 PNG 图标，保存到 Core 的本机账号引导记录，不改变 deployment.json 中的设备角色。复用需要用户明确提供原插件地址，不能自动推测账号已有插件；加入已有主台的电脑不另建插件。

插件 ZIP 由 Core 对真实本机 TLS Gateway 做认证发现与只读调用后生成。导出、用户确认创建／上传、用户确认安装、真实聊天调用分别显示。账号操作仍在官方网页或受支持 Plugin Creator 中完成；没有后台上传接口、账号登录回调或账号侧自动发现。生成器目前保留原 Bearer 声明；隧道本机转发也注入 Gateway 凭据，故额外手填 Bearer 的必要性尚未验收，已从普通必填步骤移入高级说明。

macOS 内嵌网页不能直接完成 Blob 下载，使用受主 frame／同源限制的固定 ZIP 字节桥打开系统保存面板。保存返回与取消返回分开显示，不把包生成记录当成文件已保存。App 与 CLI 共用插件资料和导出 API；普通诊断仅显示经过白名单过滤的阶段状态，不带图标、账号备注或凭据。

官方账号平台和 ChatGPT 链接在系统浏览器打开，用户完成登录后手动返回。没有伪造的 OAuth callback，也不把本机设置会话附加到外部 URL。

隧道运行密钥只提交到本机受保护 API；发送前清空输入框，失败不会回显。专用 Bearer 工具凭据只在用户明确请求后显示为只读密码字段，可由用户复制到 ChatGPT 认证字段。显示最多保留 60 秒，在页面隐藏、离开、手动清除或配置不可用时清空。这个期限只限制显示，不宣称服务凭据已过期或轮换。它不会进入通知、聊天验证 prompt、浏览器存储或正常状态投影。

真实聊天验收由 Core 提供带时限的固定请求。页面不能通过 SDK 发现、点击按钮或手动填写标记使其通过。桌面验收输入框向受保护 API 读回当前 DOM 值；真实截图、输入与后续观察仍由生产 MCP 调用证据判断，并绑定生成请求时观察到的原生 Styx App PID、同一窗口与 snapshot。必须通过 get_window_state 观察当前设置窗口；单独 get_desktop_state 不替代这项验收。若当前 App 尚未被观察到，先完成权限、重新打开 Styx，再生成新的请求。相同 challenge 的常规刷新保留输入值；替换或过期时清除。

只有真实终端请求和所选桌面证据满足条件后，才能记录用户“已在目标聊天看到结果”的确认。页面明确该来源是用户确认，`providerIdentity` 仍未认证，不能冒充平台身份认证。

## Technical operation and security reference

This local browser control plane uses `onboarding/core.mjs` and can be hosted by
the native App. The page itself is not evidence of native package acceptance.
It supports guided create-local or join-existing configuration, terminal/desktop
capability selection, authorized Core workflows, persisted progress/resume, account
prerequisites, fixed Host doctor checks, and process-owned foreground lifecycle.
Advanced controls retain separately authorized one-step maintenance operations.
System service changes are offered only when a fixed supported core adapter
is available and require separate authorization. Login startup is shown from
observed backend state, never inferred from browser preferences. The actual Gateway runtime is shown separately from successful
journal entries. `uncertain` steps are never offered an automatic retry.

Run with the project's supported Node runtime and the core module installed:

```sh
node vnext/onboarding/server.mjs --state /absolute/private-parent/new-deployment
```

The parent must already be private to the current user, as checked by the core.
Use a new deployment directory initially; reopening the same directory resumes
its persisted journal. The terminal prints a private local URL. Open that full
URL in a trusted browser. Its random fragment is removed from history after
bootstrap and the session is kept in that tab's session storage. Do not share
the URL. A server restart creates a new session, requiring the new URL. No
credentials from a previous chat are needed or used.

The listener always binds `127.0.0.1`. Every API request requires its random
bearer; mutations additionally require exact Origin and a separate CSRF value.
Host names are pinned, no CORS is enabled, static paths are an explicit allowlist,
and config requests cannot choose executable helpers or arbitrary commands.
The UI never serves stored config, invitations, account credentials or raw core
exceptions. Only recognized progress states, actual local Gateway state, bounded
error codes and the public device fingerprint/approval requirement are projected.

Local Gateway creation requires a trusted OpenSSL executable configured by the
local launcher, never selected by the browser. macOS/Linux default to
`/usr/bin/openssl`. Where that path is absent or a symlink, configure a trusted
regular executable using `STYX_ONBOARDING_OPENSSL`; the core checks it before
use. Windows requires this explicit helper configuration for create-local.
Join-existing can use a trusted administrator's Gateway and a local invitation
file, or import a private pairing link after independent inspection and confirmation
(described below). It does not accept raw invitation JSON. In a complete packaged
App, trusted launcher defaults supply software bundle/public key paths and the publisher fingerprint; advanced deployments can inspect these
public trust inputs in the collapsed installation details.
This interface does not download unverified bundles.

## Headless host with explicit trusted forwarding

Keep the setup listener private and use a trusted SSH/local forwarding channel.
For example, reserve port17895 on the host, forward that port to localhost17895
on the browser machine, and start with:

```sh
STYX_ONBOARDING_PORT=17895 \
STYX_ONBOARDING_BROWSER_ORIGIN=http://localhost:17895 \
node vnext/onboarding/server.mjs --state /absolute/private-parent/new-deployment
```

The printed URL uses the explicitly configured browser origin. Only loopback
HTTP browser origins are accepted; binding remains127.0.0.1. The user configures
the authenticated SSH tunnel separately. Never expose this admin listener on a
LAN/public address, use an untrusted reverse proxy, or forward to a shared
browser. Windows can set the same environment variables in its local shell.
No tunnel is created automatically.

## Verification

`node --test vnext/onboarding/ui/server.test.mjs` checks unauthenticated routes,
Host/Origin/CSRF boundaries, executable/command refusal, redacted state, trusted
forwarding, mutation serialization and supported local start/pause dispatch.
`ui/browser.test.mjs` is opt-in and requires a trusted Chrome/Chromium binary:

```sh
STYX_ONBOARDING_BROWSER_TEST=1 \
STYX_ONBOARDING_BROWSER_BINARY=/absolute/path/to/chrome \
node --test vnext/onboarding/ui/browser.test.mjs vnext/onboarding/ui/journey.browser.test.mjs
```

The browser test uses a fresh isolated profile, real core, private TLS Gateway,
and explicit UI interactions. It checks save → prepare → actual running → stop →
reload/resume, then cleans only its own temporary state/browser/Gateway. It never
prepares or enrolls a Host. An alternate absolute `STYX_ONBOARDING_CORE_MODULE`
may point to a separately checked-out core during development. The observed run
was on Linux; native Windows/macOS graphical wrapper acceptance is NOT RUN.
ChatGPT connection/account acceptance, native installers and system service
installation are NOT RUN by these tests. Initial security-test failures in test
mock cleanup and a fetch-normalized Host-header test were corrected; final HTTP
suite passes. Desktop/mobile layout were rendered with isolated headless Chrome.

`journey.browser.test.mjs` uses real isolated Chrome with explicit API fixtures.
It verifies ordinary packaged defaults, foreground preference-before-start ordering,
joiner approval waiting without a second Gateway/account entry, runtime key failure
clearing, timed and hidden-page credential clearing, independent proof and user
confirmation states, desktop DOM readback and mobile layout. Fixture proof changes
verify rendering only; they are not native or real-account acceptance.

## Guided defaults and local pairing

The session now suggests a device label, an unused-at-check loopback Gateway
port and a fresh Host directory beneath the explicitly configured private parent.
It does not create that Host directory or reserve the port until authorized
execution. Existing files/ports are never silently replaced. Host package, public
key and publisher fingerprint remain verified trust inputs supplied by a complete
App, with manual review available in advanced installation details. A local trusted
launcher may prefill only those three public artifact fields using an owner-private
`STYX_ONBOARDING_ARTIFACTS` JSON file with keys `bundle`, `publisherKeyFile`,
`publisherSha256`; unknown fields, including credentials, are rejected. The Core verifies the signed package; ordinary packaged users are not required
to type or select publisher paths.

For create-local, the ordinary local-setup workflow derives its explicit owner
approval from the saved device label and requested capabilities. Advanced
`host.pair` maintenance still displays the exact Gateway, device label and scope.
Approval is sent as a structured scope and the Core checks it against the saved plan. No
invitation/admin credential is copied through the browser. Join-existing keeps
the separate administrator approval flow. `gateway.verify` is transport/tool
verification, not account verification.

The additional Gateway check accepts only a local credential **file path**, a
Gateway MCP URL and optional CA file path, with both explicit independent/fresh
connection attestations. The verifier reads private files locally. The response
contains only SDK verification status and `accountAcceptance: NOT RUN`; neither
credential contents nor paths are returned. The credential path field is cleared
after each attempt. Exceptions are fixed redacted errors. Actual browser testing
verified that the generated model credential never appears in page text.

To exercise the complete native preparation/pairing flow in an isolated browser,
add `STYX_ONBOARDING_NATIVE_BUNDLE=1` plus absolute
`STYX_ONBOARDING_NODE_BINARY`, `STYX_ONBOARDING_CODEX_BINARY`, and
`STYX_ONBOARDING_CUA_BINARY` to the browser-test command. This builds a fresh
pilot-signed bundle with the fixed Node22.23.3 provenance and existing pinned
Codex0.163.0/Cua0.36.0, using an ephemeral publisher key. The observed Linux run
passed real TLS Gateway preparation/start, authenticated discovery (both the
core step and browser check), signed native Host preparation, explicit scoped
owner pairing, `doctor: ready_for_exec`, pause and reload/resume. Every test
state, browser profile, local Gateway and ephemeral key was cleaned. No system
service was installed and desktop capability was disabled. This stronger opt-in
mode supersedes the earlier Gateway-only test's narrower coverage; the default
browser mode still does not prepare a Host. The recorded historical security run had 10 PASS; this count is not a claim about the current full suite.


## Fixed service controls

When `controlDeploymentHostService` is available, Host maintenance exposes only
install/start/stop/status with explicit authorization. The core derives the
service identity and private signed configuration; the browser cannot provide
a service name, manager command, executable or config path. Installation and
start are separate steps after the Host doctor. Running is not claimed to prove
account acceptance or tool health.

Persistent Gateway service controls appear on supported Linux, macOS and
Windows platforms when the independent `gateway-service.mjs` facade is present. Install/start/stop/enable/disable/status/
uninstall are fixed actions; uninstall preserves deployment data. Foreground
Gateway ownership is checked server-side before persistent start. The UI requires
stopping its owned foreground Gateway first. Linux Gateway startup and login enablement are separate explicit actions.
macOS/Windows Gateway start also enables login startup, and stop disables it;
button text and confirmation disclose this coupling. Windows enable also enables
minute-based recovery, which may start the background task at its next minute.
Actual observed `enabled`/persistence state replaces the earlier browser-only
preference; unknown native state stays unknown. Platform capability does not
assert that any service is installed, and a running foreground Gateway does not
assert that a persistent service is absent.

Service observations have timestamps and are not a live heartbeat. A new UI
process starts with unknown observations until an explicit status request; it
never treats a successful old action as current process health. Security
regressions cover arbitrary-scope/action denial, authorization and secret path/
stdout suppression. Actual system service installation is not performed by the
browser native-pairing test; native adapter acceptance is separate evidence.

## Private pairing link and separate device approval

A joiner can paste a `styx://join#…` link into the password input on this local
page. The link is never navigated to, placed in a URL query/history, persisted
in browser storage or written into public status. Inspection retains it only
in server memory and projects the Gateway origin, expiry and optional DER
certificate fingerprint. The user separately confirms that origin/pin through
a trusted owner channel. Acceptance writes private invitation/CA references;
the later join configuration is bound to those references without manual
invitation paths or JSON. Public preview is not proof of the sender's identity.
The Gateway still enforces expiry and one use.

The owner can create a one-use link or list pending devices using the fixed
private owner API. The link appears only in an explicit authenticated response
and a password field, with user-triggered copy; it never appears in normal
status. Device approval remains separate: both sides show a grouped16hex
human comparison code, with the full64hex fingerprint available in details.
The owner must enter the independently compared code (or full hash) and choose
desktop capability explicitly. The server reloads the current pending request,
compares the typed code, then submits its full fingerprint to the Gateway.
The64bit comparison code is a human comparison aid, not a replacement for full
cryptographic identity binding. No approval input is prefilled.

LAN listening is optional and capability-gated by core's native IPv4 interface
list. Default listening remains loopback. A user must explicitly opt into network
exposure and select an owned interface; the exact HTTPS host must match. No DNS,
wildcard bind, tunnel, router or firewall changes are performed. A configured
interface/link does not establish remote reachability; unverified reachability
is displayed honestly.

Historical observed tests: 13 HTTP/security PASS, plus a real browser test with two
native signed Host installations on the same machine. The browser created the
owner's private link, inspected/confirmed it in a second local setup session,
prepared the second Host, requested enrollment, separately approved the typed
comparison code on the owner page, claimed the result and passed Host doctor.
Both Hosts used official fixed native runtimes and temporary publisher trust.
No Host service was installed. This is same-host HTTPS onboarding evidence,
not a claim that a second physical machine or ChatGPT account connected.
The test supports an optional absolute `STYX_ONBOARDING_SCREENSHOT_DIR`; it
clears link fields before saving desktop/mobile screenshots. All test browser
profiles, Gateway instances, private pairing state and ephemeral keys are removed.
