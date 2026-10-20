# Styx 产品边界与实现对照

2026-10-19：用户确认的目标架构。本文件区分目标与当前实现，不是功能完成声明。

2026-10-20：用户已固定 v6 产品流程。最新实施约束与当前差异见
[从现有版本演进到 v6](product-evolution-v6.md)。下文保留的七步网页引导、前台／后台
首装选择和登录恢复现场记录描述历史实现，不覆盖新的产品决定：欢迎页只有开始／加入，
语言在设置中；Browser 是独立执行能力；关闭窗口继续运行，退出停止 App 所有组件及其
当前恢复；登录启动独立设置；主界面为概览、电脑、聊天连接，活动入口暂隐藏。
App 管理范围以实际 ownership 为准，不能误停 CLI 独立管理的 Core。

会话身份、资源限制与尚未产品化的长期自主任务见[会话与任务生命周期](session-and-task-lifecycle.md)。

## 三种用户流程

1. 单机：一个Styx App，默认Gateway＋Host；Codex调用确定性安装接口，用户完成系统授权、
   私有MCP关联及聊天端真实验收。无需理解角色或开启多设备。
2. 多机：主台“添加电脑”负责安全可达入口及配对；新电脑明确选择加入后仅运行Host。
   网络发现不构成信任，也不能自动切换已有部署角色。
3. 高阶：Core在headless环境运行，由CLI管理；支持Gateway-only、Host-only（Exec）、
   或两者是目标。没有桌面会话不启用Cua。

App与CLI是管理入口，能力由角色和环境决定。CLI可以管理GUI设备上的Cua，但不会因此
继承桌面权限。GUI主台也可以仅运行Gateway。新增Host不获得设备组管理员凭据。

## 组件与数据责任

| 组件 | 责任 |
| --- | --- |
| Gateway | MCP入口、设备身份/审批、能力授权、转发；不承担本机桌面权限 |
| Host | 本机连接、Exec Server生命周期、可选Cua连接 |
| Cua | 有效桌面会话内的观察与操作，不管理网络信任 |
| App | 原生权限身份、设置、状态、后台生命周期 |
| CLI | 同一Core的确定性管理接口 |
| Core | 共享配置验证、计划、执行、状态与恢复 |

一个安装有一个受保护配置根。期望配置、执行日志、实时状态与凭据各自有明确权威来源，
不能互相冒充。App与CLI使用同一API。Gateway目录负责整组授权，Host保存自己的身份与
本机能力意愿。运行时配置和服务定义是派生数据，变更应通过迁移事务生成，而非分别手改。
系统权限以OS为准，不能在JSON中伪造授权。

## 当前实现

| 领域 | 现有源码依据 | 缺口 |
| --- | --- | --- |
| 单机/加入 | onboarding/core.mjs的create-local和join-existing；加入无Gateway准备步骤 | 已支持省略Host的Gateway-only，要求独立签名Gateway包；六种配置组合已测，原生组合待验收 |
| 共用核心 | onboarding/cli.mjs与server.mjs共用core.mjs | App/CLI共用服务、后台、配对、入口预检、迁移及Gateway更新接口；Host更新管理仍待完整接入 |
| 配置 | deployment.json、state.json、派生gateway/runtime.json、Host配置、service.json | 新增保留身份的原生监督器离线配置迁移及回滚；在线迁移和统一Host更新仍有缺口 |
| 生命周期 | onboarding/background.mjs与平台服务适配器 | Gateway服务已独立；App关闭不等于服务停止，登录/重启及权限链仍需原生验收 |
| macOS | host/macos/Styx.swift启动嵌入Cua和权限界面 | 新增Team-ID绑定的Styx --host-service监督链，旧服务默认保留Node路径；TCC责任归属尚未验收 |
| Windows | windows-task.ps1与Host安装/测试基础 | 尚无与Mac同等完整且验收通过的App配对体验 |
| Headless | gateway/cli.mjs可以单独运行Gateway | 独立签名应用包可脱离Host及源码运行；原生服务、无人登录启动和真实重启仍需验收 |
| 配对 | enrollment.mjs、pairing-links.mjs具备一次性邀请、独立审批、公钥加密凭据及撤销 | 已有两端指纹人工核对；已接入口预检，尚无经评审的双端短码握手及完整产品流程 |
| 网络入口 | 默认127.0.0.1，可明确配置本机IPv4接口 | 已增加精确TLS/证书到期预检；既有入口迁移、远端可达性、防火墙及证书续期待完成 |
| 聊天连接 | 已有私有MCP和隧道 | 聊天端可达不代表配对/Host反向连接入口可达 |
| 桌面并发 | cua.mjs共享连接、排队和引用归属检查 | 同一桌面仍有状态干扰，必须重新观察 |

## 权限与连接设计约束

桌面执行应由稳定身份的App/Helper承载。把Node放进App、改名或补提示词都不能证明责任链
正确。普通桌面走Cua；明确请求的应用脚本另有Automation授权，不能与Accessibility混同。
Exec是否也纳入App责任链需要平台实测，不能保证任意子进程都继承授权。
Windows必须区分用户桌面会话与后台服务；headless Linux仅启用实际可用能力。

添加设备：检查Gateway → 授权开放范围 → 准备安全入口 → 新设备验证TLS及可达性 →
限时邀请 → 双方身份确认 → 能力审批 → Host主动连接 → 实际验收。
不默认信任局域网，不自动开放所有接口或改路由器。异地接入若无中继服务，必须有可达入口。
关闭配对窗口不切断已批准设备；撤销应断开并拒绝旧凭据。
emoji/短码是绑定双方身份和当前握手的确认界面，不是连接密钥；需限制重试及有效期，
正式实现前选用成熟协议并评审中间人攻击防护。用户不手传私钥。

## 实施顺序与验收

1. 角色状态：统一Core plan/status和App输出，加入不创建Gateway；配置意图不冒充健康。
2. 生命周期：Gateway-only脱离Host安装依赖；App/CLI共用安装、启动、停止、恢复。
   覆盖单机桌面、主台桌面、仅Host桌面、Gateway-only、headless Host和headless双角色。
3. 原生包装：稳定Mac权限身份和Windows用户会话组件；实测重启、登录、App退出、升级、
   回滚及授权保留。新系统权限必须由用户亲自批准。
4. 多设备：局域网入口事务及两端确认；验收Mac主台+Windows Host、headless主台+桌面Host。
   覆盖不可达、邀请过期/抢用、错误确认、身份变化、断网重连、撤销与证书续期。
5. 新用户真实聊天端验收后发布；单台热修复不能替代产品验收。

本次先落地角色状态投影onboarding/roles.mjs：从现有配置派生，未新增角色配置文件，
Core plan/status及App后端返回一致字段。computer=requested仅代表安装意图，
deviceIngress=configured_unverified不代表远程可达。Gateway-only已有签名安装/运行/离线更新链，
配置测试与真实原生平台、聊天账号验收仍分别记录。
本次不修改piermini运行配置，后续迁移必须保留身份、设备配对和回滚点。


## 本轮开发的验收界限

新增Gateway-only与App/CLI共用Core配置/管理链已通过隔离Linux回归；实际Codex 0.163.0
命令/PTY以及真实TLS MCP可运行。签名Gateway应用包包含Node和生产依赖，不含Exec/Cua
二进制，可在删除发布源码后运行。更新/回滚保留Gateway身份和凭据，要求服务不存在且进程
已独立确认停止；进程崩溃恢复有测试，不等于断电或机器重启验收。

Mac原生监督器仅为签名身份配置和可编译测试入口，未在本环境完成编译、TCC或升级验收。
原生配置迁移只在已确认无Host服务时执行，不更改TCC、现有身份、配对或权限。已安装服务
不自动重写。Windows仍只有既有任务/Host基础，没有因此获得已验收的完整桌面App。

待完成：Host更新/恢复完整管理链、无人登录启动策略、既有Gateway安全入口迁移与续证、
双端握手确认交互、Mac主台+Windows Host、headless主台+桌面Host、Cua实际操作、新用户
聊天端验收，以及登录/重启/App退出/升级/回滚后的真实原生证据。开发预览不称正式产品。

## 2026-10-19 重启恢复修复

`onboarding/macos-login-recovery.mjs` 补充 Aqua 用户登录级的 App 生命周期；
`background.mjs` 在明确启用后台运行的事务中为已登记的 macPreviewApp 安装它。
通过 LaunchServices `open -W -g` 保持原 App 权限身份，launchd 对正常/异常退出均
限速恢复。停用必须先 stop/uninstall 登录恢复服务；直接 Quit 会被重新拉起。
App 启动后仍由 App 本身创建嵌入式 Cua 和临时 socket，不由 Gateway 代管。
此修复不把 launchd PID 或 socket 存在当成 GUI 可用，也不承诺独立 Cua 子进程崩溃
或 App SIGKILL 后遗留 socket 的自动恢复；这两项需要原生 App 后续修复及签名发布。

既有外置 Bieber 隧道可显式接管为独立登录服务，复用原 profile 和 file 引用凭据，
不会导入/复制秘密或创建新隧道。配置文件必须为私有绝对路径，内容为
`{"appPath":"/Applications/Styx.app","tunnelRoot":"/absolute/existing/tunnel","logDir":"/absolute/private/logs"}`。
省略 tunnelRoot 只管理 App；该迁移入口不自动发现或采用任意外部隧道。
运行 `node onboarding/cli.mjs mac-login-recovery CONFIG install --authorize`；
同一 CONFIG 支持 status、start、stop、uninstall（变更需 --authorize）。
已有定义不一致或观察失败时拒绝覆盖；先核对实际状态及回滚记录。

内置 `TunnelRuntime` 对已经授权的连接启动失败、进程退出每 15 秒重试，
显式 stop 取消重试。它只恢复连接进程，不重放 MCP 请求，不清除未知 owner lock。
网络未就绪不再导致单次启动失败后永久断开；仍需有效凭据和账号侧验收。

以下为875c4c3原故障排查thread的历史现场记录，本架构thread未实施线上变更。
piermini 该次保留 .3 App/Host 的签名、身份和授权，现场使用已生成的登录服务，
Gateway 继续加载 desktop-routing 热修复源码；未替换签名 App。
受控 App 退出和 Gateway/Host/隧道进程恢复已实测，不能等同整机重启验收。


2026-10-19 跨账号连接复发：外部隧道记录到 Gateway initialize HTTP 503，
即使 Gateway/Host/App/隧道都正常运行。按用户要求移除 MCP HTTP 会话数量上限，
删除 maxSessions 选项和按数量拒绝新初始化的分支；不以提高数值代替删除。
保留默认 15 分钟空闲清理，在每次新初始化时执行，并保护正在返回的响应及
持有 Exec 工作的会话。96 个并发客户端验证连接、DELETE 和互不影响。
这与设备桌面共享/操作队列、Exec 进程句柄限制是不同层次，不改变后两者。


2026-10-19 隔离原生开发验收补充（不代表正式发布）：

- pilotmac 上使用已有 SDK 26.5，Swift 测试与生产入口均通过严格编译；
  原生自测及 Cua owner 死亡后的 EOF/私有 socket 清理通过。未安装或授权签名 App，
  App/Exec responsibility chain、Accessibility、Screen Recording、Automation 仍未验收。
- NAB 的提升 SSH 会话中新文件默认 owner 为 Administrators，即使 DACL 仅允许当前用户、
  SYSTEM 和 Administrators。新增独占空文件创建接口，在写入秘密前按原生文件 handle
  验证身份并设置本次新文件 owner/DACL；已有文件和目录不自动修权限或接管。
  Core、配对、安装、签名运行时和恢复事务统一接入。Windows 原生相关测试 12 项通过。
- Windows 固定原生探针改为有长度限制的本地编码命令，长声明使用本地压缩源，
  不修改 ExecutionPolicy；中文和特殊字符作为字面参数保留。Restricted 策略下原生
  编译/参数测试通过，生产探针在 SSH Session 0 明确返回无交互桌面。
- Windows 真实 Codex Exec 和 Core/CLI 同配置检查通过；join-existing 不生成 Gateway 步骤。
  Mac Gateway＋Windows Host 临时 TLS 配对、明确指纹审批、真实 Exec、同身份重连、
  撤销后旧凭据拒绝通过；该次基线 harness 对新建文件修正过 owner，不算完整新用户安装。
- Host 更新低层事务增加存活执行者互斥和串行恢复；中断恢复 guard 留作人工归属核验。
  App/CLI 仍只暴露 Host 更新计划和凭据不外泄的状态检查，托管更新执行仍明确阻止。

真实 Windows Host 服务生命周期（包括 Restricted 策略下现有 -File 入口）、
无人登录启动、整机重启、GUI 操作、安装升级/回滚后的系统权限及真实聊天账号验收，
均不得从这些测试推断为通过。用户选择先完成无需签名的开发验收。

## 普通用户首装候选的新增边界

App 的七步引导与 CLI 使用同一个 Core。新增只读 journey/脱敏诊断；前台运行与
登录后台是不同的明确选择。前台只拥有当前进程内的连接，正常关闭等待实际回收；
重开后使用原身份显式恢复，不重复安装、配对或创建 Gateway。中断锁不能被盲目接管。

系统权限来自当前 App 私有原生描述符及存活进程核对，辅助功能与屏幕录制分别呈现。
它们不是 Exec 子进程的 responsibility chain 证明，也不能代替真实 Cua 操作。
当前 Mac 候选是 ad-hoc 开发包；没有 Developer ID、公证或稳定 TCC 升级身份的完成声明。
本轮新增前台管理的 Windows 路径明确仅启用 Exec；Windows 桌面 App/交互会话管理仍未完整产品化。

外部账号设置在官方系统浏览器完成，App 不接收网页登录回调。隧道运行密钥、
模型工具 Bearer 和 Gateway 管理凭据各自独立；交接接口只在本机明确授权后输出
工具 Bearer，显示到期不表示该凭据已失效或撤销。

聊天验收分为生产 MCP 返回的实际 Exec 证据、同一 Styx 原生窗口的桌面观察/输入/读回，
以及用户单独确认请求来自目标聊天。用户点击不能制造实际请求证据；本地 SDK 或
合成 Cua 测试不是聊天账号或原生 GUI 验收。账号平台身份仍是 not_verified，来源确认
明确标记 user_attested。既有证明是历史记录，不能代替当前进程、连接和权限状态。

PR #26 的 CAS 已有持久 Run/Wake 账本及真实模型自动回合证据，并在当前源码中保留；
当前普通 App 默认未启用，通用 Exec/Cua 任务、连续续接及平台可靠性仍需集成与验收。
详见会话与任务生命周期文档，不能把“未作为普通产品接入”写成“没有实现”。


## Agent 选择工具，本地执行契约

2026-10-20 用户明确产品边界：Exec/Cua 的选择由 Agent 负责，本地 Core、Gateway、Host 不负责识别任务语义或替 Agent 路由。不新增 Terminal 应用黑名单、命令关键词分类器、模型自报任务类型的路由开关，或仅为选择 Cua 增加一套本地任务审批。

Agent 指引与评测应明确：命令行工作（clone、下载、文件处理、构建、测试及交互式 PTY）通常直接使用 Exec；必要的 GUI 观察和操作使用 Cua。此前提出的任务级本地硬路由方案已撤回；模型工具选择的低效通过指引、技能、能力发现和真实行为回归处理，不能再把增加本地路由门禁作为本次产品目标。

本地仍强制设备身份、配对、已批准能力、凭据与会话归属、参数契约、原生权限，以及确定性执行与结果不确定时不自动重放。这些是已有执行边界，不负责判断该选哪种工具。普通 GUI 的 Agent 指引保留 Cua 与应用脚本独立授权的区别，不把提示词当作原生权限修复。

下一轮首要验收是普通用户的插件创建／关联闭环。Pilot Mac 当前 dev.2（d8555ea）缺少该流程；f67cc64 已补本机插件资料、ZIP 导出、复用分支及手动账号操作确认，但尚未进入用户安装包，账号创建／安装／连接未完成真实验收。不能把导出 ZIP 或手动勾选确认等同用户已成功接入。先完成受支持的创建／关联操作及真实聊天验证，再交付下一安装包；原生界面视觉重写后置。


2026-10-20 再次出现的 session_capacity 已通过真实 MCP 定位到 ExecAdapter，
HTTP initialize 成功且仍加载前次无 MCP 连接上限的源码。ExecAdapter 将所有尚未轮询
结束的命令句柄计入 64 上限；已经退出的进程也可能因输出尚未 drain 保留句柄。
本次删除该数量上限，以及 usedIds 达到 100000 后拒绝执行的累计上限。
句柄与历史 ID 不等于正在执行的 OS 进程数，不再据此拒绝其他会话的新命令。
保留句柄所属 MCP 会话校验、随机 ID 不复用、输出游标与排空后移除，不驱逐运行命令。
测试覆盖 96 个未轮询句柄、其他会话继续执行、原句柄输出仍可正确读取和 ID 累计。
前次 96 个 MCP 连接验收不能替代这项连续命令句柄验收。


## 浏览器操作是独立的第三类工具

2026-10-20 用户重申此前讨论的三类工具：Exec（进程／命令行）、Browser（浏览器会话／标签页／网页内容与交互）、Cua（原生桌面观察和操作）。Browser 不因 Cua 可以点击浏览器窗口而被视为已实现或已覆盖。三类工具由 Agent 选择，本地不做任务语义路由。

截至独立 Browser 开发前的基线，VNext Gateway 的实际工具目录仅接入 Exec 与十个通用 Cua 工具及设备发现／状态；没有独立 Browser provider、浏览器会话契约或 DOM/标签页工具。onboarding 的官方浏览器跳转和 Chrome/CDP UI 测试是引导／测试基础设施，不是面向用户的 Browser 能力。现有 acceptance.md 已把 Browser Playwright/CDP 标为 separate component / NOT RUN；该项不能从后续范围中遗漏，也不据此否认项目外既有浏览器方案。

后续应先核对并复用已讨论／已存在的浏览器接入方案，再补同一 Core 下的能力配置、连接／授权、状态和生命周期，并单独验收真实网页观察与操作、标签页／会话归属和恢复。具体 Browser 实现尚未在此定型；不得把 Cua 的浏览器窗口点击或测试专用 CDP 连通当成 Browser provider 验收。

2026-10-20 独立 Browser 分支已接入锁定 Playwright MCP、Host Browser lane、Core 配置/准备与独立验收证据。实现范围、隔离测试及仍未完成的迁移/原生打包/真实账号验收见 [Browser provider 开发验收](browser-provider.md)。这不表示现有已安装 App 自动具有 Browser。
