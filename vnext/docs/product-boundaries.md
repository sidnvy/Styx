# Styx 产品边界与实现对照

2026-10-19：用户确认的目标架构。本文件区分目标与当前实现，不是功能完成声明。

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
