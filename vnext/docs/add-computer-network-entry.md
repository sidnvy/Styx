# “添加电脑”的附加网络入口契约

状态：公共 Core / Gateway 已实现。`ae86337` 加入同一 Gateway 的附加精确 TLS 入口、事务恢复和独立配对窗口；`1b23221` 修正公开 join 预检。Windows / 网页接线和 Linux CLI 已纳入该来源；macOS 新 UI 的接线、三平台源码回灌和目标账号完整流程仍需分别核对，见[共享开发基线](development-baseline.md)。本文件保留实现约束，不把源码或单次原生结果写成全部平台产品验收。

真实附加入口验收记录在任务输出 `outputs/cross-platform-ready-20261022/delivery.json`、两端 actor receipt 和 `evidence-inventory.json`。Linux `1b23221` 新产物与相同公共 Core 的 Windows 冻结源码通过直接 TLS 加入：Gateway 9 项、Windows 6 项门槛通过；原 localhost MCP 会话持续可用，12 秒 Exec、真实 Edge 和关闭窗口后的执行器重连通过。测试没有使用 SSH 转发，未变更已装服务或防火墙；两端私有状态和自建进程已清理。这不是实际 ChatGPT 账号或全部原生 App 界面的验收。

适用起点仍是已有 localhost Gateway、本机 Host 和可用 ChatGPT 连接的主台。“添加电脑”增加经授权的设备入口，继续使用同一个 Gateway，不要求修改原聊天配置。

## 必须保留的既有状态

- 原 Gateway 的 localhost 地址、端口、证书、私钥、model/admin 凭据与 owner 配置保持原值。
- 本机 Host 的连接地址、身份、凭据、能力和系统权限保持不变。
- 隧道、插件地址及账号配置不重建；不自动更改默认设备。
- 所有入口共享同一 registry、EnrollmentController、Host relay 和撤销记录。App 不另起 Gateway 或 controller 并发管理同一配对数据库。

`device-ingress-change.mjs` 仍是离线首设备主入口迁移：会改变主 URL、证书和 Host 配置，并拒绝已有 tunnel/plugin。它不是在线附加入口的实现，不能通过移除拒绝条件冒充该流程。

## 用户调用链

1. App 经共享 Core 读取 Gateway 的实际归属和入口能力；归属未知或旧运行版本不支持时明确停止，不新建 Gateway。
2. “添加电脑”进入局域网邀请。Core 核对用户已授权且本机实际拥有的精确 IPv4 地址与端口；多网卡无法明确选择时报告阻塞。不使用 `0.0.0.0`，不自动更改防火墙、路由或系统权限。
3. Core 执行附加入口事务，让当前 Gateway 进程启动入口；实际监听确认后才创建该入口的限时邀请。本机配置和 TLS 探测不等于另一台电脑可达。
4. 新电脑明确选择“加入已有”，核对邀请地址和证书，通过真实 TLS 提交既有签名加入请求。
5. 两端核对同一次请求的公开摘要。主台确认设备身份；能力遵从设备端已经确认并签名的申请。摘要不是连接密钥，也不代替 TLS、签名和独立审批。
6. 新 Host 领取既有加密凭据并主动连接。原聊天通过同一 registry 选择新设备，实际验收所选能力；不重新创建插件，不搬运私钥、API key 或配置文件。

## 同一 Gateway 与 owner 控制

`gateway/device-ingress.mjs` 管理附加 listener。前台 Core 与后台 signed Gateway runner 使用同一实现；已有后台 Gateway 时，App 通过原 localhost HTTPS / admin 入口请求处理，不在 App 进程另建配对数据库或 relay。

`gateway/enroll-admin.mjs` 的固定命令包括 `ingress-status`、`ingress-prepare`、`ingress-enable`、`ingress-disable`、`pairing-open`、`pairing-close`。网络授权与状态读取分开；LAN 不提供 owner 控制。Core 对外使用 `prepareDeploymentDeviceIngress`、`readDeploymentDeviceIngressSetup`、`recoverDeploymentDeviceIngress` 和既有邀请/关闭配对 API。

LAN HTTP 只开放 join、claim、confirm；Host 升级路由复用既有 exec/computer/browser 认证和能力校验。不开放 LAN MCP、invitations、approve、revoke 等管理路由。

多监听器共享 relay 的连接表、重复 Host 检查、generation、撤销与 heartbeat。附加入口局部关闭只释放自己的连接与 listener，不能调用全局关闭或清除原 MCP session、本机 Host 和其他监听器的资源。localhost 服务独立先启动；LAN 失败不能拖垮原聊天入口。

## 配对窗口与连接入口分别管理

关闭“添加电脑”窗口或邀请到期只关闭新加入权限，并使该窗口未使用的邀请失效。已批准 Host 继续连接、断网重连；有效请求的 claim/confirm 按独立期限处理。真实跨机器验收已覆盖关窗口后的工具调用与执行器重连。

只有明确关闭附加连接入口才停止该 listener，并报告远端连接受影响；localhost 保留。单台设备撤销继续使用 durable tombstone、旧凭据拒绝和对应 relay 断开机制。

入口属于实际 Gateway 进程。重启恢复只使用原先授权的 descriptor；网卡暂缺或端口暂占时以 1 至 15 秒退避重试，保留原地址、generation、证书 pin 和身份，不重开邀请或重放 MCP。显式准备、启用、停用或关闭入口管理器会取消旧恢复任务。证书不匹配或过期不能靠重试放宽信任；这不是任意断网、重启或登录恢复都已验收的承诺。

## 配置与事务

`deployment.json` 的 `gateway.deviceIngress` 是精确入口授权，保留原 `url/listenHost` 语义；generation、URL、精确 IP 和证书 DER SHA256 受校验。`onboarding/device-ingress-config.mjs` 派生独立 TLS 文件路径和 runner descriptor，不建立第二份角色或网络 authority。

`state.configSha256` 仍绑定完整配置。`shared/deployment-scope.mjs` 仅在既有 Host 执行与聊天证明的连接范围投影中排除新增入口，使原 URL、身份和聊天绑定继续有效；既有证据保留来源，不因此生成一次新账号验收。事务共同锁、持久 intent/journal/history、写入前锁身份复核和相关 hash 对账共同约束变更。回滚只恢复本次入口变更，不能删除原身份、其他凭据或用旧数据库抹掉已经发生的设备批准。

不确定事务明确进入 `needs_reconciliation`，由显式 `retry` / `rollback` 对账，不盲目重放。恢复有独占 `device-ingress-recovery.lock`；残留 guard 即使 PID 已死也不自动删除，须受审查的恢复处理，不能声称任何崩溃点都自动自愈。

配置仍含 `gateway.deviceIngress` 时，运行时更新/恢复拒绝不支持该配置的旧 Gateway application（未声明或低于 source contract 2）。需要先显式回滚附加入口配置，不能静默删字段；历史签名包的来源闭包兼容是另一项校验。

## TLS、核对摘要与预检

当前实现选择独立的 LAN 自签 TLS 身份，并在邀请中明确绑定该入口与叶证书信任；不由主 localhost 证书推算或声称继承其根信任。主证书、私钥和原聊天信任不变。再次启用、重启和重连复用原证书，并核对已授权的 DER pin。

Gateway 在实际 listener 的 TLS 请求上记录 origin、叶证书 hash 和 generation，用于请求绑定的 owner 核对摘要；Host 也按实际 TLS peer 计算。摘要还绑定 request ID 和设备公钥指纹，不信任客户端 JSON 自报的 listener 身份。邀请同时绑定对应入口和窗口。

`1b23221` 的 `verifyDeviceIngress` 使用公开 join 路由的预期 `405 method_not_allowed` 做无副作用 HTTPS 预检，不再要求 LAN 上被屏蔽的 owner pending 路由返回 401。预检成功仍需新电脑真实 TLS、加入、领取和 Host 工具调用才能证明跨设备可用。

当前证书准备使用 30 天自签证书。自动续期、信任变更及 IP 更新不是本轮已经完成的通用方案；到期或 pin 不匹配必须明确处理，不能偷偷更换地址/证书，也不能用“重新配对所有设备”代替受审查的迁移。

## 剩余验收范围

- 各平台原生 App 与网页的完整普通用户链路，特别是 Mac 新 UI 的实际接线；共享 Core 通过不代表界面均通过。
- 已连接的目标 ChatGPT 账号指定新设备运行所选能力；原有账号确认不得由 actor 的 MCP 客户端结果代替。
- 针对交付产物的登录、注销、重启、网络恢复，以及错误核对、过期、抢用、撤销和证书/IP 变化的用户恢复流程。

第一版只覆盖已授权且真实可达的精确网络入口。没有自建发现/中继服务，不承诺跨越任意 NAT；LAN、VPN 或已知 IP 本身不构成信任。已通过的 Core / 物理案例与上述未完成范围分别报告，不再笼统称“网络入口尚未实现”，也不宣称全部普通用户流程或三平台发行已经完成。
