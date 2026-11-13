# Styx 架构：一个 Gateway，多台 Host

2026-11-14，所有者已确认以下产品行为。本文是本轮重构的目标；当前实现仍有下文列出的差异。

## 一次调用与两种角色

模型入口只有一条：**ChatGPT → OpenAI Private MCP Tunnel → Gateway → 选定的 Host → 执行器**。结果沿原路返回。一套部署有一个 Gateway，只有它持有 Tunnel 配置和凭据。Host 主动连接配对时指定的 Gateway。网络由用户提供，Tailnet、站点间路由或局域网均可；Styx 使用可直达的地址，并报告连接结果。

**Gateway 是设备目录和路由中心。** 它持有邀请、设备信任与撤销记录，观察哪些 Host 在线，并向 ChatGPT 提供管理和执行入口。可使用这个 MCP 入口的人都拥有整套部署的管理权限，包括生成邀请、移除设备和请求变更 Host 设置。部署共用一个管理范围；对话标识用于选择资源和延续上下文。设备身份验证、Tunnel 身份验证和本机系统授权继续有效。

**Host 是本机设置、执行与结果的负责人。** Exec、Browser、Computer Use 的开关由 Host 保存并执行。在本机设置和在 ChatGPT 中要求修改，最终调用同一个 Host 操作。Host 成功应用后报告实际能力；需要系统授权时报告等待授权。Gateway 按 Host 报告的能力路由。安装器负责安装与更新的完整验签。Rust Core 共享身份、协议及操作规则；GUI、CLI 和 headless 服务按需要组合角色。

## 安装、配对与更换中心

| 安装方式 | 首次设置完成时的用户体验 |
| --- | --- |
| macOS、Windows、Linux 桌面 · Host-only | 输入 Gateway 地址与一次性短码，本机确认加入，选择本机能力。也可以一次粘贴地址和短码。整个向导只有设备侧设置。 |
| 同三种桌面 · Gateway + Host | 在向导中配置 Tunnel，这一步必做。本机自动成为第一台配对设备，直接选择本机能力。之后其他设备用邀请加入。 |
| Linux headless · Gateway-only | 现有服务管理器启动 Gateway；CLI 可以先生成邀请、接入设备，再配置 Tunnel。Gateway 独立运行，无需图形会话、浏览器或本机执行器。 |

桌面 Host 的能力初始值为 Exec 默认勾选且可取消，Browser、Computer Use 默认关闭。生成邀请即批准一台设备加入。可手输的短码一次有效，首次配对仍需认证正确的 Gateway；协议选型、码长与过期时间属于实现决定，优先采用成熟配对机制。设备重连沿用身份和配对。已配置设备在本次软件重构中保留身份；用户主动换 Gateway 时，旧中心先列出受影响设备，新中心配置 Tunnel，各台 Host 分别用新邀请重新加入。

## 设备选择和操作归属

一个对话可使用多台 Host。每次执行落到一个明确设备。用户点名或上下文清楚时沿用该设备；只有一台已配对 Host 时默认选它；多台且目标不明时询问。选定目标离线就报告离线，其他设备即使在线也不会接手命令。

| 能力 | 用户可依赖的行为 |
| --- | --- |
| Exec | 任务归执行它的 Host。关闭对话或临时断线，已开始的任务继续；在同一次 Host 运行期间，另一段对话可以查询结果、进度或停止原任务。 |
| Browser | 每段对话默认有独立浏览器会话。明确要求接手时保留原标签页与页面状态，随后由新对话操作；同一会话只接受当前操作者。 |
| Computer Use | 多段对话可以使用同一 Host。并发交由该平台的 Cua 处理，Host 如实报告忙碌、目标失效与操作结果。沿用上游目标观察和输入语义，无需新增对话级整桌面锁。 |

Browser 与 Computer Use 优先沿用**固定版本**的 Playwright、Cua 工具与参数。Host 报告本机实际可用的工具，Gateway 根据目标公开或路由受支持的调用。上游升级时核对有实际差异的适配和行为。

## 断线、退出和撤销

| 事件 | 行为 |
| --- | --- |
| 派发前已知 Host 离线 | 立即报告“未发送”；再次上线后由用户重新发起。 |
| 提交中连接丢失 | 查询原操作能否被确认；无法确认时保留“结果未知”，不自动重发。已开始的任务按对应能力的生命周期继续。 |
| 主动退出桌面 Styx | 只有「退出 Styx」一个动作。本机停止自己承担的全部角色，收回自己管理的任务，保留已生成文件；下次启动不自动续跑。Host-only 只令本机离线；组合模式同时关闭 Gateway 和 Tunnel，其他 Host 保留配对，等原中心恢复后重连。 |
| 移除设备 | Gateway 立即撤销配对、停止派发并拒绝旧身份重连。在线 Host 收到撤销通知后停止所管理的任务；离线时报告“配对已撤销，远端任务是否停止无法确认”。重新加入需要新邀请。 |

## 对照当前实现

| 当前入口 | 改造决定 |
| --- | --- |
| [Gateway 配对管理](../../crates/styx-runtime/src/app/gateway_ui.rs)、[现有邀请编码](../../crates/styx-runtime/src/app/pairing_link.rs)、[设备加入](../../crates/styx-runtime/src/management/native_join.rs) | 保留设备身份、信任校验、一次消费和撤销。新入口采用地址加短码。新配对流程移除创建邀请后的第二次管理员批准，以及批准时为设备分配 Browser/Computer 权限的步骤；现有设备的能力设置显式承接，避免升级时静默开启。 |
| [Tunnel](../../crates/styx-runtime/src/foreground/tunnel.rs)、[Gateway 路由](../../crates/styx-runtime/src/gateway/paired)、[对话关联](ADR-036-TUNNEL-CONVERSATION-OWNER.md) | 保留单入口、设备选择与原请求关联。管理操作可从 ChatGPT 到达对应角色。将“哪段对话拥有资源”按上述三种能力分别处理；关闭 A 的传输或聊天后，B 仍可访问同一 Host 上的原 Exec 任务。 |
| [Host 协调与清理](../../crates/styx-runtime/src/host/coordinator)、[操作记录](../../crates/styx-core/src/operations.rs)、[执行器适配](../../crates/styx-runtime/src/providers) | 保留原操作身份、已派发结果未知时的保护，以及实际进程清理。Exec 的任务寿命与对话解绑；Browser 明确转交现有会话；保留 Cua 实际需要的资源保护。 |
| [Rust App 入口](../../crates/styx-runtime/src/app.rs)、[Mac](../../host/macos/product-ui/ProductViews.swift)、[Windows](../../host/windows/Styx.cs)、[CLI 设置](../../crates/styx/src/setup.rs) | 按安装模式组成向导。移除桌面独立「暂停连接」操作和旧的二次批准界面；底层断连、退出清理和撤销仍各有调用方。Host-only 隐去 Tunnel 设置，桌面建中心的流程必须完成 Tunnel 配置。 |

## 实施顺序与验证

先做角色组合和配对：用 headless Gateway 接入桌面 Host，再用桌面组合模式自动加入本机并接入第二台 Host。两种拓扑都应只配置一次 Tunnel。GUI 强制完成 Tunnel 和 CLI 延后配置分别从各自正常入口验证。

随后打通 ChatGPT 的设备管理与按设备执行：在一个对话中分别选中两台设备，以实际效果确认目标；从 ChatGPT 和本机变更同一能力，并核对 Host 实际状态。最后按发生顺序验证断线、跨对话继续、主动退出和撤销，确认已完成的动作不会重放。每迁移一个职责，就移除已经被接管的调用方判断；现有格式或接口仍有消费者时先处理兼容。

同机角色是否共用进程、是否走回环、crate 如何划分均为实现选择。先复用现有同机 Host 和远程 Host 的路由；只有具体用户行为需要时才增加分支。参考分支的类型和模块拆分按此取舍。
