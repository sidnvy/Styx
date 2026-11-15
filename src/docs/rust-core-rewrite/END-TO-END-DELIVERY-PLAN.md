# Styx 重构当前交付清单

更新：2026-11-15。唯一当前待办入口；产品规则以 [REFACTOR-PLAN](REFACTOR-PLAN.md)
为准。初次审核源码 `5c39783`；结构清理 `efab8be`，旧测试修正 `8f8d278`。
Gateway 先行包 `2d3fe69` 已发布并更新本机与 moedeu-apps；Windows Host 仍为上一轮 `d1cb41c`，本机 Linux 测试 Host 已正常退出，
Mac 保留原版。桌面 App/Host 的 C1/C2 原生更新验证仍未关闭。
历史正式 0.4.0 已发布；本轮重构版尚未正式放行。

## Linux 用户首次安装验收交接

所有者要求：开发验证完成后，由用户亲自从完整安装包走首次安装、配置、加入
moedeu-apps Gateway 和 ChatGPT 验收；不得预先配置后宣称用户流程通过。

- 完整 Linux 包 `0.4.1-preview.1`，源码 `61101aa5e0334bea3b3a08d99e0a12ed950206eb`，
  包含 `6c97598` 的 worker 配额修复。20 项质量门、Debian 12 构建、原发布身份签名、
  实际 CLI release verify 均 PASS。非 Stable 放行，不代表已安装或账号端到端通过。
- 包与证据：`/home/sid/Developer/Artifacts/Styx/linux-user-preview-0.4.1-preview.1`。
- 旧测试 Host PID 469180 已单次 SIGTERM 正常退出，服务 inactive/dead、Result=success；
  原文件保留，退出前后快照位于该目录的 `test-host-backup/`。未替用户建立默认配置、
  执行 setup 或生成新配对；moedeu-apps Gateway 保持原配置。
- Linux 入口仍为 CLI。完整包解压到持久目录，用户用 `styx install` 注册命令，
  在本机图形桌面终端运行 `styx setup`，选择 Join an existing Gateway，填地址及短码。
- 发布暂缓：所有者再次明确 Linux 必须交付 Gateway-only 与桌面 Host＋可选 Gateway 两种包，
  并把正式安装方式纳入验收。完整包已经包含组合角色，但当前手动解压、注册链接和
  setup 分离的入口仍需收敛；不能把本地预览包当作正式交付。自动审批在执行前拒绝了
  tag/公开 Release 发布，尚未重新提交。
- systemd 现状：两种角色都使用现有 user service，setup 安装/enable/start，
  `WantedBy=default.target`、`Restart=no`；不自动 sudo 或开启 linger。
  Gateway-only 必须明确无人登录时的持久运行方案；沿用原 user manager 的实现时，
  由安装流程明确处理服务用户与 linger，而不是声称 login service 就等于开机常驻。
  桌面包使用当前用户，Computer Use 跟随实际图形会话；不把整台 Host 绑定某个桌面窗口。
- 待用户完成：首次安装与加入、ChatGPT Exec/Browser/Computer 独立效果，
  双对话并行与其中一个退出后另一个继续，以及修复后桌面 watcher 长驻观察。

## 已发布的 Linux Gateway 先行版

2026-11-15 按所有者要求先交付 Gateway：
[0.4.1-gateway.1](https://github.com/sidnvy/Styx/releases/tag/gateway-v0.4.1-gateway.1)，
源码 `2d3fe693a4b38a75974cc972f2ee8d4af4bd784b`。仅 Linux Gateway/Core + Tunnel，
不包含桌面 App/Host 执行器，不将跨平台重构版 Stable 标为通过。

- 同源 20 项质量门 PASS，Debian 12 原生构建与签名 PASS；GitHub 三项资产摘要逐一匹配。
- 本机 38443 原配置更新，实际 Core/选定 manifest 与包一致；原 Linux Host PID 469180、
  身份及配对不变。双独立 MCP 的 Exec/Browser 与 A 退出后 B 继续通过。
- moedeu-apps 22027 原配置更新及新版正常退出重开通过，revision 7；新 Core PID 2611732，
  TLSv1.3/认证管理查询通过，身份/配对/Tunnel 配置保持，旧 22026 服务未修改。
- manifest `5cea14d3ca06a012924671b4c9fb399265cfc891f9c1bad9511c611db9cdac9a`，
  Core `9300e96c32f6223c979d46e6a55342f7c60eb3b9c2a90f2457f74ee51112f571`。
- moedeu 原旧版退出 4/两个远端 owner 未确认完整保留；独立确认本地所有组件退出后继续，
  没有重放 stop。新版再次正常退出为 0，owner/transport 未确认数均为 0。
- 本机第一次即时读取新进程 `/proc/exe` 权限失败；独立读取确认实际新 Core 后补记，未重放更新。
  时钟下界与 Tunnel 运行期临时头/健康文件正常刷新，不把它们当持久身份变化。

最终证据 `/home/sid/Developer/Artifacts/Styx/gateway-preview-0.4.1-gateway.1/release-verification.json`。
moedeu 原四个 Host 当前离线，原本机日常 Host profile 已于 11/13 清理删除；不能宣称
原身份已恢复或当前 ChatGPT 账号已可用。现有 38443 测试 Host 的原配对保持不变。

## 新发现的 Host 配额遗漏

本机 Computer Use 返回 `SESSION_DISCONNECTED`。独立系统日志证明旧 Host 的
`__linux-desktop-watch` PID 469223 在 11:20:23 因 SIGXCPU 退出，早于 Gateway 更新
15:29。原因是 hidden worker 仍有累计 CPU 2/3 秒以及 AS/DATA/NOFILE 自设配额。

`6c97598` 删除这些配额及 watcher 以低内存额度判断身份的旧检查；保留原父进程身份、
父进程退出清理、请求期限与禁止 core dump。实际子进程超过 3.25 秒 CPU、128MiB 分配、
64 个文件句柄后正常退出，以及 3 项来源/并发/取消清理回归通过；整合后 20 项标准质量门
PASS（`computer-concurrency/host-worker-resource-quality/receipt.json`）。修复已纳入上述完整 Linux
预览包，旧测试 Host 已退出；仍待用户安装及实机长驻观察。Gateway 先行包不含此修复。

## 已完成，勿重新列为待办

| 边界 | 已有结果 | 证据 |
| --- | --- | --- |
| Gateway 路由，Host 持有 Exec/Browser | 任务与页面跨对话保留；Gateway 不保存第二份 Exec/Browser 目录 | [生命周期与实现记录](DELIVERY-HISTORY-THROUGH-20261115.md#host-运行期与连接生命周期分离2026-11-14开发验证) |
| 本机能力由 Host 执行 | 能力关闭停止对应任务，其他能力继续；Mac、Windows 有原生记录 | 历史中的能力设置、Browser、Windows 原生验证检查点 |
| 短码自动加入、更新后改配 | Windows 正常短码加入及更新→换中心→退出已通过 | [Windows 闭环](DELIVERY-HISTORY-THROUGH-20261115.md#更新完成后的所有权释放与-windows-实机闭环2026-11-14) |
| 统一导航、单窗口、单一更新入口 | Mac/Windows 普通入口已收敛；两端原配置更新、退出重开有证据 | [桌面收敛](DELIVERY-HISTORY-THROUGH-20261115.md#桌面统一入口与单窗口收敛2026-11-15) |
| 运行时数量配额及清理锁误拒绝 | 已删除数量准入，清理期间等待原锁；Windows/Linux 各 17 次双对话窗口读取及 Exec/Browser 延续通过 | [最新实机检查点](DELIVERY-HISTORY-THROUGH-20261115.md#取消运行时配额与双对话实机验证2026-11-15) |
| ChatGPT 单对话使用两台 Host | 真实账号 Exec/Browser 双设备效果已通过 | [账号路线](DELIVERY-HISTORY-THROUGH-20261115.md#独立-chatgpt-账号路线2026-11-14) |

## 源码收尾审核及具体清理清单

C1/C2 已实施源码删除；原生端离线，仍需完成受影响平台验证。

| 项目 | 审核证据与判断 | 下一步及完成标准 |
| --- | --- | --- |
| C1 Windows 旧 UI 模式 | InitializeCore 只接受 rust_host；已删除 ShowPage/ShowStatus 的旧模式路径、ReconnectResult 等专用回调及旧测试状态 | 源码完成，草稿/状态检查已迁到原生状态，共享向导保留；待 Windows 编译及主窗口/设置/托盘正常路径验证 |
| C2 旧预算对象与参数 | 已删除 bootstrap Partitions、HostLinkBudget、Codex partition 句柄及 BrowserIoBudget/CuaIoBudget 空对象 | 源码完成，保留实际传输缓冲、期限及进程清理所有权；Linux 本机验证见下文，Windows/Mac 条件编译消费者已更新、原生验证待补 |
| C3 低层私有协议 | `host/protocol` 的 prepare/dispatch 仍服务 Core 资源协议、Computer 及回归；公开 Exec/Browser 经 Host 目录 | 保留有消费者的部分；删除前给出具体调用者清单，不能因为名为 private/legacy 就整片删除 |
| C4 Gateway 的 ComputerContexts | `gateway/paired/backend_computer.rs` 按 owner/device 保存 Cua 操作关联；backend cleanup 清理该 owner | 属于当前 Computer 关联，不是重复 Exec/Browser 目录。未发现需要另造 Host 管理层的依据；不为形式统一迁移 |
| C5 更新事实归属 | `app/runtime_update.rs` 持有原更新记录；Windows UpdateStyx 调用同一 Core 操作 | 保留原记录恢复和身份保护；不把准备/提交等内部接口重新暴露成用户步骤。不凭接口数量断言重复状态 |

审核覆盖 Gateway 公共路由/owner cleanup、Host 目录与启动组合、Windows 模式分支及
更新入口；不是对全部源文件的穷尽证明。未发现 Gateway 重新持有 Exec/Browser 目录。
C1、C2 是结构收尾，不能仅凭编译通过关闭。本次已删除 Windows 被替代的旧页面、
回调和测试状态，以及 Host bootstrap/link、Codex、Browser、Cua 的逻辑预算对象和透传参数。
保留真实传输缓冲、执行期限、原生进程所有权与清理；没有新增准入层。
Linux Runtime 严格检查通过，348 项单元测试通过；真实 Codex 保留/归档场景通过，
确认未知结果不重放、进程退出及 reader/stderr 回收。整合源码 `8f8d278` 的 33 项质量门
全部 PASS，包括完整 workspace、真实 Codex 动作、Browser Host 和 Browser 引用场景。
证据：`/tmp/styx-browser-handoff-20261114/computer-concurrency/refactor-cleanup-quality-v2/receipt.json`。
首轮失败原件保留在同级 `refactor-cleanup-quality`：旧动作测试要求已删除的 slot Busy；
修正过时断言，未恢复配额。Browser 首轮因开发项目缺依赖未启动，复用原锁定依赖后通过。
Windows/Mac 当前离线，
条件编译接口已逐一更新，但两端原生编译、Windows 页面和最终更新验证仍待完成。

## 角色与入口证据核对

下表归并已有记录，不把旧包的通过算作 `efab8be` 的原生验收。

| 角色/入口 | 已有依据 | 本轮边界 |
| --- | --- | --- |
| Windows Host-only | 历史“更新完成后的所有权释放与 Windows 实机闭环”：正常短码自动加入、更新后改配、原配置退出重开；“取消运行时配额与双对话实机验证”：d1cb41c 双对话独立效果 | C1 改动后需原生编译及主窗口/设置/托盘验证；设备离线 |
| Mac Host-only | 历史“本机测试 Gateway 与 Mac 能力开关”：正常短码自动加入，三项能力关闭/重开及原配置恢复；“桌面统一入口与单窗口收敛”：用户确认单窗口、正常更新退出重开 | 最新配额与 C2 清理尚未完成安装/双对话验证 |
| 桌面 Gateway+Host（Mac/Windows） | 历史“已完成的设备选择基础”记录 GUI Tunnel 配置；`app/runtime_bootstrap_tests.rs::desktop_gateway_setup_requires_tunnel_before_pairing_local_host` 覆盖必配 Tunnel；更早平台矩阵有组合角色运行记录 | 本轮共用 Core 的必配 Tunnel、本机自动配对及正常清理回归通过；两端实际 GUI 首设与最终版本绑定仍待核实 |
| Linux headless Gateway-only | 历史“本机测试 Gateway 与 Mac 能力开关”明确本机无 Host、无 Tunnel 的 Gateway，随后独立账号路线接入测试 Tunnel | CLI 可先运行再接入 ChatGPT 有实际记录；本次未替换该 Gateway |
| Linux 桌面角色 | 当前 Linux Host 有 d1cb41c 窗口读取、双对话 Exec/Browser 记录 | 实际入口是 CLI 桌面向导；本轮隔离组合角色设置及原配置恢复通过，不代表 GUI 验收。首次 Exec 可取消遗漏已修复并通过真实开/关两条设置及重开场景 |
| 能力关闭、明确撤销、断线恢复 | 历史 Mac 能力开关、Windows 原生验证记录本机关闭只停止该能力；“Host 运行期与连接生命周期分离”记录真实 CLI 在线撤销停止任务、Gateway 重启后原任务继续 | 保留不受影响证据；C2 的执行器生命周期以本轮真实场景复核，原生端仍待补 |

本轮补验（2026-11-15）：`refactor-desktop-setup-exact.log` 的共用 Core 场景 1 项通过，
`refactor-cli-hub-setup.log` 的真实 CLI 组合角色首次设置、原配置恢复不重新配对场景 1 项通过。
`refactor-join-recovery.log` 的短码一次消费、Gateway 重启领取与未知结果不重放场景 1 项通过。
日志在原 `computer-concurrency` 证据目录。CLI 使用本轮已构建的 debug CLI 与原 d1cb41c
签名 payload；这是入口与恢复验证，不宣称最终同版本发布包已验收。第一次 Core 测试过滤
未匹配（0 tests）的记录保留，正确模块路径执行后才计通过。
Linux 桌面现有 CLI 首设缺 Exec 可取消选项，违反 REFACTOR-PLAN 的初始能力规则。
源码 `96aa1eb` 已补齐默认开启且可取消、部署传递与重开保持；CLI 局部 15 项测试和
all-targets Clippy 通过；整合后 `refactor-role-quality/receipt.json` 的 20 项标准质量门全部 PASS，
绑定源码 `96aa1eb1153ebab60547ccc0c74ef695d39f8d7b`。`refactor-cli-exec-roundtrip.log` 中两个真实隔离场景并行通过：
Exec 开启/关闭均连接成功，正常结束后原配置重开，部署与配对文件保持不变。无新增 GUI。
Windows/Mac 的 SSH 及独立验收插件均再次确认离线，未派发远端构建或更新；不能以本机
测试替代两端验收。

## 唯一剩余清单与顺序

1. **Host 配额遗漏与 C1、C2 验证收尾。** 本机按上面的用户首次安装交接继续，验证桌面来源及长驻 watcher； 源码清理、Linux 局部回归与整合质量门已完成；设备恢复后补两端原生编译和 Windows 正常页面路径。
2. **角色/入口剩余证据。** 上表已归并已有记录；核实 Mac/Windows 组合角色实际 GUI 首次设置，绑定最终版本；Linux 现有 CLI 入口已补验，非新增 GUI 项。未核实项不等同失败，不重跑已经通过且不受修改影响的整套拓扑。
3. **Mac 最终更新与受影响场景。** 当前最新配额修正只验证了 Mac 编译，正常更新后核对
   安装/选定/实际组件，再验证双对话读取及退出后继续。复用原配置、签名和安装路径。
4. **账号缺口。** Mac 后来的本机窗口/截图恢复已有证据，但不代替原 ChatGPT 账号路线的
   Computer 恢复验证；只补这条路径及最终版本绑定。已有双 Host Exec/Browser 成绩保留。
5. **最终交付。** 整合上述结果后冻结产品版本，按支持平台生成发布包；复用未受影响证据，
   核对必要的安装、原配置退出重开、卸载无残留进程和版本绑定。明确发布决定后才关闭 NO-GO。

第 2 项剩余的是上表明确的证据缺口，尚不能宣称所有角色入口都缺实现或都已验收。
源码清理完成不等于最终发布完成，安装完成不等于保存的组件选择已经切换。

## 不属于本轮阻塞

在线自动升级、Mac/Windows 常驻 OS 服务、新增登录启动实现、自动中心接管、Claude 接入
仍遵循 [延期范围](REDUCED-SCOPE.md)。已工作的能力不删除，但不借收尾扩展建设或验收。
上一轮口头列出的“在线升级、Mac 登录启动待补”不应自动升级为当前发布门槛。
不改生产 Tunnel/plugin，不操作 piermini，不负责底层网络保障。

## 维护方式

每次只更新本页的当前状态和剩余项。详细过程、失败原件和旧“下一步”放入
[历史记录](DELIVERY-HISTORY-THROUGH-20261115.md)或原 artifacts，不把它们追加为新待办。
关闭一项写明对应源码、实际入口和结果；新增一项必须指出违反了哪条已确认行为，
或哪项必要证据确实缺失。不要为每一步建立新候选、新项目或新的批准流程。
