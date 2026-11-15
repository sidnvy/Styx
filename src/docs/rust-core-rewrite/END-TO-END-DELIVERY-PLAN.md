# Styx 重构当前交付清单

更新：2026-11-15。唯一当前待办入口；产品规则以 [REFACTOR-PLAN](REFACTOR-PLAN.md)
为准。初次审核源码 `5c39783`；结构清理 `efab8be`，旧测试修正 `8f8d278`。
moedeu-apps Gateway 已原配置更新至 `0.4.1-gateway.2`（源码 `70e634a`）；本机由用户
自行安装 Linux Desktop `0.4.1-preview.2` 并加入 moedeu-apps，设备名 niuda。
Windows 已安装源码 `8fa9a1b` 的 `0.4.1-preview.3`，正常改配 moedeu-apps；Mac 已安装
源码 `5610aad` 的 `0.4.1-preview.3` 并改配同一 Gateway。两端已完成原生编译和实际能力验证；
当前剩余问题与最终发布资产见下文，不再将设备离线或客户端未安装列为待办。
历史正式 0.4.0 已发布；本轮重构版尚未正式放行。

## 当前桌面更新与账号验收（2026-11-15）

- Windows：`8fa9a1bcd77525cdb4aa010be947d083453826a6` 包含 C1/C2 清理、共享
  Gateway 状态/大截图修复及应用/安装器图标。最终 Inno `0.4.1.2017` 已正常安装；
  已安装程序含图标资源，开始菜单指向同一新包。原配置先在 NAB5 本机备份，再由用户
  通过正常 GUI 加入 moedeu-apps，设备 `styx-74a81308ccce927899aa2950`。
  选定 manifest 与已安装 manifest 均为 `5636ece901ea7797cc75e5a9a97d01738822878995d89d80d63d5dfd86f7cf76`，
  Core 哈希一致。正常退出旧 App/Core 11636/7664 实际 exit0，原配置重开新 App/Core
  12536/3804，配对与配置摘要不变。当前账号 Styx 工具已实际通过 Exec nonce 文件、
  Browser 导航/关闭、窗口树和 740×940 PNG；直接 MCP 另有 Browser 写入/独立读回、
  截图后同一会话继续调用结果。证据复用 `Artifacts/Styx/windows-gateway-update`。
- Mac：原签名 App build 2015 / Runtime `0.4.1-preview.3`，源码 `5610aad`，安装、
  选定 manifest 与实际 Core 已核对一致。经 moedeu-apps 的直接 MCP 曾实际通过 Browser
  导航/写入/独立读回/关闭、窗口树、1024×958 PNG、截图后继续调用；证据在
  `Artifacts/Styx/mac-gateway-update`。用户正常重启后 App/Core/Cua 为
  36554/36556/36557，当前账号窗口列表、截图、Browser 导航/独立快照/关闭通过。
  控件树失败已取原生证据：窗口 71781 无对应 AXWindow，返回 `ax_window_unresolved`；
  TCC 权限正常。源码已修正错误归类，不再误报权限，并修复临时可用性变化永久隔离、
  完整 Unknown 响应阻塞后续独立读取。新修复尚待安装及同一 owner/双 owner 实测。
- Windows 加入进度条曾被用户报告等待较久；随后真实截图显示已配对且已连接，进度条
  已消失。未复现持续卡死，没有重放加入，也没有据此引入重试或配额。
- 发布身份沿用既有 Styx publisher 和 Mac 本地签名。新增 notarization、Authenticode、
  在线自动升级仍属延期范围，不增加为本轮门槛。当前正式版本号与四平台下载资产尚未统一，
  功能验收通过不等于已生成或已发布正式 Stable。

## 用户安装后的 niuda 能力修复与验证

用户原安装和配对保留，Host PID 929414 未变，配置摘要前后相同；没有重装或重新配对。
修复源码 `70e634a2aaff2aadfc135c40c59583a2e0409a8b`：管理列表改用实际共享连接状态，
删除 MCP 出站 256 KiB 限制及其关闭会话路径。保留入站请求边界，没有增加会话/能力配额。
完整整合质量门与官方 SDK 大图片后同会话继续调用回归 PASS；Debian 12 构建及原身份签名 PASS。
moedeu-apps 通过正常退出、备份、发布选择、重开更新为 `0.4.1-gateway.2`，选定与运行组件一致，
Gateway 身份、配对与 Tunnel 配置摘要不变，旧 22026 服务未动。

原 niuda Host 经 moedeu-apps 的认证 MCP 实际通过：三项连接 connected、4 个真实窗口、
1024×611 PNG（响应 357646 bytes，超过旧限制）、截图后同会话再次读窗口、浏览器写入文字并独立
snapshot 读回、关闭自有浏览器会话。截图已视觉检查。证据目录：
`/home/sid/Developer/Artifacts/Styx/niuda-capabilities-20261115/result.json`。
随后按用户授权在 ChatGPT 正常创建并 Connect「Styx moedeu-apps」，复用原 Tunnel，
没有改安装、配对或 Gateway 密钥。账号对话 `6af85143-d800-83ec-98c2-6538d0609351`
实际发现 niuda、读 4 个窗口、返回 1024×611 PNG、截图后再读窗口；Browser evaluate 写入
`Styx-ChatGPT-acceptance-20261115` 后由 snapshot 独立读回并关闭测试会话。
账号验收回复保存在同目录 `chatgpt-account-result.json`；Gateway 的 ChatGPT last seen 已刷新，
Host 仍为 PID 929414。此项不含 Computer 点击/输入、双对话或长驻验收，Stable 仍为 NO-GO。
用户要求清理旧同名插件：旧 0.1.0 已删除；旧 1.0.1 App-backed「Styx」两次返回
`Couldn't delete plugin. Try again`，仍未删除。新连接可用，不因清理错误重建或改配设备。

## Linux 双形态安装交付（0.4.1-preview.2）

本机首次安装前清场已完成：旧测试 Gateway PID 860339 正常退出，临时 unit 已回收，
38443 端口释放，本机无 Styx 用户服务/进程，默认配置与命令入口未创建。剩余测试配置
已迁入既有归档；moedeu-apps Gateway 只读认证查询成功、未修改。证据见本版
`local-test-retirement.json`。

[双形态预览版已公开发布](https://github.com/sidnvy/Styx/releases/tag/linux-v0.4.1-preview.2)，四项资产摘要匹配。
源码 `27a61d61107b56e328001e011ad8f379750a50e1`；完整材料在
`/home/sid/Developer/Artifacts/Styx/linux-install-preview-0.4.1-preview.2`。
Gateway-only、Desktop（Host＋可选 Gateway）两个包均带单一 `./install.sh`：
安装验证并复制至持久用户目录，注册固定命令，再进入原设置或更新流程。
Gateway-only 通过明确确认及系统授权处理已有 user manager 的 linger；桌面不改 linger。
Linux `styx quit`/`styx start` 复用原 service authority，不增加后台进程或持久管理层。

- 20 项最终整合检查 PASS，Debian 12 构建与两套原发布身份签名、分发校验 PASS。
- Desktop 最终包真实安装、下载目录移走后运行、同版本重装不改变进程/配对、
  原进程退出、原身份重开、卸载服务 PASS：`Artifacts/Styx/it2/result.json`。
- Gateway-only 最终包安装、systemd 启停/卸载 PASS，未创建 Host：
  `Artifacts/Styx/ig2/result.json`。两份结果已复制到本版本交付目录。
- 两次测试环境失败完整保留：第一次测试路径超过 Unix socket 长度限制（155字节），
  第二次 tmpfs 用户配额阻断复制；没有据此报告产品验收通过或重放未知服务动作。
  最终测试使用持久磁盘上的短测试目录。默认用户配置未创建，moedeu-apps 未改配。
- 独立代码审核发现并修复连续升级 CLI 链接及未完成升级恢复问题；
  当前安装入口委托既有 updater 处理原步骤，只在其确认完成后补齐命令入口。
- 正常 CI 的 Linux assets 已改为同一 distribution producer；其 9 项局部测试 PASS，
  不再保留第二套手工 README 包装。
- 用户本人首次安装与加入已完成；直接 MCP Browser/Computer 验证见上。ChatGPT 账号路线、双对话使用及长驻观察仍待完成。
  跨平台 Stable 仍为 NO-GO。不要替用户预配对再声称其首次安装已通过。

`/tmp` 历史材料已迁移至 `/home/sid/Developer/Archives/Styx/tmp-20261115`，
记录见 `relocation.json`；当次占用由约23GB降至8.7GB，运行中的测试 Gateway 配置保持原位置。
后续大文件与证据统一走 WORKSPACE.md 的持久目录。

## 前一轮安装交接（已由 preview.2 替代）

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

C1/C2 已实施源码删除，Mac/Windows 原生编译、安装及三能力实测已有结果。剩余的是当前
Mac Computer 恢复与双 owner 场景、组合角色新增入口适用性和最终发布绑定，不是重复编译或重装。

| 项目 | 审核证据与判断 | 下一步及完成标准 |
| --- | --- | --- |
| C1 Windows 旧 UI 模式 | InitializeCore 只接受 rust_host；已删除 ShowPage/ShowStatus 的旧模式路径、ReconnectResult 等专用回调及旧测试状态 | 源码完成，草稿/状态检查已迁到原生状态，共享向导保留；Windows 原生编译、正常主窗口、设置及图标安装路径已验证；托盘正常退出与同配置重开已通过 |
| C2 旧预算对象与参数 | 已删除 bootstrap Partitions、HostLinkBudget、Codex partition 句柄及 BrowserIoBudget/CuaIoBudget 空对象 | 源码完成，保留实际传输缓冲、期限及进程清理所有权；Linux 本机验证见下文，Windows/Mac 条件编译消费者已更新且原生构建和三能力实测通过；Mac 双 owner 与当前恢复待补 |
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
两端条件编译接口、原生构建与正常更新已有上述当前证据；Windows 页面和正常退出重开
已通过，Mac 当前账号 Computer 恢复与双 owner 验证仍待补。

## 角色与入口证据核对

下表归并已有记录，不把旧包的通过算作 `efab8be` 的原生验收。

| 角色/入口 | 已有依据 | 本轮边界 |
| --- | --- | --- |
| Windows Host-only | 历史“更新完成后的所有权释放与 Windows 实机闭环”：正常短码自动加入、更新后改配、原配置退出重开；“取消运行时配额与双对话实机验证”：d1cb41c 双对话独立效果 | C1 后原生编译、设置/主窗口和托盘正常退出重开已通过，复用当前 8fa9a1b 证据 |
| Mac Host-only | 历史“本机测试 Gateway 与 Mac 能力开关”：正常短码自动加入，三项能力关闭/重开及原配置恢复；“桌面统一入口与单窗口收敛”：用户确认单窗口、正常更新退出重开 | 最新配额/C2 已完成安装和直接三能力验证；双 owner 与当前账号 Computer 恢复待补 |
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

1. **Mac 当前 Computer 恢复及双 owner。** 已定位并修复临时可用性、Unknown 后读取和 AX 降级误报；安装后
   验证两个独立 owner 对同一 Mac 的重叠读取，以及 A 退出后 B 继续。保留当前配置、配对与
   失败原件，不以重配或清空 profile 替代恢复。Windows/Linux 已通过且不受变化影响的并发证据复用。
2. **组合角色新增入口证据适用性。** 旧 Mac/Windows Gateway+Host、三能力、正常退出恢复
   已有实机记录；本轮共享 Core 的必配 Tunnel、初始 Exec 选择和 CLI 组合首设/恢复回归已通过。
   逐项核对新版 GUI 将 Tunnel 并入首次创建及统一导航后的入口与这些证据的映射，只补确实
   变化且未覆盖的原生路径；不为了矩阵重新改配当前日常 Hosts，不重跑旧完整拓扑。
3. **最终产品版本与四项下载包。** 更新正式版本元数据并冻结产品源码，复用原生缓存与
   原发布身份，生成 Windows x64 EXE、Mac arm64 DMG、Linux Desktop 与 Gateway-only tar.gz，
   以及统一 SHA256SUMS/公钥和安装说明。Cargo 元数据已准备为 `0.4.1`，现有
   桌面 `preview.3` 与 Linux/Gateway 包绑定不同源码，不能直接改名宣称同源正式版。
4. **最终绑定和发布决定。** 核对最终资产与已通过场景的源码/组件差分；保留 Windows
   当前正常退出重开、Linux 双形态实际安装/启停/卸载、历史未改动 Mac/Windows 卸载证据。
   只对相关差分或当前失败补验，不因重新封装重复所有用户旅程。当前 Mac 账号恢复和
   组合角色新入口确实未覆盖的部分关闭后，记录明确的 Stable 决定，再完成发布。

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
