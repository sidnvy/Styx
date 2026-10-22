# macOS 开发分支的跨平台整合 — 2026-10-22

本文保留最初 `d0f41e6` 同步轮次的来源与证据。后续 `ae86337` 已实现同一 Gateway 的附加精确 TLS 入口，`1b23221` 修正公开 join 预检，并有真实 Linux / Windows 附加入口验收；不再处于“附加入口待实现”状态，见[网络入口契约](add-computer-network-entry.md)。这不证明 Mac 新 UI 已接线、目标账号已验收或三平台已统一发行。

## 当前共享基线整合

共享开发按 [develop 工作流](development-baseline.md) 进行。本地 `develop` 已在 `c4aafad5ba46c098b81498b58619cb8b2b5e1c64` 真实合并原始 Mac 历史，parents 为 `4eaaac1` 和 `d2eca1106006684051d9c31828ee62de6b4651e2`。相对前者仅合入 8 个 Mac UI 文件（319 行新增、143 行删除）；涉及的 Mac Swift 内容逐文件等于 `d2eca11`，`gateway`、`onboarding`、`packages`、`plugin` 的共享 Core 保持 `4eaaac1`，与 Linux `1b23221` 公共 Core 一致。

CI 的产品源清单、`develop` push 触发、先 compile 再 native fixture 与 unsigned scratch 测试工件配置已在独立提交 `4964910` 修正，本地定向检查 17 项、16 通过、1 跳过。远端 `develop` 发布、Mac 隔离源码回灌以及整合后完整 quality / native compile 尚待完成；Mac 隔离副本的 Core 仍为旧 `d0f41e6`。这些源码与配置结果不等于已更新安装、完整原生验收或统一发行。

## 最初同步轮次的来源与保留范围

通过 Styx 只读检查并提取 Mac 开发目录 `/Users/it-bootstrap/Documents/StyxDevelopment/macos-ui/source`，从 `5a302a1` 到固定提交 `d0f41e675c9067b298b6333164b93fc3f05a3ef8` 的 11 个提交。初次提取时工作树干净；base tree 与本地 `fefc162` 相同。补丁 208433 bytes，SHA256 `da91435182a9730b0024657dd5c3d4048a0932cd209479e919d2a49a542bf4ea`。在原本地 `67494e9` 之后用 `git am --3way` 整合，没有冲突，原 Windows/Linux 修复和逐请求配对确认规则均保留。

| Mac 提交 | 本地提交 | 内容 |
| --- | --- | --- |
| fcc7516 | 2332e52 | 原生设置稳定性与本地诊断 |
| 8831768 | 61af88a | Tunnel 结构化日志 |
| bc36769 | 1b8daf0 | 保留生产依赖的运行目录 |
| 8df27b1 | 55ec559 | Mac 原生 ZIP 引导 |
| 5e6f340 | 6452db5 | 插件包含四项技能 |
| 2f6cfbd | 2835d11 | 可信 Tunnel 跨 MCP 连接的会话归属 |
| d999ea6 | eaaad7b | 在真实设置窗口读回验收 |
| fa10f6b | be7847f | 工具证明与人工账号确认分离 |
| 61e7471 | 018bafa | 当前输入框及 AX 窗口绑定 |
| 781a421 | d6ee58c | Cua 过期观察恢复，不重放输入 |
| d0f41e6 | 44bc208 | 匹配已签名 Cua 的真实拒绝响应 |

该轮随后只读复查时，Mac HEAD 未变，但三项产品 UI 文件和新增 `ProductTryoutView.swift` 已有未提交工作。当时没有提取或覆盖这些文件，也未改 Mac 开发仓库、安装、权限或运行状态。后续已提交 UI 的来源按上方 `d2eca11` 整合记录另行核对，不改写这次历史检查。

## 最初同步轮次的跨平台接入

共享 Core 继续使用现有权威配置和 API。可信 Tunnel 必须同时满足本地专用 capability 和正常 MCP bearer，才可使用平台提供的会话元数据；普通 MCP 客户端仍按连接隔离。新增复现并修复旧 owner 异步清理与同一会话新请求的竞争：新请求等待清理结束，避免新资源被旧清理删除。没有添加 MCP 会话数量上限，也不自动重放操作。

Windows 将只读刷新与用户操作分开，合并在途快照，拒绝旧观察覆盖新操作；刷新/切页保留未保存的 Tunnel 和能力输入，持久显示失败原因。重连分别显示进行中、已连接和未确认。浏览器偏好未知时保留原值。Exec 连接、逐项真实工具证明和用户账号确认分别呈现。

Windows 桌面验收使用真实 Settings TextBox、当前挑战、实际进程 PID 和顶层 HWND。Core 通过仅运行时注入的 provider 检查固定 App/Probe 文件及哈希、Node 实际父进程、同一交互会话和进程启动 ticks；HTTP/CLI 请求不能自报 authority 或 generation。无 GUI、锁屏/安全桌面、错误进程或旧 generation 均不算可验收。独立的 MCP 前置观察、真实输入、后置快照和原生读回仍然必需。`SessionProbe` 的可用状态本身不构成 Cua 证明。修复同值输入重试后不再读回的缺口；操作不重放。

Gateway 签名清单包含新会话与 Tunnel 模块。Linux 和 Windows 的真实输出均包含四项插件技能；Windows 也强制包含 native authority helper。锁定生产依赖不能按 `test/tests/fixtures` 目录名字粗暴删除运行文件，仍过滤私有状态并保留签名、锁、路径和 symlink 校验。只有真实 Windows 编译成功才在 runtime manifest 写入 App/Probe pin。这是包内一致性检查，不代表 Authenticode 发行签名。

Windows 本轮保留现有 Tunnel 设置路径。Mac 源码的 ZIP 默认交互已保留，但全新账号 ZIP-only 网页首装仍没有验证，不能据此切换所有平台的默认路径。Linux 首轮仍为 CLI、headless 与 Chrome/Edge Browser Automation；没有添加 Linux 桌面 App 或承诺其 Computer Use。

## 最初同步轮次的验证与证据边界

本轮 task 输出目录为 `outputs/mac-sync-20261022-d0f41e6`，保留来源元数据、原始补丁、最终 TAP 日志、检查摘要、NAB 原生编译命令及源码哈希。

- 共享会话、HTTP/Cua、插件、Tunnel、Core 和账号证据回归：95 项，92 通过、0 失败、3 个可选原生测试跳过。
- 使用锁定 Linux Node 22.23.3 的 Windows bridge/authority、HTTP API 和产物检查：74 项全部通过、无跳过。包含从实际输出启动 Core、独立复算插件清单/哈希、移除源码后启动签名 Gateway，以及生产依赖从 test/tests/fixtures 目录加载真实模块。
- 另行启用真实 Codex Exec Server 测试：通过临时认证 MCP 执行实际命令，独立 `write_stdin` 轮询到退出并记录生产 observer 证明，1 项通过。使用隔离 CODEX_HOME，没有真实聊天账号参与。
- NAB 两次全新隔离目录编译，最终目录为 `Documents/StyxMacSync-20261022-d0f41e6-final`。实际 .NET C# 编译 App 和 SessionProbe，warnings-as-errors 通过；真实控件自检覆盖九个页面、草稿/错误保留、重连反馈、挑战替换及同值读回重试。源文件哈希与本地最终版本一致。SSH 实际 Session 0，探针返回 `session_unavailable`；没有绕过这一边界，因此交互 Cua 与 ChatGPT 验收均为 NOT RUN。

只读复查 Mac 原生线程的新证据 `diagnostics/cua-idle-20261022/report.md`：修复后的网页会话闲置至少 422 秒，另一个 owner 保持共享 transport 活跃；回来后 Cua 观察并关闭 sheet、Browser 原页面读回及 Exec 独立轮询都通过，六个相关进程不变。原生三项 verified，用户 `targetChatConfirmation` 仍 pending。它证明该 Mac 的这一条真实链路，不等于新账号或其他平台通过。本 thread 自身的 Styx 源码检查曾遇到 `write_stdin` 内部错误及 `read_unavailable`；已取得 stdout，但没有把未确认退出当作新增远端 Exec 验收，后续需单独对照运行时日志排查。

## 尚未完成

- Windows 登录用户桌面的真实 Cua/独立读回、ChatGPT 新账号完整引导；本轮未安装或启动完整产品环境来冒充通过。
- 全新 ZIP-only 网页账号首装，以及长期验收历史跨挑战过期的呈现。
- 附加 LAN 入口的 Core / Gateway 与真实 Linux / Windows TLS、Exec、Edge、关窗口后重连已经补齐；完整原生 App 与目标 ChatGPT 账号的普通用户流程仍需验收，Mac 新 UI 接线须单独确认。当前物理证据为任务输出 `outputs/cross-platform-ready-20261022/delivery.json`（`1b23221`，Gateway 9 项、Windows 6 项通过）。
- 统一发行、各平台完整升级/回滚及整机重启验收。后续 Windows / Linux 已有隔离工程候选和按来源记录的原生检查；Linux 后续受控升级/回滚有独立 PASS，早期 quiescence BLOCKED 记录仍保留，不能推广为任意后续版本均通过。
- 本地 `develop` 已整合 `d2eca11` UI 并保留当前公共 Core；Mac 隔离源码回灌、整合后完整 quality / native compile 及平台调用链验收待完成。源码回灌仍不等于更新安装。

上述最初同步轮次没有 GitHub 推送、PR 合并或线上部署，也没有修改 piermini、NAB 既有服务/配置/权限或 Mac 安装。当前 consolidation 的源码同步/分支发布与既有安装部署分别记录，不从旧轮次的结果推断当前已完成。
