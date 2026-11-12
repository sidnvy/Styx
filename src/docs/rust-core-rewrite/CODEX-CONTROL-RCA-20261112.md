# Codex 控制链根因核查（2026-11-12）

本报告核查开发/验收控制链，不改变 Styx 的 Gateway/Host 架构或发布门槛。
用户决定：停止适配自写桥接，不重发原 C31 安装指令；随后明确授权先通过 PilotMac 官方连接做一次独立只读探针，验证执行后再继续 Styx。

## 结论与边界

已证实的故障是：同一 NAB5 聊天曾由 SSH 与桌面两种 app-server 上下文争用；
协调器又把 CLI 入队当成桌面任务启动。这是控制路径选择和会话归属的编排问题。
不能因此声称跨机消息整体不受支持，也没有证据将本次所有问题归为 OpenAI 产品缺陷。

手机已能通过原生 NAB5 设备入口打开原聊天，证明该路径的设备发现和聊天访问可用。
本轮没有通过该官方路径发起新 turn，故不把“能打开”扩大为所有执行能力已验收。
用户随后明确确认：niuda 的 Connections 中没有 Control other devices 页面。
因此，当前安装客户端没有暴露官方文档描述的原生设备控制入口；不是继续寻找某个遗漏开关的问题。
当前已知 `wenden-win` 目标是 SSH 连接，不能作为该原生入口的替代。
页面缺失究竟对应 Linux 平台支持、此版本或功能灰度，尚未分别证明；不据此断言所有 Linux 版本永久不支持。
用户又确认已在 PilotMac 的 Control other devices 中添加 NAB5。这是正式原生控制连接的配置进展，
尚未验证从该连接发起 turn、其内置跨聊天工具的目标暴露，或 niuda 根聊天可通过它自动协调；不把添加设备当作完整消息链验收。

本轮已通过正式 `send_message_to_thread` 将该验证任务交给现有 PilotMac owner
`01a1caa8-0096-7572-bdde-e474a8e64f01`（`remote-ssh-discovered:pilotmac`）。
owner 完成检查并报告：其当前暴露的工具没有官方设备/聊天发现和发送接口，无法获得原生 NAB5 hostId。
因此这次没有向 NAB5 发送探针（0次），没有实际接收执行证据，也没有调用私有桥、CLI queue 或 Windows SSH 恢复。
这只证明当前 SSH owner 缺少所需工具，不能推断 PilotMac 桌面新增的官方连接本身不可用。
下一验证入口为 PilotMac 桌面已登记的 NAB5 原生设备，打开既有聊天
`01a1bc09-6a26-7751-80d1-2e945120df79`（「接手 Styx GUI 验收」），
发送一次 `PILOTMAC-NAB5-OFFICIAL-READONLY-20261112-01`，仅记录机器/cwd/PID/Session和完成收据；
探针明确暂停安装队列、安装器和 Styx 操作。Root 不用 SSH 聊天接口代替这个原生入口。

本人随后确认已从 PilotMac 官方入口发出该探针。Root 经普通 SSH **仅读取结果文件**，
取得 NAB5 原聊天生成的完成收据（`2026-11-12T06:39:47.2968627Z`）：
nonce和目标chat UUID均精确匹配；机器`NAB5-WIN`、cwd `D:\Developer\Styx`，
执行进程`pwsh.exe 2912 / Session1`，父进程为桌面`codex.exe 14116 / Session1`，
再上层为`ChatGPT.exe 11556 / Session1`。状态`READONLY_VERIFICATION_COMPLETED`。
本轮安装器启动和Styx操作均为0。原聊天报告旧C31尝试因旧`codex-code-mode-host.exe`
不存在（os error2）在工具执行前失败、未派发安装；该失败保留，不视为安装成功。
因此 **PilotMac官方入口→NAB5原聊天→真实桌面上下文命令执行已通过**。
这是本人从官方入口提交的验证，不是Root自动A2A发送成功；当前Mac SSH owner的工具缺口仍存在。
证据：`D:\Developer\Styx\tasks\native-owner\PILOTMAC-NAB5-OFFICIAL-READONLY-20261112-01.json`。

## 官方连接模型

| 工作 | 官方路径 | 本轮应保持的约束 |
| --- | --- | --- |
| 桌面 GUI/Computer Use | Mac/Windows 桌面 App 作为宿主，通过原生 Remote Control 访问宿主聊天、权限和工具 | GUI 验收聊天归属桌面实例；Windows 保持解锁的活动桌面 |
| 源码、构建、文件和 shell | Settings → Connections → SSH；通过登录 shell 启动远端 Codex app-server | CLI 工作与 GUI 验收使用清晰、不同的会话归属，不能同时争用同一聊天 |
| 自建产品的 Codex 集成 | 公开 app-server JSON-RPC 或相应 SDK | 不是现成桌面 App 的私有 IPC；不能据此假设新开 server 能继承现有桌面权限 |

官方明确列出的原生远控宿主为 Mac/Windows，手机或受支持的 Mac/Windows 客户端可控制这些宿主。
Linux App 仍为 preview，官方文档明确其原生 Computer Use 尚未提供。
不能把 niuda Linux 客户端当成已验证与 Mac/Windows 完全等价的原生控制端。
这些限制针对 OpenAI 原生客户端；Styx 独立 Linux 工具验收结果保持不变。

## 已验证因果链

1. NAB5 本轮正常重启后，SSH app-server8024 在 Session0 先启动，桌面 app-server14116 在 Session1 后启动。
2. Windows Restart Manager 对目标 UUID `01a1bc09-6a26-7751-80d1-2e945120df79` 的锁查询，曾确认 writer 为 SSH8024。
3. 当前 boot 且明确归属这些 PID 的日志中，桌面14116 对该目标产生8条 writer 冲突记录；记录数不等于8次独立尝试。
4. 仅正常断开 niuda 的一个 SSH 客户端后，父进程 `/usr/lib/chatgpt/ChatGPT` 在约1秒后重连。
5. 本人关闭 niuda 的 `wenden-win` 连接开关后，原客户端消失；13:19:43 上海时间，目标锁文件不存在、无持有者。没有删除锁或结束远端 Codex。
6. 后续既有内部桥的只读检查曾返回桌面14116对精确 UUID 的 `owner_found/resumed`。用户要求停止内部桥后，不再调用它。

因此，Windows 桌面曾因另一执行上下文持有同一聊天而被拒绝，有直接证据。
关闭自动 SSH 连接解决了这项争用，但不等于已触发桌面任务或消费原队列。

## “原桥接”究竟是什么

现有 `nab5-native-owner.py` / `native-owner-bridge.ps1` 是自写辅助程序：
经 SSH 访问 Windows 本地 `codex-ipc` named pipe，发现桌面 owner，调用内部
`thread-follower-*` 方法。历史存在向 GUI14588发起 start/steer 并收到 accepted 的收据。

它不是 OpenAI 文档承诺的稳定跨机控制接口。其发送 guard 只允许旧 alpha3.2；
当前桌面 CLI 为 alpha4.1。旧 inline PowerShell 传输还出现了执行前的解析错误。
换既有 SFTP 暂存传输后，只读 Inspect 成功，但这不是新版本发送合同已经验收。
源码存在相同 handler/协议编号，也不能将内部接口变成正式接口。

本轮没有修改 guard/helper，也没有经该桥发送新消息。后续不把维护这段内部适配作为根治方案。

## 队列与版本事实

- 原 C31 nonce `NAB5-NATIVE-C31-INSTALL-20261112-01` 仅在12:42:41入队一次，记录 `resume_requested=false`。
  尚无匹配的完成收据；没有重发。CLI queue 的确认不是 `turn/start`、GUI 执行或安装完成。
- 选择桌面版 `codex.exe` 文件，不会自动把消息绑定到那个已经运行的桌面 server。
- niuda 本地包元数据为 `chatgpt-desktop 26.1103.60933-1`，描述为官方二进制重打包；
  当前同步数据库没有该包的候选。NAB5 桌面安装资源版本为 `26.1106.6628.0`。
  版本和更新来源存在漂移，但未证明它造成 writer 故障。
- 重现应用真实的登录交互 shell/PATH 前缀后，SSH 入口是 `~/.local/bin/codex`，
  一个明确引用旧 f71 可执行路径的文本 launcher；当前 SSH8024运行该路径。
  普通非交互 SSH 缺少 `codex` 的 PATH 结果已撤回，不能拿不同 shell 上下文证明配置错误。
  尚未证明该 launcher 的创建者、更新策略或版本差异造成了协议不兼容。

## 分开的故障与未证明项

- 用户此后明确要求SSH分配新配对任务、再要求新建NAB5聊天。公开queue向旧UUID的单次投递因读取该thread元数据`Access is denied (os error5)`失败，没有入队确认；未改ACL或调用私有IPC。
- Root当前`list_projects`没有NAB5目标。使用官方`codex exec`在现有项目新建一个独立CLI会话后，外部确认thread `01a1cf18-2ec5-7d33-a068-f42233350c02`、PID1652/Session0。新任务可发出模型/工具请求，但本地Exec/Node连接runner pipe-in均15000ms超时，正式CUA getState启动失败。它产出`BLOCKED_DESKTOP_CONTEXT`，未进入配对READY或产生产品效果。新聊天创建不能自动证明已有原生桌面工具；超时的具体原因不能仅凭Session0归因。
- 新任务还报告配置项`computer_use.windows.always_allowed_app_ids`不被当前版本识别而忽略；本轮未修改该设置，不把此警告直接归因为runner失败。

- 当前 NAB5 指定 PID/boot 日志范围未检出注册409/already-online；不能把历史注册冲突与本次 writer 冲突合并。
- niuda 的 “Couldn't update remote control availability” 原始失败原因尚未定位；平台支持矩阵、错误 UI 和原始服务错误需要分开。
- 本轮恢复后，Styx 可枚举 niuda 的 ChatGPT 窗口，但读取其树得到 `PERMISSION_REQUIRED / desktop_read_not_proven`；
  没有改用像素或脚本绕过。其后用户亲自确认 Control other devices 页面不存在，页面状态采用该用户观察；
  工具本身没有读到此设置，也没有证明隐藏配置或功能灰度值。
- Sunshine503是独立的显示捕获故障：正常服务重启无效，获准的一次 Windows 重启后编码器就绪、用户确认 Moonlight 连通。
  该恢复不能解释或修复 Codex 会话归属。

## 根治路线与验证出口（尚未执行）

1. 保持内部 IPC 发送停用，保留既有队列和所有失败/UNKNOWN收据。
2. 为 GUI 聊天固定一个桌面 owner，取消通过 SSH 自动恢复该同一聊天。
   需要 SSH 的构建工作复用其他既有 CLI 会话/正式命令，不创造每候选新聊天。
3. 先使用已确认存在的官方 NAB5 原生设备路径作一个受控只读 turn 对照，确认真实桌面上下文及工具。
   若正式路径也失败，保留最小复现和日志，才按客户端缺陷处理。
4. 由于 niuda 当前客户端缺原生设备控制入口，先评估有该入口的受支持 Mac/Windows 控制客户端，
   验证其正式连接及内置聊天工具能否选择真实桌面目标，再决定控制会话的接管方式。
   niuda 的源码与唯一集成 checkout 保持，Styx Gateway 仍为 moedeu-apps；不靠内部桥补齐缺失入口。
   迁移/配对/更新本轮不自动执行，也不承诺只换前端就一定能恢复自动 agent-to-agent。
5. 正式路径成立后，才让原 owner 处理已经排队的 C31 指令，独立核对消费与执行；不重新提交安装。

## 证据

- `Developer/Artifacts/Styx/native-checks/native-queue-delivery-20261112.json`
- `Developer/Artifacts/Styx/native-checks/native-writer-release-20261112.json`
- `Developer/Artifacts/Styx/native-checks/native-owner-route-20261112.json`
- `Developer/Artifacts/Styx/native-checks/nab5-official-path-rca-20261112.json`
- `Developer/Artifacts/Styx/20261109-codex-remote-control/OWNER-IPC-{A,B,C,D}-*.submission.json`
- `Developer/Artifacts/Styx/20261109-codex-remote-control/NAB5-NATIVE-C31-INSTALL-20261112-01.submission.json`

官方资料：

- https://learn.chatgpt.com/docs/remote-connections
- https://learn.chatgpt.com/docs/developer-commands
- https://learn.chatgpt.com/docs/app-server
- https://learn.chatgpt.com/docs/linux/linux-app
- https://learn.chatgpt.com/docs/computer-use
