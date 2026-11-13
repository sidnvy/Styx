# Styx 原生 GUI 与 Custom MCP 端到端交付计划

2026-11-08。本文是**剩余交付工作的唯一执行入口**；范围由
[REDUCED-SCOPE.md](REDUCED-SCOPE.md) 决定，架构由
[README.md](README.md) 和冻结合同决定。
[GUI-CONVERGENCE.md](GUI-CONVERGENCE.md) 保留历史尝试与证据，不能把历史通过当作当前候选通过。
本文中的计划项不代表已经执行；当前状态以最新检查点为准。**功能验收通过；正式 Stable Release 尚未交付。**

## 当前开发检查点（2026-11-12）

### 当前阻塞：Mac 正常 MCP 会话清理（2026-11-13）

`47427bb` 的三平台构建、contracts 和 20 项质量门已通过；Mac build1152 已原位安装，
GUI 的 Runtime 更新已 Committed，实际 Core 与新选择一致，AX/SR 均已生效。
独立 Gateway→Host/Core→Cua 的真实截图通过。两个测试窗口均自行正常结束且独立记录为
零写入；真实文本写入、按钮点击及正常退出重开尚未通过，不将截图当作这些场景的结果。

原 MCP 会话的一次 DELETE 返回 HTTP 500，随后新 owner 的一次读取明确返回
`computer_not_dispatched`、`uncertain:false`，没有重放写入或旧 DELETE。新空会话已单次
关闭且没有 DELETE 错误；这不能证明原资源已经完成清理。App/Core 仍响应，保留原实例。

两位 owner 并行只读确认直接代码缺陷：资源清理先取消 `resource.stop`，而原 MCP
transport 使用同一 token，因此后续标准 `end_session` 在准入处被本地拒绝。
已分离业务停止与原 transport 的关闭时机；仍保留原 client、预算、协议拒绝和实际
IO join。官方明确的 cleanup pending/partial 已与普通未知失败区分，只继续同一会话
明确未完的清理，不重发用户操作。本机受影响 Cua 回归 50 PASS、0 FAIL，保留原有一项
需原生 capture receipt 的 ignored；真实 transport 测试同时复现旧接线的零字节拒绝并
验证新接线完成 request/reply/close。Mac 独立官方 proxy 的只读 start/read/end 和真实
exit0 已通过，证实上游正常清理可用；这些结果尚不替代修正版的产品内验收。
原 `47427bb` 的 daemon-first 故障退出场景已实际通过：预先观察原 App/Core/Cua/Codex，
一次标准 PID-bound stop 后 Cua 真实 exit0，随后一次正常 App Quit，其余三进程均真实
exit0，全程零信号、零强制处置。旧 DELETE 500 仍原样保留，不据此改成会话清理成功。
仅补受影响的 native 效果、会话结束和同身份恢复；Windows 17 项及其他已通过场景不重跑。
**Stable 仍 NO-GO；先完成开发原生验证，再冻结匹配的新发布输出，不发布旧包。**

### 最新修正：Mac 授权后的 daemon 退出清理（2026-11-13）

用户已完成正常系统授权，AX/SR 的 TCC 均绑定新 `9a4` 证书。录屏授权后原 Cua daemon
已退出，App/Core 仍在；一次正常 Quit 未完成，后续只读状态请求也等待原 Core 响应。
原生 sample 显示 App 原控制队列等待 Core，Gateway 独立确认 Mac 已 disconnected。
没有重放 Quit/Runtime 更新、没有强杀、没有重启或清空身份；已退出 Cua 的原 exit status
未独立观察，不补写为正常退出。当前运行实例仍是下面的 `4d03b72` 包，不能视为验收通过。

源码缺口已修：清理复用原 socket peer 绑定的完整 daemon 身份，在其确定结束时记录
独立物理终止事实，并仍实际 join 原 proxy/transport/probe/stderr；不伪造 `end_session`
ACK，不改变历史动作 Unknown，不接纳替代 daemon、不增加私有协议。Swift 的原 owner
意外退出只设置显式恢复标记，仍由 Continue 先收拢原 Core，再恢复，不能自动重放。
Linux 原缓存 5 项边界及 6 项严格写入回归、Mac 原缓存 Rust 增量检查和同 5 项原生测试、
Swift 完整类型检查和权限恢复自测均通过。随后统一冻结修正版，复用缓存生成匹配包。
旧实例卡在旧代码，不能热加载修正；精确处置须在修复/验证与新包就绪后另行明确授权。
**Stable 仍 NO-GO：修正版实际 Runtime 选择、真实效果、正常退出恢复及正式发布尚待完成。**

### 当前：0.4.0 Stable 收尾（2026-11-13）

用户授权并行关闭 Windows 17 项失败和新版 Mac GUI，复用已经通过的证据。
正式版本已定为 `0.4.0`，构件冻结源码为 `4d03b72f25cfb4cafcac93763b6a6d3a0b08da25`。
[最终 contracts](https://github.com/sidnvy/Styx/actions/runs/43388111573) 四个 job 全部通过；
Windows 为 92 PASS、0 FAIL、15 个平台/环境限定 skip。17 项旧失败已收口：修复安装器真实
8.3 路径别名比较，修正测试路径/权限/换行及 Quit 各分支计数，不删除有效负控。
原 Windows 安装准入 3 项及 Quit 14 模式也在 NAB5 实际通过，未改该设备安装或身份。

[正式发布构建](https://github.com/sidnvy/Styx/actions/runs/43388310324) 已全部通过：
20 项质量门、三平台 Core/Cua、签封及四份正式包。`complete-release` artifact 为
`14021976762`，四文件 SHA256 和固定 publisher pin 已独立核对；正式 tag/Release 尚未创建。

Mac 最终 DMG/build1151 已验签并原位安装，App/Core 为冻结源码，新 Cua 为 0.47.24。
旧四个原进程均正常 exit0，原身份/凭据/CA/seed/deployment 保留。用户已明确授权并完成
新 `9a4` 证书的正常系统确认，只读核实其信任仅限 CodeSigning。
**当前还不能算 Mac 通过：**App 已更新，但持久状态仍选旧 `.33` Runtime `8e631746…`，
尚未正常 GUI 选择新 `335dbd57…`；AX/SR 仍 false，TCC 授权仍绑定旧 `cb50`。
用户切换 AX 开关后旧签名绑定未变，已请用户在正常辅助功能页移除旧 Styx 授权行并重新
添加 `/Applications/Styx.app`。不直接编辑 TCC、不改 SIP/Gatekeeper、不重复未知操作。
授权生效后仅补新 Runtime 选择、真实 Gateway→Host/Core 的受影响 Computer 效果及正常退出恢复。
旧配对、Browser/Exec、安全、卸载等未变路径证据复用；不自动重建用户已删除的插件。
**Stable 暂未放行：仅剩上述 Mac 必需场景及随后正式 GitHub Release 交付。**
正常用户步骤见 [0.4.0 设置指南](../stable-setup.md)。

### 最新更正：验收通过不等于正式 Stable 发布（2026-11-13）

用户明确指出正式Stable应有全新正式安装包并通过GitHub Releases交付。此前将自用范围的
验收门槛通过写为“Stable GO”过早，现撤回正式发布完成的含义；下列验收与性能原始证据
保留有效，不能据此声称已有正式Stable版本。只读核实Cargo仍为`0.4.0-dev.1`，GitHub现有
Release仅为10月19日等历史Preview，没有本轮Rust正式Stable。

正式发布还需明确版本/tag、正常产品身份/默认路径的独立安装包、四目标运行包、SHA256与
发布说明，以及“moedeu-apps Gateway-only、其他设备Host、一个ChatGPT插件”的正常用户
指南。现有候选、测试配置和密钥不直接作为用户安装输入；已有功能证据复用，仅补版本/
包装真实影响的检查。不因用户询问发布方式就对外发布、改变仓库可见性、重装现有设备或
替用户创建插件。当前未创建新的GitHub Release，也未上传本轮候选。

### 最新使用状态：用户自行重新设置插件（2026-11-13）

用户明确要求两个旧连接都移除，再自行按真实用户流程设置。已通过插件管理工具卸载
`Styx GUI Acceptance` 与 `Styx Tunnel Icon Check`，已安装列表核对均不存在；取消此前
保留前者改名的方案。不自动创建、重新连接或替用户设置新插件。三端App/Runtime、
服务器配置、配对/密钥和工程文件保持；下列Stable放行与账号效果为已完成的验收证据，
不表示用户主动卸载后仍有已安装ChatGPT连接。后续入口设置由用户接手。

### 最新：Stable v1 已放行（2026-11-13，上海时间）

用户要求复用已通过证据并直接收尾。此前“Stable需另行核验”未列具体缺口，现已完成明确审查；
**Stable GO，限既定自用v1范围，复用产品冻结9104的四目标.33，构件/签名/安装均不重做。**

唯一补测是当前Linux启动计时：完整空配置本地Hub+Host创建至Gateway确认Exec连通并setup完成
上界1.270957624秒（目标<10），同profile重开上界0.457574077秒（目标<3），各一份样本；
后续独立Exec40 actual exit0。前者正常退出0且临时资料清理，后者保留原身份并保持在线。
已过功能矩阵不重跑：53条原PASS/106份日志摘要及9104当前24项Gate完成适用性核对；
Mac旧fresh Gateway业务通过与1142默认入口实跑按24份GUI源及Rust改动路径明确映射，
不把旧producer伪称有sourceFiles，也不声称又跑了一次.33默认Gateway。

16项必需场景的证据层级和适用范围已明确；旧SPEC移除/延期项不重新变成门槛。
原失败/Unknown与KVM只读未确定假设继续保留，不将历史记录改写为成功。
[Stable放行决定](/home/sid/Developer/Artifacts/Styx/native-checks/startup-check-removal-20261112/final-source-9104/STABLE-DECISION.md)；
[逐源/日志/场景证据映射](/home/sid/Developer/Artifacts/Styx/native-checks/startup-check-removal-20261112/final-source-9104/stable-decision.json)。没有剩余本次Stable阻塞项。

### 此前：同源 .33 剩余验收与 P7 核对完成（23:53 上海时间）

四个目标均以产品源码 `9104d6a84c69b89cb81537ef7aad26099ed870e4` 正式生产并完成实际选择/部署；
当前Linux、Windows与正式Mac三Host由独立账号确认connected，既有身份/配对/密钥保持。

| 目标 | 本轮实际补齐 |
| --- | --- |
| Linux | 原foreground入口卸载/装回、正常exit0、同profile恢复、独立Exec91；默认服务不动 |
| Windows | .33实际Runtime选择已Committed；官方卸载一次实际清空入口/shortcut/HKCU/产品进程；同SHA原位恢复；正常退出/自动重开与Exec21新文件通过 |
| Mac | 同签名DMG/build1142，标准Trash真实卸载后原位恢复；同身份自动重连及Exec90通过 |
| Debian12 Gateway | 同profile正式seq2/3/4更新；新版正常exit0、未确认owner/transport均0，同原测试Tunnel重开 |

已过三能力、安全及其它连接方向复用，未重跑完整矩阵；源码质量门24项和四目标producer均PASS。
最终插件在新版Gateway路由后单次Refresh恢复可用，Logo实见；无成功toast，不编造。
Windows首次Update在Host settle前置失败、没有写C07；原实例正常退出后新明确事务提交成功。
原官方卸载审批拒绝未派发，用户随后明确授权才执行；辅助Gate exit-code采样null如实保留，
未新增产品门槛。Root已将共享Gateway生命周期与客户端更新串行、App安装不等于Runtime切换
写入AGENTS，避免再由并行断连或仅看包版本误报完成。

KVM只读RCA以核显VFIO/MMIO映射竞态为主要假设，根因仍未证实；本轮未改动或重启宿主。
旧失败/Unknown不改写，新版正常退出证据单列；没有遗留本轮尚待操作的预览验收格。
**本轮预览交付完成；Stable仍NO-GO，须依既有Stable门槛另行明确核验放行。**

简短六领域结果、包/选择/安装/独立效果/卸载/恢复与原位恢复材料见
[最终结果](/home/sid/Developer/Artifacts/Styx/native-checks/startup-check-removal-20261112/final-source-9104/RESULT.md)；逐SHA原始证据索引见
[交付索引](/home/sid/Developer/Artifacts/Styx/native-checks/startup-check-removal-20261112/final-source-9104/final-delivery-index.json)。产品冻结后仅补交付文档，不把文档提交当成重编理由。

### 此前：NAB5已恢复，三台Host均在线（22:40 上海时间）

用户已完成Sid登录并授权继续。新鲜前置确认console1 Active、原C32包/Runtime/host-ready一致，
没有已有Styx实例；只通过原快捷方式启动一次，未重建、重装、重配或点击Reconnect。
实际新App8344/Core10308，GUI明确Connected；原device617c、fingerprint、grants/generation及
host-ready SHA `aadce0bbfb6d2cc971b3b5f2070c2fc44c699d7defdbfb5d956e8aea42c30ab8`保持。
独立账号list确认Linux1eb7、Windows617c、正式Mac6dd0均connected（旧Mac dev9623离线为保留历史）。
Windows独立新Exec session89实际exit0，本地38字节新文件精确匹配，
SHA `ee9973f909fd3a247de1810ecfba7e3190d3c31ff8387a0580d083459f2f1267`，mtime晚于新App/Core出生。
宿主仍连续运行30天；VM150 QMP running，重置后至22:39未再观察到kvm run failed。
**恢复已完成；原KVM Bad address的底层触发原因仍未确定，不把恢复当成根因修复。**
原始证据 `windows-postboot-effect-c32-01.json`，派生索引 `windows-postboot-c32-index.json`；
当前三Host状态已追加进 `final-independent-account-results.json`，旧离线/失败收据保留。
本轮功能与当前部署复通均收口；本次没有发布Stable或将其宣告GO。

### 此前：本轮功能验收收口；NAB5当时离线（22:20 上海时间）

| 设备/出口 | 已实际完成 | 当前状态 |
| --- | --- | --- |
| Linux C32 / de3 | 原profile更新、正常exit0、同身份重开、两轮独立新Exec | 同env `styx-1eb7f66a3e5c793eefe45b72` connected |
| Windows C32 / de3 | 原位安装、首次配对、三能力独立真实效果、7原进程正常exit0、同身份重开和新Exec | **历史验收PASS；当前IP10.0.8.146不可达、SSH No route to host、账号disconnected** |
| Mac C33 build1142 / 9104 | 真实默认配置启动修复、正常GUI角色退役/保留旧配置、正式默认首设/四字段批准、独立Exec与Computer完整树/截图、5原进程正常exit0、同profile重开和新Exec | 新正式env `styx-6dd0c1e6845ade63440fe4d0` connected |
| 独立验收插件 | 最终路由后已安装详情读取、单次Refresh tools完成回到可用、黑色圆形波纹Logo实见 | 生产Tunnel/plugin未改；未观察到成功toast，不编造刷新回执 |

Mac修复已集成在 `9104d6a84c69b89cb81537ef7aad26099ed870e4`，原项目/缓存/证书，
实际Runtime manifest `8e63174602aae9c3142a0d2479de19e7aea92755458cdcc8d6d6605d6cb664c7`。
原1141失败App已正常exit0；1142同位置更新后 `bootstrap_completed`，旧启动拒绝消失。
产品正常Change role将原profile/runtime-updates备份为 `.retired-20261112T135519Z`，
没有手工搬整个Library或清空身份；旧dev profile同样保留。
新请求 `29d56faaf10e45ed99d3f891ae661bb2` 只提交/批准/Claim各一次，
实际label仍为 `Corporate的MacBook Air`；AX字段曾读回PilotMac但提交模型未持久化该改名，未重放请求迁就名称。
首次独立Exec87实际exit0，Computer树22项完整且实际截图显示Host/Exec connected；
正常Quit后5个原进程由kqueue独立确认exit0（客户端因daemon退出断连，未用此断连推断退出）。
同profile重开App12052/Core12054，root/identity/pairing/ready逐字节不变；
独立Exec88实际exit0，新文件SHA `787e2ef52a2930afa85737a43155c2ad95a4657147e980f29cacc1a9319224ef`，时间晚于新进程。
Mac旧Browser/安全旅程及其它未受影响方向复用既有证据，不再扩矩阵。

当前唯一现场可用性缺口：UTC14:10只读核实NAB5单机不可达，同站网关10.0.8.1及Wenden10.0.8.12可达。
未能读到Windows进程/睡眠/锁屏/断连日志，**不能断言睡眠、关机或Styx故障**；
没有重连、重开、改OS电源/路由或重装。已询问用户设备电源状态，答复前不擅自唤醒。
NAB5恢复管理可达后只补当前同身份连接确认与必要新效果，不重跑已通过矩阵。

用户随后授权检查宿主10.0.8.12。22:23–22:26只读定位VM150（win）：
QEMU原始日志在**22:00:09上海时间**记录 `error: kvm run failed Bad address`；
标准QMP `query-status`实际为 `internal-error` / `running:false`。
PVE显示running只代表QEMU进程仍在，不能据此当Windows仍执行；Guest Agent无响应。
宿主无同期内核OOM/I/O错误，swap使用0，两个虚拟磁盘io-status均ok/失败读写flush均0，
thin pool数据88.15%、metadata4.08%。直接故障层已定位到VM执行异常停止，
**底层Bad address的具体触发原因尚未确定**，没有将其归因为Styx、睡眠或物理内存损坏。
未执行cont/resume/reset/stop、未重启宿主或改VM配置；原始诊断摘要在
`windows-host-vm150-diagnosis-20261112.json`。宿主PVE9.2.2、kernel7.0.2-6-pve、QEMU11.0.0-3。

后续恢复：用户先授权resume，22:28单次 `qm resume 150`明确exit255，QEMU返回
`Resetting the Virtual Machine is required`；未自动重试或擅自reset。
用户随后明确批准重置VM150。22:29单次 `qm reset 150`实际exit0，VM进入prelaunch；
针对该新状态执行一次resume实际exit0，QMP恢复running。
Windows实际boot为22:30:18上海时间，Guest Agent ping成功、SSH以Sid应答；
宿主仍连续运行30天、QEMU原PID3050124保持，无宿主重启/配置变更。
原host-ready SHA `aadce0bbfb6d2cc971b3b5f2070c2fc44c699d7defdbfb5d956e8aea42c30ab8`及device617c均不变。
22:32实际仅LogonUI/无Sid交互会话、无Explorer/Styx；**VM已恢复，Styx仍待用户登录Sid后正常启动**，不清配置代替恢复。
原始重置/后续resume及只读核对见 `windows-vm150-approved-reset-result-20261112.json`。

本机原始/派生证据均在既有 `native-checks/startup-check-removal-20261112/`：
`windows-c32-install-join-summary.json`、`windows-drift-readonly-20261112-1410Z.json`、
`linux-c32-normal-recovery-account-effect.json`、`mac-history-fix/MAC-FORMAL-ACCEPTANCE-INDEX.json`（25份原证据逐hash）、
`final-independent-account-results.json`、`final-plugin-detail-20261112.png`。
新9104基础质量门24项全PASS、input/git稳定；Mac真实配置纯观察1项PASS且343输入不变；
受影响Node检查及Windows原生私有创建7项PASS。未把已撤的复杂夹具FAIL或旧C31 exit4改写成通过。

| 领域 | 本轮结论 |
| --- | --- |
| Product | 三平台多余启动整包扫描已移除；正式Mac首设/恢复补齐；既有能力边界不变 |
| Architecture | Gateway/Host/Core、成熟执行器、安装更新签名及私有凭据边界保持 |
| Integration | 既有develop集成de3及9104；不新增worktree/项目/cache；未push |
| Release | Linux/Windows C32，Mac C33/build1142，各自精确源/签名/实际安装绑定；未宣称同一全平台新冻结包 |
| Reliability | 已过矩阵复用；真实启动、正常退出和独立效果闭合；NAB5当前整机离线单列 |
| Decision | 本轮功能验收完成，统一三Host当前在线仍待NAB5恢复确认；**Stable NO-GO** |

### 此前：Windows/Linux收口；仅继续Mac正式入口（21:30 上海时间）

用户再次要求避免验证实现偏离主线。已停止扩展新的Linux双角色验收夹具，保留实际失败原因，
不重跑Windows/Linux已通过矩阵；只完成Mac真实配置问题及正式App首设/恢复。

- **Windows C32原地安装、首次配对、三能力和正常恢复全部通过。** 安装器SHA
  `83ffc10b8cf6f81733c93e6a26acac6e0373ccf44f2cd453d2a65038a888b5a0`；原productId、D盘安装根及C31Host scope不变。
  GUI origin/CA匹配，新的单次请求 `76da316b1fb04b67b649e39e9fc0e3e6` 的四字段与服务器独立匹配后批准；
  device `styx-617c9ac5cbf57319ba54b753` 实际Connected。账号独立截图先读随机视觉标记，再核oracle；
  Computer一次设值/一次点击、本地变化1/点击1；Browser目标GET1；Exec session85实际exit0/新文件精确匹配。
  首次显式shell override被INVALID_ARGUMENT/uncertain=false拒绝，未派发；使用Host注册默认shell的新调用才实际执行。
  效果后原App/Core/worker共7进程正常exit0；新App2108/Core12080同身份重连，host-ready逐字节不变；
  恢复后账号session86实际exit0，本地33字节新文件SHA `9563a8738cc2ca590275317dad7fe6d503566054d04937b5a9e88c92f5a0b588`。
- **Linux C32同profile更新、正常退出/恢复和独立新Exec通过。** 详见下一检查点，不再重复三能力。
- Windows新打包目录继承Developer写权限的独立producer缺陷已修源码：Windows原子新建私有产物根；
  已有产物通过原Gate新建私有parent后仅复制数据，2168成员SHA保持，未重编Core/App或改旧目录ACL。
  新producer修复的Windows原生7项测试全部通过；Mac构建器同时允许复用原Swift cache。
- **Mac C32已正常退出旧dev App并在原位置安装正式App，但尚未完成正式启动/首设。**
  新App/Core及b9bc签名Runtime精确匹配；实际默认profile仍选旧1259 Runtime，启动返回
  `app_runtime_input_changed`。五条旧双角色更新历史精确属于仍保留的11月9日retired roots，
  被误送入当前profile的恢复协调器；并非配置字段不兼容，也没有证明恢复或重连。
  两旧root的原C07 reader证明14笔链完整、10条select精确Committed；旧desired Running保留为历史快照。
- 最小修正只把精确物理归属、完整C07闭合且无旧执行持有者的历史视为数据，不重放旧事务，
  普通当前/未完成历史仍按原规则处理；同一证明用于正常角色retire。没有整包扫描或新增产品开关。
  Root增量check/6项快速回归、Mac原cache/jobs10增量check通过；真实默认profile纯观察1项通过（0.69秒），
  343个受保护输入的inode/时间/内容前后完全不变。这不是GUI首设成绩；下一步只做必要的新Mac Core/App原位更新及实际入口。
  新Linux大夹具自身不一致及并行引用签名源的native_release_busy失败原样保留，未算PASS；新增大夹具已撤，
  原archive reference恢复原样，未以此新增验收矩阵。

Windows原始证据索引 `startup-check-removal-20261112/windows-c32-install-join-summary.json`；
恢复效果 `windows-recovery-effect-c32-01.json`；独立截图 `windows-account-post-effect.png`。
Mac证据在同目录 `macos-native-results/retired-existing-profile-test01.json` 等。
**仅Mac正式默认入口、首设及恢复尚未完成；Stable NO-GO。**

### 此前：原地更新与独立效果并行验收（20:37 上海时间）

用户要求直接并行执行，复用已通过且未受影响的证据，不要求本人逐项手动操作。
Root使用测试套件、原生构建/安装脚本、已授权SSH GUI自动化及独立验收账号工具推进。

- 修正已集成在 `de3df9246dedb9d26debda4318f28f8df7e78b14`；三平台正式Core及签名Runtime完成。
  workspace质量检查53项通过：45项原输入/日志SHA匹配复用，8项TLS测试因旧测试证书过期，
  仅更换测试PKI并重跑受影响项通过；生产CA、配对和签名身份未改。
- Linux原profile已通过正式seq2停止意图、seq3 Runtime选择、seq4运行意图更新到linux.32；
  新Host PID2808747/birth40812449实际connected，原device/profile及identity/credential/CA/seed字节不变。
  独立账号同environment `styx-1eb7f66a3e5c793eefe45b72` 新Exec session83实际exit0，
  本地独立核对47字节新效果文件SHA `d82488c16863e69d1b607b7cbf86c6a8a62dbd190f549c6661d044de385fc3d3`。
  旧C31进程stop实际exit4、远端transport drain历史汇总未确认，原失败收据完整保留。
  随后针对新.32进程独立执行一次正常stop实际exit0，再以原profile/answers重开，
  新Host PID2817126/birth40867823同身份connected；账号新Exec session84实际exit0，
  本地独立核52字节新效果SHA `12fd41143cb4d8c60e90fa5a02dccde2931a8aa5794eeb94d81c57ab859831ff`。
  **本版正常退出/恢复已通过；旧C31 exit4历史不被改写**，没有重放旧stop或增加profile。
- Windows正式Core使用原target/cache/jobs8，producer exit0，SHA `6027aaa1564ab29022c353611087a6ab58e38148f913ea7808596a6c7fce26b6`；
  新签名Runtime manifest `e3d06cd13db4072789ece1f5e4675e3387a806682472097da411a9dea76f83b7`。
  正在原项目组装相同productId/root/scope的App/Inno，**尚未证明安装、配对或三能力真实效果**。
- Mac正式Core、同原证书签封与签名Runtime完成，manifest `b9bc536e74a9668127adb46acfc4fa6c5f99d8ada91fff4ffe805e356a115d6f`。
  正式App构建器原先强制新Swift cache；现最小修正为复用现有owner缓存、icon renderer同缓存，
  受影响Node检查22通过/1原生平台skip。未变Swift/Core继续绑定de3，App另记实际builder SHA，不重复编译Rust。
  当前已运行App仍使用Developer devprofile；正式默认Library中存在旧Host历史，不能冒称空首设或正式恢复通过。
- Root在真实账号Chrome已安装详情核实验收插件、黑色圆形波纹Logo、Write21/Read14工具及三能力清单；
  Refresh tools仅点击一次并回到可用状态，没有观察到明确成功toast，不据此编造刷新回执。
  生产Tunnel/icon-check插件未改。账号工具已确认Linux及Mac环境库存；Windows仍未出现。

收据仍在同一 `native-checks/startup-check-removal-20261112/`：
`quality-tls-retry/receipt.json`、`linux-existing-host-update-result.json`、
`linux-independent-fresh-exec-effect.json`、`account-plugin-detail-and-linux-exec.json`。
**Windows原地App更新/首次配对/三能力/正常恢复，Mac正式默认入口及恢复仍待完成；Stable NO-GO。**

### 此前：移除多余运行期整包校验；保持原安装位置（20:03 上海时间）

用户明确否定未经要求的启动前全量校验和安装祖先ACL限制，要求Windows/Linux/macOS一起移除，
直接使用现有项目、依赖缓存、安装位置和配置原地更新，不再通过换目录重装或新建验收scope迁就实现。
此前建议的 `D:\StyxGuiAcceptanceC31` 搬迁方案已撤回。现有范围第58行原本即规定payload完整性只在安装/更新校验，
不在每次加载时校验；不能把旧实现的额外限制当成用户需求。

- 共享Rust新增安装元数据加载路径，普通启动/status/配对/恢复不再枚举整包资产。
  首次App Runtime拷贝按签名清单边拷边校验，不再额外扫描源和目标各一轮。
  显式安装/更新保留签名和完整包校验；系统代码签名、publisher pin、配对/TLS及私有凭据边界保留。
- Windows移除安装父目录的额外ACL要求；GUI启动改读已安装元数据。
  Mac同样改读已安装元数据，并移除显式重复扫描sealed resources，保留当前运行代码的原签名身份检查。
- 本机Rust增量check、workspace clippy `-D warnings`、格式检查及workspace测试通过；runtime 336项通过、71项既有显式参考忽略。
  初轮13项socket/loopback被执行沙箱拒绝，另1项旧测试仍要求cold load扫描普通资产；改为区分安装资产校验与运行入口身份后，
  在允许本机socket的环境重跑workspace全部通过。Linux新CLI读取原C31 Runtime实际exit0、0.587秒；
  新App Core隔离空容器status冒烟曾exit0，未启动Host/Gateway；用户随后要求不再新增该类隔离验收目录。
- Windows C#原生编译exit0、零警告；Rust原生check exit0。
  首轮命令漏带原显式target并仅用-j2，误入另一缓存子树触发依赖冷编；已精确结束本轮自有编译进程，未动产品进程。
  更正为原 `--target x86_64-pc-windows-msvc`、原cache、`-j8` 后仅重编runtime/CLI，186秒exit0。
  新CLI SHA `bca9195f9358bf456ecbf5178ed045d967eff78058de3628f1a1e433f177b3da`；
  对原安装payload及原ACL实际执行installed-selection exit0、stderr空、1.334秒，manifest及root身份匹配。
  这证明新代码的原目录读取通过，**不证明旧GUI已更新或配对通过**。原App300/Core10604及原包保持，未重放Request。
- Mac完整Swift closure原生typecheck exit0、4.78秒；原checkout共享Rust受影响check exit0、4.43秒，复用原cache、-j10。
  原aarch64 release缓存构建进行中；未签包、未安装或改默认Library。
- Windows源码发送曾被自动审批两次以缺少明确载荷/目标授权拒绝，均未派发；用户随后对精确25文件传输明确授权，
  SHA绑定同步及原生编译才实际发生。两次拒绝和已取消构建的收据保留，未改用旁路。
- 用户要求的后续规则已写入AGENTS和native-development技能，并记录长期偏好：按CPU/可用内存利用并行，
  保持target/profile/features/RUSTFLAGS命中原依赖缓存，不以保守jobs上限替代资源观察；不增加重复启动全包扫描。
  技能quick_validate和diff检查通过。

收据统一在 `/home/sid/Developer/Artifacts/Styx/native-checks/startup-check-removal-20261112/`；
Windows `windows-native-check-final.json`、`windows-installed-selection-native-03.json`；
Linux `linux-installed-selection-result.json`。Mac原机收据在原项目
`artifacts/startup-check-removal-20261112-mac-agent/`。
**源码及编译检查已通过的项目与已安装效果分开：匹配Runtime/App原地更新、Windows配对与真实三能力、
正常恢复、Mac正式默认Library剩余出口及最终Logo仍未完成。Stable NO-GO。**

### 先前：Root 直接 SSH 验收；旧C31 Runtime admission 阻塞（18:16 上海时间）

用户已选择 Root 直接 SSH 操作 NAB5，不再依赖对端 Codex；下面的 Codex 控制链段落仅保留历史，
不是当前交付前置条件。本轮没有修复 Codex、读取旧聊天日志或重新投递安装任务。

- 现有 `develop`/HEAD `2cb70c2` 及全部原未提交修改保留；无切分支、提交、worktree、App/Core 重编或重装。
  Root 新鲜核实 App300/Core10604 的原 birth、Session1、安装路径和 Core SHA `770e6ab9…52164b`。
  fixture8572/supervisor13772 仍为原实例，有效至 UTC16:03:22；随机视觉 oracle 未读。
- 原邀请在 UTC09:56:47.963 明确过期，未提交。服务器 CA DER 独立计算仍为 `0cb0c23b…334d9`，
  权威 pending 为空。只创建一份新的 600 秒邀请（`windows-c31-direct-join-02`），保留旧文件并私密递送新文件，
  不输出链接/token。两次参数校验拒绝发生在邀请创建前，不计作创建或配对重放。
- 通过 Sid/InteractiveToken/RunLevel0 的临时任务操作原 GUI。新 Review 的第一次前置以为旧输入仍存在，
  实际输入已被应用清空，故 `set_attempted=false/review_attempted=false/Request0`；新鲜观察后新 Review 实际各写入/点击一次。
  `obs07`（UTC10:06:34）确认 GUI origin/CA 正确，新邀请 expiry `1794478466765`。
- UTC10:07:18 对新鲜绑定的 `Approve Gateway and request to join` 仅点击一次。
  `request01` 只证明原生消息已递送；`obs08` 返回 **operation could not be confirmed**，不证明远端请求已提交。
  后续权威 pending 仍为空；没有可比较的四字段，故批准/Check confirmation/账号三能力效果均0。
  原 Request 保持 UNKNOWN、不自动重放。
- 只读诊断：同一已安装 Runtime 的 `release verify` 在 SSH 与 Sid 桌面 Session1 都返回
  **`native_release_payload_integrity` / exit2**。独立 Node 枚举核对签名清单2154项及两个清单/签名文件，
  实际2156文件，SHA/大小/成员全部匹配；签名 executable 标记也无差异。
  当前 `D:\Developer\Styx` 祖先 DACL 含三个额外 SID 的修改 ACE；Rust `open_installation` 会逐祖先调用
  `local_executable_acl`，其规则拒绝当前用户/System/Admin/TrustedInstaller 之外主体的修改权。
  该规则在冻结源码 `5618911` 至当前 HEAD 间未变。此 ACL 冲突是现有安装路径的确定阻塞条件；
  **没有证明这些 ACE 何时或由谁加入，也没有取得原 GUI RPC 的具体错误码**，不把独立验证诊断冒称原 RPC 收据。
- UTC10:14:40 本地 `profile`、`runtime-versions`、`app-join-input-v1.json` 均不存在；
  fixture 输入空/变化0/点击0/HTTP GET0，Exec目标文件不存在。原App/Core继续运行，未Quit/重开或改ACL/配置。
  本轮所有已完成交互任务均按精确名称回收，旧任务不动。未关闭 Windows 配对、三能力或恢复出口。
- Mac只读前置刷新：正式C31 DMG SHA仍为 `8435d4f2…c7`；默认 Library约3.0GiB，与Developer制品同卷，
  可用约579GiB；拟归档目标 `/Users/it-bootstrap/Developer/Styx/artifacts/c31-library-preserved-20261112` 不存在。
  已向用户请求本轮具体的正常Quit→完整保留归档→现成C31安装/默认Library首设/服务器配对/重开授权；
  答复前没有执行这些状态变化。

本轮收据/脚本：`/home/sid/Developer/Artifacts/Styx/native-checks/windows-c31-root-20261112/`，
其中 `request01-read-receipt.json`、`obs08-read-receipt.json`、`verifySession01-read-receipt.json`、
`runtime-inventory-receipt.json`、`runtime-acl-receipt.json`、`final-read-receipt.json`、`gateway-pending-final.json`
可独立核对。私密输入仍只在私有文件中，不进入 Git。

**下一出口**：Windows先解决当前安装路径的Runtime admission条件；本轮不改Codex ACL、不调整已有目录权限、
不重建/重装、不重放UNKNOWN。四字段批准、独立账号效果、同身份恢复均保持未通过。
已只读准备替代方案并请求本轮授权例外：正常GUI Quit并确认原进程退出，复用同一SHA匹配的C31安装器，
安装到不存在的 `D:\StyxGuiAcceptanceC31`，只创建新私有目录，保留旧安装及AppData/keys/pairing，
不改共享Developer祖先ACL。UTC10:17:51预检确认目标不存在，D盘可用137163280384字节；
详见 `install-route-preflight.json`。用户答复前不执行该方案；不把新安装许可解释为UNKNOWN Request重放许可。
Mac等上述本轮授权；最终账号路线和已安装Logo刷新仍未完成。**Stable NO-GO。**

### 较早的控制链与安装进展（历史）

当前先收口 Codex 控制链只读 RCA；用户已明确停止内部 IPC 桥适配，随后授权仅用 PilotMac 官方连接验证一次独立只读探针。
已确认原 SSH writer 释放、手机能通过原生 NAB5 设备入口打开原聊天；原 C31 指令不重发。
用户进一步确认 niuda 没有 Control other devices 页面；当前根客户端缺正式原生设备控制入口，
需要先验证受支持控制端的官方路径，不再维护内部桥。源码/Git 与 Styx Gateway 位置不变。
PilotMac 现有 SSH owner 没有官方原生聊天发现/发送工具，自动发送0次；随后本人从PilotMac官方设备入口向NAB5原聊天发送单次只读验证，Root已直接读取完成收据。nonce/chat UUID精确匹配，NAB5-WIN/cwd正确，执行进程2912→桌面app-server14116→ChatGPT11556均为Session1；官方入口真实执行PASS。本轮安装器/Styx操作均0；自动A2A目标暴露仍未通过，不用私有桥补齐。
原聊天报告旧C31因缺失旧code-mode host在工具执行前失败、未派发安装。Root新鲜只读观察没有Styx/安装器进程，C盘可用12956364800字节，不新增清理。本人已确认在同一官方原聊天接续保存任务，不重贴安装内容；截至14:54:25上海时间，固定项目尚无新验收JSON收据、无Styx/安装器进程，不能声称安装已开始。读取该聊天助手进度的操作被自动审批以私有日志敏感性/缺少明确授权拒绝；已停止日志路径，限定读取授权问题仍待本人答复，未改用IPC或重发任务。
14:57:08新鲜只读观察确认已有实际进展：精确C31安装器于14:56:24启动，PID16060（父11796）及Inno子进程16224均在Session1；原路径为`D:\Developer\Styx\artifacts\candidate-31\inno\StyxSetup-0.4.20261112.31.exe`。固定项目尚无新安装/READY收据，因此只记安装器已启动，不宣称安装完成。当前可继续靠产品进程与明确收据跟进，受限聊天日志读取不作为验收前置条件。
17:08–17:09 Root读取原任务精确结果收据及`candidate-31/windows-install-ready.json`，确认16:12:41已为READY_EMPTY_JOIN。最终安装器为`inno-selectable-private-root/StyxSetup-0.4.20261112.31.exe`，SHA `5a5f4b75068ee8d74b54f249f6c8004fb9427572ffd95100d48131cfa7725764`（127693698字节），父子实际退出0；正常Explorer启动一次，原App300/Core10604/console9576及新fixture8572/window2688484身份已记录。Root独立读取当前Core SHA与冻结C31的`770e6ab9…52164b`一致；三能力/Chrome、未配置提示及空Join通过，Request/Review/邀请输入均0，尚未选择并启动Host Runtime，不冒称账号可用。fixture到UTC16:03:22有效，零基线保留，Browser URL已获授权但未调用。
最终安装前原owner修复了可选D盘目录及缺失目录私有DACL创建：只新建目录，不修改已有父目录ACL；三项受影响原生场景通过。旧固定包取消/首次退出Unknown、第一份可选包安装后资格失败及原退出2分别保留，不重写为最终包成功。五文件源码租约已释放，Root按相同Git基线及逐文件SHA精确归入现有develop；`git diff --check`与JS语法检查通过，无App/Core重编。原有startup ownership测试的权限失败仍单列，未放宽权限。传输收据为`Developer/Artifacts/Styx/native-checks/windows-c31-final/installer-source-transfer-20261112.json`。
当前下一出口：服务器CA DER独立再核与既定`0cb0c23b…334d9`一致、权威pending为空。原owner配对阶段文件`D:\Developer\Styx\tasks\native-owner\C31-SERVER-JOIN-20261112-ROOT-NEXT.md`已新建；等原owner生成`C31-SERVER-JOIN-receiver.json`后才创建一次10分钟新邀请，私密递送，四字段独立核对批准，再做账号三类真实效果。自动跨聊天控制的核查已分到用户的新对话，不在此修私有桥。
用户随后明确改选由Root通过SSH分配此配对任务。Root经现有SFTP暂存传输调用公开`codex queue --thread 01a1bc09-6a26-7751-80d1-2e945120df79 --message …`一次，nonce=`NAB5-C31-SERVER-JOIN-20261112-01`，不带`--resume`、不创建server/聊天。命令实际退出1：`thread/queue/add failed: failed to read thread ... Access is denied (os error 5)`，失败发生在读取原聊天元数据阶段，未取得入队确认；原helper的`unknown_or_failed_no_auto_retry`原记录保留，不再次投递。此处是Windows拒绝访问，不是自动审批拒绝。未修改Codex ACL/锁/进程，私有IPC仍停用。原生GUI owner仍需从桌面接续已落地阶段文件；收到receiver READY前新邀请创建次数保持0。
用户随后明确授权在NAB5新开聊天。Root正式`list_projects`未返回NAB5目标，故使用官方`codex exec --approve-for-me --cd D:\Developer\Styx --skip-git-repo-check --json`新建一个独立CLI会话，不恢复旧thread。首次启动脚本仅在本轮新目录的SID类型构造处失败；只读确认目录空/所有者Sid后修正，无Codex进程启动的旧步骤未重放。第二次真实创建会话`01a1cf18-2ec5-7d33-a068-f42233350c02`；Root独立读到thread.started事件及PID1652/Session0。SSH启动回执40秒超时保留，但新任务已继续并产出完成结果，未重复启动。
新会话预检结果为`BLOCKED_DESKTOP_CONTEXT`（`tasks/native-owner/C31-NEW-OWNER-20261112-01-result.json`）：两次本地Exec和Node均报连接runner pipe-in 15000ms超时，正式CUA getState Node启动失败，没有取得Session1 Styx观察。Styx账号库存仍只有Linux/Mac，尚无Windows。新agent无法自行读取thread/PID/session，报告保留null，Root外部观察的UUID/PID/Session0不回填为agent自证。配对READY/Request/fixture操作均0，未读取或修改旧聊天、未安装/退出产品、未改服务/配置/沙箱；不能把新CLI会话创建成功当原生GUI接手成功。具体runner超时原因尚未证明，控制问题仍在独立对话处理。
故障归属、官方连接模型及下一验证出口见 [控制链 RCA](CODEX-CONTROL-RCA-20261112.md)。
RCA 尚未证明 OpenAI 产品缺陷，也不放弃任何 Styx 正式安装/真机验收门槛。

以下补充本轮实际变化；后面的 C30 验收矩阵保留，尚未通过的格不因开发检查通过而关闭。

| 出口 | 当前证据 | 下一动作 |
| --- | --- | --- |
| 固定项目指导 | 指导引入于 `997ad83`；Mac/Windows 父项目 AGENTS 薄入口与 Skills 发现链接均有 READY 收据；两端持续 source 已核实干净同步至 `2cb70c2`，缓存/配置不动 | 按需使用指导，不再每次加载历史或新建项目/聊天；旧构建收据不改写 |
| Windows staging 归拢 | 四祖先限定 ACL 完成；4326 文件复制/哈希一致，新树权限验证通过，正式 C30 reader 实际 exit0；新 Developer staging 指针已启用，旧树保留 | 此项收口，不再审计或复制一次 |
| Mac 真实开发入口 | 固定 dev profile 已集成；全新Gateway、三能力、Sheet拒绝与同worker恢复、Windows Gateway→Mac及双方恢复通过；本轮服务器→Mac经四字段批准，三能力真实效果独立核对PASS | 保持服务器Host连接；开发结果不冒称正式App/默认Library验收，不重跑旧完整旅程 |
| Mac 正式包 | 复用 `5618911` Core/完整 Runtime；正式 App 编译29秒、原钥匙串签封/DMG51秒PASS；Root匹配DMG/收据SHA。旧Library与备份同卷、空间约580GiB、归档目标不存在的只读前置已就绪 | 本机原聊天已发一次完整阶段确认：旧Library原样保留归档、现成正式App安装/首次设置/服务器配对/正常重开；本人答复前未Quit/归档/安装 |
| 四平台冻结制品 | Core同源 `5618911`；Mac/Linux/Windows/Debian12 Runtime原签与独立验签通过；Windows App及最终可选私有目录Inno已完成安装，App/Core未重编 | 完成剩余真机/最终App安装验收，不能将制品通过计为交付完成 |
| moedeu-apps集中Gateway | C31正式安装、首次setup、严格LAN TLS、测试Tunnel及同profile正常退出恢复通过；Linux及Mac均connected并有三能力独立效果；旧服务保持 | 等Windows及Mac正式App最终路线，最后刷新Custom MCP详情/Logo |
| Linux最终路线 | 最新C31已正式独立安装；服务器→Linux三能力独立效果、同profile Host恢复、旧token无效果、Gateway恢复后新Exec均通过 | 保持连接，复用已通过场景 |
| NAB5桌面与清理 | 最终C31已安装，App300/Core10604仍为原实例。Root直接SSH完成新Review并单次Request；GUI结果未确认、pending空。现有Runtime只读verify报integrity/exit2；字节匹配但安装祖先存在不受信主体修改ACL，见最新检查点 | 先闭合Runtime admission阻塞；UNKNOWN不重放、不调整Codex ACL或重装。之后才能四字段批准、三类账号效果及同profile恢复 |

Mac 新 dev Gateway 通过实际 GUI createLocal/tunnelSave 各一次，三能力/自动 LAN/系统权限
已核对；独立验收 MCP 实际列出 `styx-7c7a313ee112506335705652` connected。
冷账号 Exec 文件30B已独立读回；Browser nonce页面/快照和关闭完成；Computer完整AX树、
实际PNG、输入/提交成功。无害Sheet66182的单次读取明确not_dispatched/uncertain:false，
同上下文后续主窗读取成功；旧消费token负控同样明确未派发且原输入保持。
fixture为29600/66165，真实5小时TTL，不因便利偏好再编译夹具。
正常Quit后原6个产品进程（含SDK worker30288）均由原观察器记录实际exit0；
同一App/同一dev profile现已观察到恢复：新App31657/Core31662、同设备身份自动连接，
Root实际新Exec文件34B/精确SHA、Browser第二次nonce GET200/正常关闭、Computer新树及PNG均通过；
重开前旧token写入负控明确not_dispatched，独立fixture输入/提交仍各1、Sheet开关各1。
原退出后新App的启动来源未证明，且未带诊断参数，故仅关闭功能恢复出口，不冒称受控单次启动通过。
Root原始账号收据见 `native-checks/macos-development-entry-20261112/account-recovery-results.json`；
独立效果计数/原进程退出收据随原owner归档。
开发配置结果不能回填原 C30 同配置 P3 恢复 FAIL。旧 App/配置/keys 保留。
为满足现有 Runtime 组装器的精确 Git HEAD 要求，使用过一次记录租约的冻结组装工作树；
无源码修改或编译，签包完成后已清退并保存 HEAD ref，当前集成 checkout/缓存不变。
Windows 原 App/Core 本轮新鲜核实已不存在、22022 无监听，原退出原因未知；
当时只有Session0 SSH app-server，无可用Sid console桌面/原生Computer Use pipe，产品启动0次。
Session0的新fixture不算交互GUI READY。用户仅能使用Moonlight，Sunshine已正常重启一次；
显示捕获仍失败。仅启用既有微软兼容签名的Virtual Desktop Monitor（Code22→0），
并备份后把Sunshine过期output_name改为其本次自身枚举的显示器GUID；正常服务重启后仍有
DuplicateOutput 0x80070005，不能称Moonlight恢复。未改另一未签名虚拟驱动、Intel、配对、
安全策略或重启电脑；客户端复测待用户结果，GUI验收单独挂起。
为继续缺失方向，原owner复用已安装C30正式CLI及原Runtime建立独立Gateway-only profile；
首次run因bootstrap默认desired=stopped明确失败，正式plan/apply提交running后run实际监听。
Core6436在127.0.0.1及10.0.8.146:22022就绪；Root从公有CA独立核对canonical DER指纹
`60584d3d358120f6d6bdd817309e80607c117403959e29075afecade37ead1e6`、TLS1.3/证书链/IP通过。
此为无桌面Gateway参考，不替代Windows GUI。Mac正式GUI退役已返回空Join，原Tunnel/Exec/SDK
均实际退出0，App/Core不变；Windows Gateway正常退出0、所有drain确认后配置独立测试Tunnel并重开。
新邀请经私密文件递送，Mac正式GUI发起1次请求；Root核对双方request/device/fingerprint/code
四字段完全一致，Windows正式approve1实际exit0/approved/operations_replayed=false。
账号新Mac身份 `styx-3bb05b295ecae5f583257489` 已connected；本方向三类真实效果独立读回PASS：
Exec42B/SHA `a1e40f732e2c8589a0f84d84b4311685d39c63d58afc990b1f7e9af5ce013d87`，
Browser本轮目标GET1/200，Computer变化/提交本轮各1且原视觉标记匹配，负控保持无效果。
随后Mac Host正常Quit1，原5进程actualexit0，退出后未调用CUA；同App/profile显式带诊断启动1，
同Gateway/identity/三能力自动恢复、Reconnect0，新App38702/Core38705/SDK39024。
恢复后新Exec46B/SHA `d12ee7c8f5589badde71da22252fed28aa83b039f679395dffe2dd464d2ba44d`
及完整新AX读取通过，独立fixture计数保持2/2、HTTP累计3。此处受控启动已明确，不改写早先
Gateway恢复启动来源未证明或原C30失败。账号原始效果见 `native-checks/windows-mac-route-20261112`。
Mac固定Python的TCP探测errno65保留；正常系统curl严格证书校验0，SSH子进程严格TLS也通过，
不归因为Gateway证书失败，也不以更改网络权限解决执行上下文差异。
Windows Gateway随后原PTY正常退出，原Core/Tunnel/console actual退出分别0/1/1，Gateway四项drain
确认、未确认数0；同profile重开为Core896/Tunnel2600，同CA/原配对保留，Mac自动连回。
Root新Exec42B及独立读回SHA `be935b6f398ad3bba1859700b68e40656c6594ce3bdfa27a22135ef849981806` 通过。
Windows C31 Core原机一次编译PASS（235秒），Debian12 Core一次离线编译PASS（75秒）；
两端固定缓存/原release-only屏障和timings均保留。四平台C31 Runtime均prepare/sign/finalize通过，
原publisher公钥及独立OpenSSL验签均通过，汇总为 `candidate-31/four-runtime-result.json`。
冻结组装临时工作树干净清退，canonical develop不变。Windows原清理批次及限定到737文件/空目录
的清理均在CreateProcess之前被原端自动审核以 `blocked by policy` 拒绝；本人在Root主聊明确批准后，
Root正常审批接受同一限定动作，逐项核737原hash/no-reparse/单链接后删除737文件及96空目录，
持续source/原tar/gate/Core收据保留，无ACL改动；原端三次拒绝保留。
Linux工作站和moedeu-apps已用正式CLI独立verify/install C31通过，后续实际验收如下；
旧默认入口/旧服务状态保留，服务器旧测试入口已可恢复归档。
moedeu-apps C31已完成一次正式首次Gateway setup并以原监督器前台持有：Core2941095/birth92844536，
127.0.0.1与10.0.38.8:22027监听，tunnel_ready；原Windows测试组已正常全退，旧服务器服务不改。
公有CA DER `0cb0c23b33c673deb292c6ad088d75483ef47269ed38e7b96132c41c55d334d9`，Root严格TLS1.3/链/IP通过。
Linux C31新Host `styx-1eb7f66a3e5c793eefe45b72` 经双端四字段核对、正式approve/claim连接成功；
服务器账号三能力独立效果PASS：Exec39B/SHA `ad5ef75d6611899c4313e922cc0078a559d247ea51aba5035c2c272e6c7fce14`，
Browser nonce GET1/200且正常关闭，Computer真实PNG随机视觉与独立oracle匹配，input/result一致、变化/点击各1。
一次过期观察写入明确not_dispatched/uncertain:false，刷新观察后正常效果成功；原拒绝不改写。
Linux同profile正常退出/恢复已PASS：原Host actualexit0、原workers/unit gone；同root重开跳过已完成配对，
新Host2444237/start37237656 connected。旧Host token在新观察前明确not_dispatched/uncertain:false，
新Exec43B/SHA `5157f68ff9fe5ee7343044d8934ee65c7717dcbc72e1b2c8928b9bfff6ad2b1f` 与fresh树独立通过，
fixture变化/点击保持1/1；remote drain枚举未单独输出，不据exit0宣称更强的远端Complete。
Mac角色退役碰到 `app_cleanup_unknown`，本机Exec/SDK已退，
按产品要求正常Quit（原3进程actualexit0）并显式重开后继续fresh角色变更；不重放旧操作或删除配置。
服务器Gateway也已正常恢复：原2941095 actualexit0、测试payload进程与22027监听全退；
同profile显式重开为2954416/birth92942814，Gateway/Tunnel ready、同CA、Linux自动连回。
Root新Exec46B/SHA `26528bff70b0cb737e2d21cd263f2b0c54e169751a5588bc25491f9cee32858f` 独立读回PASS。
Mac新角色确认“继续”被自动审批明确拒绝（按钮未派发）；本人随后在Root主聊明确确认本次角色变更及服务器配对，原端审批仍拒绝跨聊天转交确认，Continue实际派发0次，待本人在当前对话框单击；
Windows C31 App/Inno已生成且未安装/启动，Sid交互桌面/Moonlight仍未恢复。
后续只读发现同SID已认证的Sid/Session2 Disconnected及Explorer/Codex GUI；一次标准tscon actualexit0，
Session2现为console Active/UNLOCKED，Sunshine worker自动迁移，服务未额外重启，但捕获仍0x80070005。
现有原生队列只读探针实际仍由SSH7368/Session0消费，非GUI17108/14952/Session2；不能把队列成功称GUI恢复。
原SSH owner还持有的两个旧Session0测试fixture后台已经既有normal-close接口正常退出，两原PTY actualexit0，
未终止Codex或改pipe/client身份；继续尝试正常原聊天上下文交接。
Mac正式App编译29.091秒后，仅对现成prepared签封，实际51.016秒/exit0，原钥匙串解锁1次；
DMG SHA `8435d4f2d652bc8684b58e3965aeffc5bb169321d65104f738f723b4a7f753c7`，
原收据SHA `edb9c580129413c7184f66ce55d1b5fe931a0b131cb0ea5d2ae6a433cd79596c`，Root已取回并独立匹配。
Windows安装器SHA `255368f859bc6cddc394ffd22650c086aac46635359ff06ca097934924c145f4`，127692872B。
Linux原验收前台通过原监督器正常Ctrl-C退出，实际exit4且Tunnel/主进程已消失；
保留setup_host_cleanup_unconfirmed，不冒称exit0。只读审阅定位本机清理已settled，
远端drain仍Unknown/Unsupported，具体子类未保留，不能归因于泛化watch_stream_ended。
上述为开发/平台参考证据；统一最终版本与剩余矩阵仍未闭合，Stable NO-GO。

## C30 验收检查点（2026-11-12；后续旧检查点为历史）

冻结运行时源码为 `dce8d24d599924c88e0f177fbfb92cf07ff7fd58`，证据根为
`/home/sid/Developer/Artifacts/Styx/20261107-gui-convergence/candidate-30`。
开发工具归拢的工作区修改不改变这个已安装候选，不为目录整理重新生产候选。

| 工作流 | 已验证 | 仍缺的出口 |
| --- | --- | --- |
| 生产与安装 | C30 集成质量、三端 Core/完整 Runtime、Mac App/DMG、Windows 安装器及精确安装已有收据 | 制品通过与真机验收分开，不能据此宣布交付完成 |
| Linux Gateway → Windows Host | C30 拒绝/批准、三类独立效果、Host及Gateway正常恢复、撤销负控与新身份重配效果已闭合 | 保留原退出非零与负控 `offline/uncertain:false` 原文，不改写成所有进程 exit0 或更强的 revoked 错误分类 |
| Linux Gateway → Mac Host | C30 拒绝客户端确认、新身份批准及三类独立效果通过；P3 原13个产品进程正常 Quit 全部实际 exit0 | 单次重开后 bootstrap_failed、Core 未存活、账号 disconnected，恢复 FAIL；同 worker Sheet 读取边界仍待闭合 |
| Windows Gateway → Mac Host | C28 的 Windows Gateway 本机三能力及 Linux 连接旅程保留；C30 本地 Gateway 就绪，人工防火墙 Allow 后原 owner 核对监听/精确规则，Linux 独立 TCP/TLS1.3、公有 CA DER 指纹、证书链与 IP 核对通过 | Mac Core 恢复阻塞该方向真实配对/最小工具效果；网络就绪不是账号工具连接 |
| Mac Gateway 首次设置 | C27 的 Mac Gateway 三端 Host 历史成绩保留 | 全新设置入口未完成，不能由保留旧配置的成绩替代 |
| moedeu-apps 日常部署 | C30 Debian12 包兼容/验签/独立安装、私有测试输入已准备 | 新 C30 Gateway 未设置或启动；旧服务未替换，三端最终接入和恢复未验收 |
| Custom MCP | C30 已执行工具刷新与安装详情重新加载，黑色圆形波纹 Logo 可见 | 最终 Gateway 切换完成后再确认一次最终详情和实际工具路由 |

当前顺序固定为：

1. 完成用户本轮要求的三端持续目录、入口、缓存归拢；受保护密钥和活引用例外单列，
   不因目录整理重新构建或重装。记录见 `Developer/Artifacts/Styx/workspace-consolidation-20261111`。
   已收口的平台可并行恢复既定验收；私钥/活引用和 Windows staging 祖先 ACL 例外单列，不擅改祖先权限。
2. Mac 原 owner 收口当前 Host 恢复/读取边界；Windows 原 owner 关闭其 Gateway→Mac 的缺失方向。
   用同一项目、同一原聊天，仅补缺失边界，不重新跑 Windows 已通过的完整旅程。
3. Mac 原 owner 补全新 Gateway 设置；复用已有合同/能力证据，仅对新设置与路由做实际核对。
4. 正常收口独立测试 Tunnel 后切到 moedeu-apps 新 Gateway，接入三台 Host，验证每端最小
   真实效果及连接恢复，刷新最终插件详情，按最终证据决定发布。生产 Tunnel 和旧服务器服务不动。

Mac P3 的失败收据在 `mac-host-p3/`：新 App91645 存活，当前已知启动路径均存在且没有
指向归档 Documents，不能据此归因于路径迁移。一次只读采样主线程在正常 AppKit 事件等待，
不能宣称死锁。现有 Swift 客户端丢弃 Core stderr，未保留原始退出事实；原错误无法事后恢复。
有界源码草稿仅增加 opt-in 闭合错误码、原 child PID 和实际 wait 后退出状态，保持持续排空、
超时、EOF和无重试语义；先做原机 check-only/隔离 self-test，再决定受控参考与必要修复。
诊断草稿不是根因修复，更不是 C30 已安装行为。不会为目录整理启动新候选生产。

隔离真实文件系统参考已复现另一项确定缺陷：完成双角色 runtime update 后，正式角色退役
没有同时退役 `runtime-updates`，同容器的新 Host 身份会被旧记录以 `app_runtime_input_changed`
拒绝。原双角色 cold-open 和干净父容器为对照；这不是原 Mac P3 根因证明。
源码修复已实现且仅面向新的正式退役：完整准备集合、持久 begin/done、部分失败继续封锁；
不追认旧 UNKNOWN，不迁移或清除现有设备配置。有效完成后允许正常归档清理。
原签双角色参考通过（166.55秒）；新增 begin 后根变化负控验证当次 Unknown 与重开封锁。
独立审阅发现的 begin 后错误分类已修正并复核。该长参考早于随后 Windows 只读 snapshot
句柄释放及测试夹具适配，未保留当次完整源码哈希，不能冒称最终哈希已执行该参考。
Mac 原机增量编译与5项 FS/history 测试、Windows 原机增量编译与4项 FS/history 测试通过。
Mac 首次测试因系统 `/var` 符号链接被拒绝；改用固定项目内物理 TMPDIR 后通过，原失败保留。
Windows check 42.219秒、首次测试含依赖编译214.406秒，实际场景0.44秒；两端均4 jobs、复用固定缓存。
收据在 `/home/sid/Developer/Artifacts/Styx/native-checks/role-retire/20261112`。
其后根集成仅按 Clippy 建议改3处等价闭包，affected-crate strict Clippy 已通过；当前进入一次集成质量检查。
通过后再冻结统一候选，不逐补丁生产。已安装 C30 与原 Mac P3 FAIL 均不改变。

`25d26c9` 将 Host 命令通道 Closed 从 Busy 修正为 Offline，真实 bounded-mpsc 满队列、
关闭及丢回复三个场景通过；此项没有部署，也尚不能归因用户未提供原始字段的 capacity busy。
`35bd5ba` 的 Mac opt-in 启动诊断通过原机 check-only 与隔离 self-test，同样未安装。
Windows 防火墙后的独立网络收据为 `windows-gateway-firewall/root-lan-tls-probe.json`。

Product：三能力已有实际效果，Mac 恢复出现明确失败；启动历史缺陷源码修复已通过变更场景，未部署。Architecture：Rust 边界不变。
Integration：开发入口/缓存、闭合诊断及通道分类修正已提交，角色退役修复进入集成；保留源码清单/签名屏障，仅在此检查点跑一次集成质量。
Release：C30 冻结制品不变，无新候选。Reliability：UNKNOWN、非零退出及目录权限失败原记录保留。
Decision：先完成已授权归拢，再继续上述缺口；Stable NO-GO。

账号效果证据位于 `account-linux-gateway/`；服务器准备证据位于
`server-debian12/target-{install,private-input}-dispatch.json`；Logo 证据位于
`plugin-final-refresh/receipt.json`。这些路径均相对于上面的 C30 证据根。

## 当前关键路径补正（2026-11-11，C29实际角色验收后）

- Linux C29 正式安装、旧Hub本地过期尝试退役及新固定Hub单次完整setup通过；账号
  Exec41B/精确SHA、Browser nonce GET1、Computer独立随机视觉和input/result/各1次变化点击均通过。
- Windows C28 Host首次Runtime准备已完成，一次GUI Request正常返回awaiting_approval，
  原回复与Linux唯一pending四字段已逐值匹配；之前空pending只是一张更早的快照。
- **当前产品阻塞是 Linux 正式 CLI 没有 `gateway reject`，不是缺用户授权。**
  底层已有精确RejectionSelection/Action::Reject、严格TLS/C07/reader7和无重放路径；
  已补公开CLI到现有路径接线及公开surface回归，不新建拒绝协议、权限或事务。
  增量检查、参数/admin及TLS正负控通过；新debug CLI在原pending有效期内精确拒绝一次、
  actualexit0/rejected/no replay，仅计开发参考，不冒称新候选安装验收。
- 本入口本应在候选生产前核实；本轮安排遗漏已纠正。C29原Core/Runtime成功收据不改标，
  Mac/Windows App生产在已开始工作的确定收口点暂缓；接线参考已通过，集成检查后统一冻结下一候选。
  不为未收敛的每项修改再次生产全平台，不冒称修改已安装生效。
- Windows客户端唯一Check发生在原pending期限之后，结果未确认且零效果；服务端拒绝
  另计PASS，客户端不算终结通过，不重放Check或放宽时效。Root调度时机不足单独记录；
  按正式正常退出/生命周期收口后再开新尝试。Mac原聊天授权边界单独挂起。
- C29 Mac/Windows Core及Runtime签名验证、Debian12 Gateway-only包与离线正式验证已通过；
  Mac App准备曾因private_directory_permissions明确exit2，全树新输入权限/ACL归因与收紧已完成，原CLI正式只读verify通过，无App/DMG产出。
  这些是制品/参考事实，不是已安装最终候选或服务器部署。Stable NO-GO。

## 当前推进检查点（2026-11-11）

以下为最新状态，后文日期较早的检查点保留为历史。

| 工作流 | 已验证变化 | 下一出口 |
| --- | --- | --- |
| Windows Gateway | C28 本机三能力、Linux 拒绝/批准/撤销/重配对和正常恢复已有真实证据；本轮正常退出后又从原入口恢复，账号实际列出 b939 connected | 保留原配置与通过证据；配合 Linux Gateway 的远端 Host 验收 |
| Linux Gateway | 首次实际 Hub 的分阶段同根恢复触发 `native_gateway_pending_binding_mismatch`；重开换叶证书，旧 pending 严格绑定旧叶，批准/claim/Host 均未派发 | 新签名候选仅恢复这个已知失败的本地尝试，再完成本机及 Windows 远端能力与正常恢复 |
| Mac | 原 owner 仍停在授权边界；两次过期邀请均未提交请求 | 只接受原聊天可用的本人授权，不改用其他通道绕过；此阻塞不阻止 Linux 独立推进 |
| 发布与日常部署 | C28 Debian 12 包仅完成原机兼容/验签，未替换服务器；最终 Logo 刷新未完成 | 角色缺口关闭后统一发布检查，再部署 moedeu-apps Gateway + 三端 Host |

本次有界修复保留严格 TLS 身份绑定，增加 **POSIX 上明确退役未完成 Hub 本地 Join**：
核对精确请求/身份/上下文并持有原写锁；未过期走已有拒绝事务，过期只持久推进可信时间下界，
不伪造拒绝或全局清理；只归档本次本地 Host/attempt，保留 Hub、Gateway、CA、Runtime 和其他设备。
Windows 对这条新增 Hub 退役路径明确拒绝，原 Join 退役行为不变；不宣称通用跨平台恢复已完成。

- Product：真实 Linux 首设恢复缺陷已复现；修复尚未安装。
- Architecture：沿用原 Core/Runtime/CLI 边界与严格证书检查，无新管理权威或持久服务。
- Integration：实际签名 reader7 的同根退役→新身份→连接、旧绑定拒绝以及过期保留参考均 PASS；
  独立写锁交接审阅已闭合；本次集成 quality2 的 53 项 PASS，输入稳定。
- Release：尚无新 release 编译、签名、安装；下一步冻结单一新源码候选，复用各端缓存。
- Reliability：保留 C28 原失败、退出 UNKNOWN 及质量首轮两个 lint FAIL；禁止重放旧请求。
- Decision：Linux 路径独立推进，Mac 授权单独挂起；已有通过项目不全量重跑。Stable NO-GO。

证据根：`/home/sid/Developer/Artifacts/Styx/20261111-hub-resume-recovery`；
原 C28 真实账号/平台证据：`/home/sid/Developer/Artifacts/Styx/20261107-gui-convergence/candidate-28`。

## 当前推进检查点（2026-11-10，新候选检查前）

- **Product**：C27 Windows Gateway 的实际账号路由及本机三能力已独立通过；Exec
  36字节精确文件、Browser HTTP1、Computer输入1/点击1且像素与随机独立oracle匹配。
  Linux P1的唯一GUI Yes出现工具缓存错误，保留UNKNOWN；随后单次正式claim仍为
  awaiting_approval，已过期，不能称拒绝通过。Mac Join明确未发送，原失败保留。
- **Architecture**：Rust仍是唯一管理权威。CLI同根Join退休增加容器互斥和持久
  begin/done栅栏，保留旧Host/本次输入及未知历史，Runtime selection/publisher/其他
  角色不动；未完成归档不得被setup当fresh。不增加服务、JS权威或自动重放。
- **Integration**：上述CLI切片本地严格TLS/签名合成reader7场景实际走正式
  `setup::pair`，验证明确拒绝、同根退休、新邀请的新身份/请求、批准并ready；
  并发/碰撞/不完整journal及原有丢回复不重放通过，独立源码复核无阻断项。
  不是完整setup::run、断电、平台或真实账号验收。
- **Release**：Mac原owner已检查功能行显示、换行、LAN用途说明、固定错误码和指导；
  生产/测试类型检查、隔离self-test、plist lint通过。Windows原owner已检查设置页
  Quit复用原退出逻辑及公开配对指纹，两次编译和QuitLifecycle idle/active/busy通过。
  尚未打包或安装；源码收敛后只跑一次候选质量检查，再统一冻结新候选。
- **Reliability**：Mac SSH严格TLS通过、Windows现用程序防火墙已有Allow，均不能
  证明Styx桌面App的Local Network权限；系统列表中无Styx项，原因未证。当前旧包
  缺LAN用途说明，下一包补齐；不改系统授权、不把假设当根因。原UNKNOWN/FAIL均保留。
- **Decision**：继续原测试顺序；已有成绩复用，当前修复均需新候选受影响真机复核。
  不为工具错误重放旧Yes，不换目录掩盖CLI重配对缺口，不操作生产Tunnel。

> 本地测试执行更新（用户，2026-11-10）：当前先完善本地测试，不依赖或改造
> GitHub Actions，后续稳定发版时再复用本地入口接 CI。新增明确的
> `test:unit -- --package …`、`test:contracts`、`test:integration` 入口；保留原 JS
> 套件兼容性并明确其不等于 Rust 检查。真实固定拒绝客户端的合法 TLS 请求快正控
> 与原负控、schema 投影/等价共4项通过，5项编排失败/零测试行为检查通过；增量
> `cargo check -p styx-runtime`、fmt 与 diff 检查通过。未重跑全 quality、未打包，
> 当前已装 C27 不变。具体命令和覆盖边界见 [本地质量说明](../quality-gates.md)。
> Windows Gateway 已正式创建并监听 10.0.8.146:22022，本机 Host b939b…实际就绪；
> Mac 正常角色退休完成，旧 Tunnel 实际退出0，当前停在空 Join。Windows 原 owner
> 一次 Save and connect 后为 configured/ready；独立账号 list 已实际只返回 connected
> NAB5-WIN / styx-b939b24a32d1744997cc9122，证明账号切到了 Windows Gateway。
> 远端加入及该 Gateway 三能力/生命周期仍未覆盖。此前失败、raw signal9 留存。
> Mac 原生 owner 实看 Settings 仅 CLI，C27/build1136 哈希正确；源码因缺少选择记录
> 隐藏 Browser/Computer。有界显示修复通过生产/测试两次原生类型检查、隔离编译、
> self-test 与实际 SwiftUI 三状态可见性回归；Root 已实看未配置导出图。首次截图套件
> 因隔离程序缺少随包图标失败，保留该记录；补齐既有资源后一次运行退出0、11.631s。
> 随后窄窗文本换行修正也通过一次隔离编译/渲染回归（8.571s/12.549s、退出0），
> 原 owner 实看三状态无省略截断，源码租约已释放。
> 未重建发布包、未安装。用户已撤回过时的手动完整配置归档/重置授权，不得执行。

## 当前产品范围与证据缺口（用户澄清，2026-11-10）

最终目标是兑现既有承诺的成熟产品：macOS、Windows、Linux 均保留 Gateway 与 Host
能力以及受支持的跨平台连接。用户日常选择 moedeu-apps 集中做 Gateway、电脑做 Host，
只是适合其网络环境的部署方式，不是缩减产品能力或验收责任。撤回此前“无需补
Windows/Linux Gateway、只差 Gateway 对齐”的判断。

C27 当前端到端证据如下；“未覆盖”不等于源码未实现，也不能写成通过：

| Gateway 所在平台 → Host 所在平台 | macOS Host | Windows Host | Linux Host |
| --- | --- | --- | --- |
| macOS Gateway | 已验证本机三能力及恢复；全新 profile 首设未覆盖 | 已验证配对/三能力/恢复/撤销重配对 | 已验证三能力/负控/恢复 |
| Windows Gateway | Join明确未发送，未通过 | 本机三能力/独立路由已通过；恢复/安全旅程未闭合 | 一次请求等待批准，GUI拒绝UNKNOWN，未通过 |
| Linux Gateway | 本候选未覆盖 | 本候选未覆盖 | 本候选未覆盖 |

后续先核对未覆盖角色的已有实现和精确参考证据，再由原平台 owner 通过正常产品
入口补齐 Gateway 创建、至少一个真实远端 Host 加入、身份批准/拒绝、实际工具路由、
停止重开及恢复等平台主路径。其余连接方向只补该方向所缺的连接/协议边界与最小
实际效果，不为每个格子重复全部三能力、安装、P1–P4和旧已通过场景。
发现实际缺陷才有界修复，必要时产生新候选；文档、参考或历史成绩不能冒充实机通过。
原平台 owner 继续占有设备 GUI，共享源码只在唯一 develop 集成；先核实各自状态，
不为换角色擅自清空现有 profile、改生产入口或重放未知操作。

moedeu-apps 的最终日常部署单独收口，不能替代上述产品角色矩阵。此前暂缓 Mac
全新 profile 场景只记未测，不视为对三平台 Gateway 能力的豁免。持久服务、自动更新、
legacy 迁移等既有延期项不因“成熟产品”字样自动变成新功能任务；范围变化单独记录。

本次六领域变化：Product 恢复完整承诺范围；Architecture 无变更；Integration 仅纠正
计划与交接；Release 无新构建/安装；Reliability 新列未覆盖角色与连接方向、保留既有
失败及 UNKNOWN；Decision 产品能力收敛与个人部署分开，交付未完成、Stable NO-GO。

## 下一轮具体顺序与测试深度（2026-11-10）

按 Gateway 平台集中跑，不按工具或每对电脑分别重建环境。执行顺序是
**只读就绪 → Windows Gateway → Linux Gateway → Mac 剩余缺口 → 发布检查 → 日常部署**。
Windows 有已知退出控制拒绝，先闭合其原生角色/生命周期风险，避免先完成其他平台
后才发现共享修复需要再产候选。Linux 随后提供服务器平台的 Gateway 证据；Mac
保留已通过的 Gateway 行，只补首次设置及安全入口等尚未覆盖项目。

| 顺序 | 固定被测 Gateway 与参与电脑 | 具体出口 |
| --- | --- | --- |
| 0 就绪 | 当前精确包、两端原 owner、Linux 已安装 C27 与原服务状态 | 确认版本/私有状态/无未知在途操作；先证明独立验收入口可指向本轮被测 Gateway，核对身份和实际路由。不可一直通过 Mac Gateway 来冒充测另一个 Gateway；不修改生产 Tunnel/插件。 |
| 1 Windows Gateway | NAB5 当 Gateway + 本机 Host，Mac 与 Linux 分别作为远端 Host | 正常产品入口创建 Gateway，LAN/VPN 自动选址、邀请与身份核对、三平台清单、角色与权限正确；集中关闭 Windows Gateway 的新主路径及两条跨平台方向。Mac 旧 Gateway 的退休/角色变化依赖新入口实际可用，正常保留状态，不擅自清配置。 |
| 2 Linux Gateway | 工作站的独立 C27 Gateway + 本机 Host，Mac 与 Windows 分别作为远端 Host | 同样集中覆盖 Linux Gateway 主路径与另两条跨平台方向；正常 CLI/前台运行，无新持久测试服务；保留既有 b31 入口、状态和恢复路径，不先改 moedeu-apps 的运行实例。 |
| 3 Mac 缺口 | 复用已通过 Mac Gateway 证据 | 补未覆盖的真实首次设置及错误确认/自撤销保护等必要入口，不重跑已通过的整行。首次设置尽量合并正常产品角色切换，但必须确实满足该场景前置，不能将保留 profile 或旧 reader 的运行成绩当新首设。不得执行此前被拒绝的归档命令；如必须迁移当前私有状态，先形成具体可审查方案。 |
| 4 发布检查 | 同一冻结产品源码的三平台包 | 汇总角色矩阵，正常安装/退出/卸载收口、必要恢复与已有启动指标；随必要启动记录耗时，不另开 benchmark。历史 FAIL/UNKNOWN 与未覆盖项保留，未过门槛不得称成熟交付。 |
| 5 日常部署 | moedeu-apps Gateway，三端 Host-only | 只读核对服务器版本/pins/入口，具体方案后对齐最终包和账号入口；正常配对三端、最小真实效果与服务器重开恢复；最后刷新已安装插件 Logo。此部署不替代前面的平台能力验收。 |

每个新 Gateway 的测试深度固定如下，不能再无限增加检查：

1. 本机 Gateway + Host 验证真实三能力；选一台远端做三能力完整效果，另一远端
   复用其已有 Host 三能力证据，只补真实配对、正确选机和一次独立工具效果，验证
   剩余连接方向与路由隔离。角色矩阵同时记录连接与各工具覆盖深度，不将一次调用
   冒充该格所有工具都已逐项重测。
2. 每个 Gateway 只做一组绑定准确目标的生命周期/安全旅程：明确拒绝、随后新请求
   批准、正常退出重开及既有 Host 恢复、撤销后的无效果与新配对；本机自撤销保护和
   错误确认入口在其实际支持的 UI/CLI 边界验证。不为每个远端复制整套 P1–P4。
3. Gateway 重开时两个远端可同时观察恢复；每台电脑一位原 owner 持有 GUI，准备、
   独立读回和结果汇总可并行。独立验收入口的切换、配对依赖及同一设备角色变更
   顺序执行，不能让多个 owner 或测试客户端同时改其状态。
4. 当前包没有新增缺陷就不构建/重装。遇到实际缺陷先最小复现、有界修复和受影响
   场景；需要新候选时在修复收敛后统一冻结，三平台最终版本来源一致。仅对受影响
   路径回归，不能靠混用不同候选宣称最终矩阵完成。
5. 只维护总矩阵和每个平台一份简短角色结果，绑定版本、实际效果、负控、恢复及
   未测项；复用现有原始证据，不增加每按钮一份报告。每轮给出 PASS/FAIL/未测和
   一个明确下一动作；10分钟无新产品证据就说明具体阻塞，不以反复轮询代替进展。

本节是执行安排，不代表已派发、已改变设备角色或已经验收通过。Windows/Linux
Gateway 均仍待验；此前已经通过的 C27 Host 与 Mac Gateway 证据保持原结论。

## 既有部署核实与历史检查点

> 日常部署偏好（不是产品范围）：日常 Gateway 目标是 **moedeu-apps**，
> PilotMac、NAB5、Linux 工作站是接入的电脑。当前 C27 成绩来自独立验收连接，
> Gateway 实际运行在 PilotMac（Core31647 实测监听 127.0.0.1/10.0.8.165:22022）。
> moedeu-apps 只读实测已有独立 Gateway：用户 unit
> `styx-native-3a6d212c99fdda5a215ba0a9a8fd2eaf-gateway.service` active/running，
> PID65916，监听 127.0.0.1/10.0.38.8:22026，执行文件位于
> `~/.local/share/styx-native-releases/0.4.0-dev.20261031.fresh.2/payload/bin/styx`。
> 该实例与 C27 最终版本/日常插件入口的绑定尚待核对，不能说服务器上没有 Gateway。
> 这证明临时验收旅程通过，不能证明 moedeu-apps 的最终部署或原日常插件已交付。
> 先只读核实 moedeu-apps 现有 Gateway、版本、持久状态与入口，再形成具体可审查的
> 最终部署和三端接入方案。不得把验收连接与生产连接混用，或擅改生产 Tunnel。
> 用户倾向暂缓 Mac 全新 profile 首设；该项保留未测，之前归档方案未派发。
> 此前将最终 Gateway 拓扑称为唯一或首要产品缺口的判断已由上面的产品范围澄清纠正。

> 最新检查点（2026-11-10 00:31 +08:00）：C27 精确源码
> `ca46db609ed2e0a8163f4202189e8bbf3bb85ae4` 的安装后旅程已闭合：
> Windows 新私有 scope 首设、P1 精确拒绝、P2 双方真实三能力、P3 双方正常退出与
> 保留配置恢复、P4 精确撤销及新身份重配对后的三能力均已实际核实；Linux 最新
> C27 独立安装、三能力及正常重开恢复完成，测试进程正常收口，原 b31 服务运行恢复。
> 已安装独立 Custom MCP 最终 Refresh tools 和详情 reload 后仍显示黑色圆形波纹 Logo。
> **完整交付仍未完成：Mac C27 沿用原 Rust profile，不能替代全新首次 setup 验收。**
> 原 Mac owner 的只读最小方案已完成；未重置当前配置、重建或重装。执行方案被
> 自动审批拒绝：当前完整状态迁移到新本机归档路径及验收 Gateway/Tunnel 中断
> 尚缺具体授权，已向用户展示完整归档→首次设置→恢复方案，等待答复。
> 不重跑已闭合的 P1–P4，不为旧错误标签扩大诊断。
>
> P4 旧 Computer token 单次返回 `outcome_unknown/uncertain=true`，原样保留，未重放或
> 改判 NotDispatched。独立效果在调用前后及正常 Pause、原20个 worker 实际退出0后
> 均未增加；角色更改明确要求 Quit/reopen 后，用户正常 Quit 的 App/Core/console
> 原句柄均退出0，同安装同 scope 重开才成功新角色设置。新身份
> `styx-974fae3f5d6e9f283a31a65d` 精确批准/确认后自动连接，三能力新效果独立通过。
> Windows Browser 正常关闭时原 Node/conhost raw exit1 保留，不伪改0；wrong-confirmation、
> self-revoke 未覆盖，不标 PASS。Linux 原 b31 Gateway 连接失败基线仍保留。
>
> 当前收据：`/home/sid/Developer/Artifacts/Styx/20261107-gui-convergence/candidate-27/candidate-inputs.json`；
> P4与最终 Logo：同目录 `account-connection-evidence/C27-P4-CLOSED.json`、
> `C27-FINAL-LOGO.json`。以下 C26/C25 表与时间线均为历史，不是当前进度。

> 当前出口（2026-11-09 08:51 UTC）：C26 冻结源码 `40d56df476f926d6a28db86af67d4ba149282c16`，
> 三平台 Core/完整 Runtime、Mac 原签 App/DMG build1135、Windows `.26` Inno 均已完成。
> 原同 HEAD 集成质量实际执行53项 PASS；打包、安装与账号效果分别记录，不能相互替代。
> Mac 已精确安装，保留 profile，GUI 选择 C26 committed；两次必要正常退出的原进程
> 均实际 exit0，冷重开实际 Core6988/父6986/583b96b…已独立核对，账号三连接可用。
> 首次 generic refresh 失败后单次 GUI Connect 成功，原失败保留；不能称初次启动无故障。
> Linux C26 独立安装、Exec/Browser初始效果及重开新Exec效果通过；测试Host/fixture正常退出0，
> 原b31服务恢复rev92 active/running/enabled，旧Gateway连接仍失败，不能称网络恢复通过。
> Windows C26未安装：C盘约21GB无需清理，原C25正式app status在正常审核上下文明确
> exit2 `app_control_peer_or_protocol_refused`，Quit0/install0；需要本人正常托盘退出这一实际动作。
> 原聊天补充指令已执行；另一次直接续做接口的active-writer错误保留，未开第二owner。
>
> 当前新增阻塞是**公开工具声明兼容性**。实际账号Mac及Linux的list_windows可用，
> 但tree/pixels分支返回 `unsupported_or_invalid_computer_arguments`、uncertain=false，未输入。
> 本会话实际get_window_state声明仅剩branch flags，缺pid/window/environment；click声明缺element_token。
> 冻结源码root schema字段完整，直接decoder场景通过；尚不能证明实际转发字段如何丢失。
> 当前有界草稿仅在现有两个oneOf的每个分支显式重声明公共properties和required，
> 保留root closed-shape、分支const/not、原decoder和权限不变；语义等价与branch-only投影回归
> 已实际通过；受影响crate增量check退出0（2.12秒），独立旧快照结构审查未见阻断。
> 接下来仅执行一次候选检查，不能称连接器或真机已修复。
> 不重复C26 Computer读取、不重放旧P1 Reject UNKNOWN、不为此改系统权限或重启设备。
>
> 下一出口：草稿引用通过→冻结下一个同源码候选→检查真实账号新声明含全部目标字段→
> 三平台最终安装/实际效果/恢复。P1新邀请、请求、拒绝持续授权有效；双方真正READY后才创建。
> Windows等待实际正常退出时继续共享合同工作；下一候选就绪后只安装最新精确候选，避免无意义中间安装。
> P1–P4、Mac同worker安全拒绝恢复、Linux完整Computer旅程和最终installed Logo仍OPEN；Stable NO-GO。
>
> 以下C25表与后续时间线为原始历史，保留失败/未知和证据，不继承为C26或下一候选结论。

| C25 当前事实 | 已验证出口 | 下一门槛 |
| --- | --- | --- |
| PilotMac | C25精确安装、原签/完整闭包/原reader通过；选择C25后一次正常Quit原六进程实际退出0，同配置冷启动的账号list/完整树/截图及独立oracle通过。App等原进程保持；旧fixture实际退出0、旧worker退出0。新fixture91228/window58594同出生存活，基线全0；账号Exec只读ps实际退出0 | 先前三项Computer错误保持Unknown、不重发。07:16首次不同用途verify_state正文明确SESSION_DISCONNECTED/not_dispatched；Gateway无载荷计数正控577→578、该调用578→579，已到Gateway但具体Host分支未定。原owner正做一次已有live状态/日志只读核实。P1精确Reject一次失败/未知；原混合Runtime/refresh失败保留 |
| NAB5 | C25第二次受控安装由用户真实Explorer打开，原owner一次Install/Finish，主子原句柄实际退出0；原安装器严格Gate接受。真实Explorer打开已核对Start Menu快捷方式，App14816/Core5332一次启动、保留原profile，当前选择C25；三能力+Chrome、未配置正确提示和新独立fixture均READY。第二轮新邀请origin/DER CA匹配，06:57:03单次请求明确awaiting_approval，公开身份齐全 | Mac对同一requestID2167219632394897b4a68049c769caf4明确Reject一次后仍Pending、终态未证，P1未通过，批准0。不做新的请求或假定拒绝。第一轮本地过期、Root复制EOF超时和误排队零动作分开保留。旧安装FAIL与首次点击UNKNOWN保留，未改ACL或沙箱，无新构建/签名 |
| Linux | 独立安装/原身份选择 C25；真实账号三能力及独立效果核对通过，同代际旧 token 明确 not_dispatched。正常退出0、同配置重开后的三能力正向核对通过；测试 Host/fixture 最终正常退出，旧 b31 原 CLI 恢复到 rev90、active/running/enabled | 跨重开旧 token 额外负控返回 HTTP 传输错误，无原生回执，结果 UNKNOWN；最终状态未见负值但不能证明从未派发，禁止重放。旧 b31 服务运行已恢复，其 Gateway 连接仍报 gateway_connect_failed，不能称网络恢复通过 |

来源索引：`/home/sid/Developer/Artifacts/Styx/20261107-gui-convergence/candidate-25/candidate-inputs.json`。
Mac 原本机保存的 signer 密码已在原设备 SSH 签名上下文实际解锁成功，Core 签名/验证通过；
原生 Codex 的认证失败和 `CSSMERR_TP_NOT_TRUSTED` 保留为该执行上下文的失败，不据此改密码或转移私钥。
Windows 同 PE、同原 HANDLE、重叠时段的对照证明：同用户名/卷下的同名 AppData 指向不同文件 ID；
MSIX 等具体机制尚未证明，不为此修改产品权限策略或新建候选。

本轮变化（2026-11-09）：

| 维度 | 已发生的变化与限制 |
| --- | --- |
| Product | 新增一项有界修复草稿：本地admin HTTP客户端准入固定Reject路径；C25安装未变。真实P1精确Reject一次失败/未知；新Computer verify明确SESSION_DISCONNECTED/not_dispatched |
| Architecture | 确定的客户端路径合同缺口：有Reject helper和服务端路由，但底层允许列表漏项。旧服务测试用generic HTTP绕过产品客户端，现改真实客户端闭合。Swift映射/五字段完整；没有新增管理权威或放宽请求/会话围栏 |
| Integration | C25仍绑定1d34f8f。草稿限一个Rust产品文件及两个测试、Mac既有可选诊断及隐私测试、本文；disjoint lease已交回，无新checkout。三平台Rust增量check、Mac production/testing及纯隐私断言、严格TLS/Core/持久拒绝基线失败→修复通过、HTTP边界与原服务旅程通过；进入一次集成检查，尚无下一候选包 |
| Release | 三平台C25均完成安装阶段；Windows受控attempt2实际退出0，旧attempt1实际退出2保留。无Core/Runtime/App/安装器重编或重签 |
| Reliability | 保留第一轮Runtime准备约100秒耗尽剩余63秒、Root复制/误排队、工具几何前置拒绝及本次真实Reject失败。新verify完整正文与Gateway计数已取得；不把旧单字段INVALID_ARGUMENT改判。隔离回归原服务与Node均正常收口；没有实机动作重放 |
| Decision | C25无法靠重试补完P1，先收口拒绝修复与Mac会话诊断，再决定同源码下一候选；不立即重复三平台producer。P2–P4/最终Logo仍OPEN，用户持续授权沿用，Stable NO-GO |

本轮源码与原生检查证据：
`/home/sid/Developer/Artifacts/Styx/20261109-pairing-rejection-client`。
真实客户端拒绝基线明确`InvalidInput/NotDispatched`；修复后严格TLS、Core拒绝提交、
错误身份/MCP凭据不提交、实际journal重开、旧claim不可复活及新请求独立性均通过。
测试监听显式使用localhost首解析地址并要求loopback，不通过地址回退掩盖生产客户端问题。
Mac首次故障原值现有入口无法读取的限制已由原owner证实，原历史不靠新日志补写。
新诊断只为下一候选的后续观测留证；原C25四次读取结论各自保留。

P1最新门槛（2026-11-09 06:13 UTC）：用户已明确确认“现在执行本轮P1创建、请求与拒绝”。
Mac新创建/Copy各一次，私密文件2271字节、0600；Root一次私密直传到NAB5新收件槽成功。
Windows输入/Review各一次，GUI origin与canonical DER CA均精确匹配；06:10:10.992Z在
邀请到期前点击请求一次。06:10:53仍Working，无公开deviceID/指纹/验证码/requestID，
当时结果UNKNOWN。邀请06:11:13.824Z到期，不能记作拒绝。Windows后续新鲜只读观察明确显示
`Native result pairing_link_expired_or_invalid`、按钮恢复；Mac06:14:17提交后检查未见行，
但无明确empty/响应成功收据，不能据此证明Gateway从未收到请求。两端无公开身份绑定，
拒绝/批准均0，本轮P1未通过。原按钮单次Working观察保留，不重提、不新邀、不退出原进程。
源码显示Join先完成本地Runtime bootstrap校验/复制，再检查邀请期限，之后才写入join输入
并进入native网络请求。原Core5332实际state-dir父目录的固定bootstrap目录06:10:13创建，
完成selection于06:11:53发布，晚于邀请期限约40秒；本轮Join输入/seed/dispatched/reply文件均不存在。
最初误查App外层目录的全不存在结果已作废，不能作为profile证据。源码固定错误与这些时间
支持本地准备耗尽剩余63秒；并无逐请求网络追踪。已完成bootstrap路径只重验原完成结果，
不再整包copy。两端原owner已完成新独立P1空输入/接收槽READY，原进程和fixture保持。
后续“排队新邀请创建/Copy”整条命令曾被自动审批拒绝，未执行；用户随后明确确认
“执行这次新邀请、请求与拒绝；之后都不用再问了”。同验收范围继续沿用该授权。
第二轮创建/Copy各一次，changeCount1201→1202，私有文件0600/2271字节，期限06:57:54.430Z。
Root原复制脚本等待stdin EOF超时，目标未落盘；依赖命令未在失败处停止，误排队到缺失
指令文件，原Windows owner明确输入/Review/请求均0。原自有复制helper17248核对出生后
结束，确认无活写者且目标不存在；改定长3028字符复制一次成功、双方实际exit0，未修改
产品或沙箱。此额外协调耗时不得归到产品失败。后续所有依赖已改为成功才继续。
Windows对新邀请输入一次，Review几何前置拒绝未派发，滚动/新鲜目标后正常Review；
origin/DER CA精确匹配。06:57:03.320Z单次请求明确`awaiting_approval`，deviceID
`styx-462b163e4c907b7e475fbebf`，公钥指纹
`ff1452d5cc06ccc92ed2bd083c225228181de8ea197197ef048593bf1ea95db3`，
验证码`9BE8-2A3E-8AEA-A49F`。Windows GUI不显示requestID，原Mac owner将绑定本次
实际Pending行requestID，按新鲜身份比较仅明确Reject一次。拒绝出口尚待实际证据。
此后即使成功，仍保留此次首次准备失败，不记为冷首次设置通过。未新增构建/签名/安装。
原动作时确认的自动审批拒绝保留，不能误记为本次已确认操作未发生。
Root账号Exec已实际退出0；Computer的窗口列表、首次树、首次像素各一次返回
INVALID_ARGUMENT，原生派发来源不明。独立OpenAI Tunnel的聚合命令计数有后台活动，
无法给单次调用归因，不作未派发或产品外故障证明；早先cloudflared指标名假设已作废。
独立验收连接详情显示Allow all，未改权限；“Refresh tools”点一次后按钮恢复可用，
此前中间截图可见黑色圆形波纹Logo。进一步浏览器截图被自动审批拒绝：整站
chatgpt.com观察权限超出仅Styx详情范围；已停止浏览器后续操作，最终Logo重验仍OPEN。

独立证据位于candidate-25/windows-owner-evidence/的
`installed-read-diagnosis-root.json`与`installed-gate-root-diagnosis.json`；
原失败与GUI截图保留在NAB5固定project的candidate-25制品目录。

并行顺序记录：此前 Windows 等待人工退出期间，独立 Linux 旅程已并行推进并收口；
Mac/Windows 的 **P1拒绝 → P2批准与双方效果 → P3退出重开 → P4撤销/重配对** 顺序不变。
Mac 首次账号只读属于就绪核实，不提前执行 P2 正向输入效果；两端原生App/fixture及私密接收/Copy流程实际READY前不创建新邀请。Mac当前Computer读取问题单列OPEN，管理GUI的P1可在独占GUI租约下推进，不能据此放行Computer或最终交付。
Linux 测试进程已全退出并恢复原 b31 unit 的运行状态；网络连接未证明恢复，限制单列。

以下 C24 表格与出口说明保留为历史，不代表当前 C25 已验收。

> 历史检查点（2026-11-09，C24）：两端持续项目、工具与缓存归拢和批量清理已完成，
> 用户确认两端 Project 设置完成；复用原 owner 恢复验收。Windows 当前 target 缓存误删且未恢复，不能称缓存全部保留。四项边界实现已集成，C24（`93fdcdd`）已冻结并产包；
> P6尚未通过，不能把C23或参考场景成绩继承为C24成绩。
> 当前修正草稿与已安装C24分开记录；没有新候选构建或安装排队。
> 原工时预测已撤回，按可验证场景出口报告进度。

| 当前工作 | 已完成 | 下一出口与负责人 |
| --- | --- | --- |
| Mac C24 build1133 | 精确DMG签名/安装；一次正常Quit后原App/Core/Tunnel实际退出0；重开后新控制器一次恢复连接成功；真实Exec、Browser及Computer效果独立核对通过 | 原首次连接FAIL及重开后的普通refresh FAIL保留，不能推断startupStatus失败；旧Computer worker在间隔中消失，须另验同worker的安全拒绝恢复 |
| Mac修正草稿 | 独立pending入口和身份比较弹窗完成；Swift production/testing typecheck通过。运行故障仅投影固定stage/cause；原机Rust检查和纯状态case通过；同源码独立原生参考在正常单命令审核上下文通过，资格/严格读取/受控后续epoch拒绝/首故障锁存及原FD drain均过，零输入 | 原默认exec参考在discovery明确拒绝，保留FAIL；正常审核新参考3.71秒通过，不改变全局沙箱或旧账号围栏。当前C24账号Computer仍失败，原首故障无日志不可追溯；源码参考不算新候选安装或账号恢复 |
| Gateway重开参考 | 真实签名payload/严格TLS基线失败；有界修复后同场景通过：Gateway仅按自身Running恢复、Stopped负控和Host停止意图/原文件保持；affected检查通过 | 修正尚未打包或安装；这不是Mac历史首次错误原因的证明，不触发立即产包 |
| Windows C24 .24 | 本次GUI Join仍UNKNOWN；用户正常Quit后原App/Core/conhost不存在、退出码不可得；同profile重开App6536包验证失败、无新Core。2154文件全部匹配，四进程可见token flags一致 | 正常GUI新鲜Retry一次仍FAIL。Codex命令上下文祖先AppData/Local触发原ACL上界拒绝，独立SSH对应10节点均通过且验签exit0；尚未归属具体SID/actor。原CLI状态固定码app_control_peer_or_protocol_refused，Quit0。保留原失败，不放宽ACL；原owner核实正常单命令审核通道，只有状态精确匹配且idle才正常Quit/重开 |
| Windows安装修正 | 九组真实Node/ISCC预处理及独立argv参考通过；同字节修正已纳入源码草稿 | 后续精确安装器的实际快捷方式仍待验，不继承手工修正成绩 |
| Linux C24 | 独立安装/配对，真实账号Exec文件42字节与哈希、Browser独立请求1、后台语义输入/点击1均通过；效果后正常退出原Host/能力进程及重开连接通过；原b31最终已恢复rev88 | 账号重开读取两次及Exec只读均Unauthorized；完整恢复未过。真实TLS/WSS源码基线复现旧绑定阻挡新Host，修复/旧业务帧/未知清理负控通过但未安装；审批commit已证、GUIactor未归属，不能称GUI批准PASS |
| 跨设备及Logo | C24 P1参考已尝试但未通过：新鲜Copy成功并私密直传；原Copy UNKNOWN保留；双边未形成请求身份绑定，拒绝/批准均0 | Root过早安排关闭邀请Sheet暴露无独立pending入口，已修源码未安装；不把邀请过期或无持久记录算拒绝。P2–P4、Linux完整旅程及最终Logo仍待验 |

当前机器收据索引：`/home/sid/Developer/Artifacts/Styx/20261107-gui-convergence/candidate-24/candidate-inputs.json`。
NAB5新任务统一放`D:\Developer\Styx`；现有安装/profile/冻结制品路径保留。

2026-11-09源码出口：`integration-quality6/receipt.json` 的53项全部PASS，154.74秒；
没有产包或安装。真实TLS/Core/Host/Gateway参考已关闭“明确未派发却保留Opening”
缺口：原Host只终结精确仍Reserved的记录，Gateway仅接受匹配终结证明；Unknown/
丢失回应保持封锁，正常owner与transport清理通过。其结果在
`20261108-architecture-reference/computer-open-refusal/RESULT.md`。
独立Gateway恢复及干净Host新代际绑定参考也已通过，均尚未安装。

冻结只改变Git归属时，允许独立来源等价证明复用原不可变测试结果，不能修改原
quality收据或伪称重执行。必须绑定新clean HEAD逐blob与原404项输入，并额外核对
collector未包含的七个Rust嵌入PNG/技能Markdown/plugin.json：七者须与原93fdcdd
blob相同且原检查前后无dirty记录。新证明明示原执行revision、原收据SHA和
`tests_reexecuted=false`；正常制品构建及真机验收照常必需。

## 1. 完成定义与边界

最终同源码候选必须在 PilotMac、NAB5 真机完成：精确安装、能力选择、GUI
邀请/拒绝/批准、双方真实账号 Exec/Browser/Computer Use 独立效果、正常退出与
重开恢复、撤销旧设备的负控、重新配对。最新 Linux 候选也必须安装并验收。
最后刷新已安装的独立 Custom MCP 详情，仍显示 Styx 黑色圆形波纹 Logo。

编译、测试、打包、安装、实际效果、恢复分别记账；任一缺项不能宣布完成。
恢复通过不能把首次失败改写为通过。预览验收完成也不自动放行 Stable。

不增加产品范围，不重开语言/管理核心选择；只用 Rust 自有管理核心以及已选定的
Codex/Cua/Playwright 和原生桥。不接管浏览器、不增加自动任务或持久服务功能。
不操作 piermini、不重启工作站、不删除正式插件、不修改生产 Tunnel、不关闭
沙箱、不扩大现有产品/profile/祖先目录权限、不转移签名私钥。

## 2. 历史C23事实基线（不得作为当前C24验收结果）

| 项目 | 已有证据 | 当前结论 |
| --- | --- | --- |
| 源码 | develop，C23 提交 `fd41fcefa3ea24f670eede6983105b2e1c762d35`；候选输入已冻结 | 不为本文重建、改包或提交 |
| 集成质量 | C23 检查通过，125.66 秒；原平台缓存复用 | 测试通过，不等于平台通过 |
| Mac 安装 | build1132，精确 DMG 安装一次，签名/完整性核验通过 | 安装通过 |
| Mac 首次设置 | 新 profile 的 Tunnel 保存后 Computer 初始化失败，`console_match/console_epoch_changed` | **FAIL，R1 必须闭合** |
| Mac 恢复 | 正常 Quit 的五个原进程实际退出0；同配置重开后完整树/独立截图通过 | 恢复路径通过，不称首次冷启动通过 |
| Mac 拒绝恢复 | 新邀请 Sheet 读返回 StaleObservation/NotDispatched；同一 SDK worker 随后有效窗口读取成功；旧 token 写入被拒，独立状态无效果 | C23 此回归通过；该 worker 后续正常退出0，不能称持续存活 |
| Mac 真实效果 | Exec 原PID71555续接、一次输入/独立文件/退出0；Browser 一次 nonce GET/页面读取/关闭；Computer 一次设值和一次点击/独立文件与像素 | C23 恢复后的三类效果通过 |
| Windows 安装与设置 | C23 O 安装一次，2169文件闭包、Runtime与publisher核验；新导航、三能力、Chrome | 安装/设置通过；账号三效果尚未验收 |
| 最近配对实测 | slot02私密传输；双方设备ID/公钥指纹/验证码及Windows GUI CA与Mac canonical DER核对通过；请求一次；Mac负向按钮一次后当时仍pending，批准0 | **P1未通过：此入口仅取消比较，没有终结拒绝；之后到期也不算拒绝通过** |
| 第一份邀请 | 到期前 Windows 未输入、未审阅、未请求；Mac 无批准/拒绝 | 协调失败，EXPIRED_NO_ACTION，不能代替拒绝测试 |
| Custom MCP Logo | 本轮详情页刷新仍显示黑色波纹 Logo，截图已存证 | 当前通过；全流程最后再刷新 |
| Linux | 最新候选尚未安装/验收；工作站原服务保留 | **OPEN；不能宣布交付完成** |

C23 制品根：`/home/sid/Developer/Artifacts/Styx/20261107-gui-convergence/candidate-23`。
实际账号收据位于其中 `resumed-account-acceptance/`；质量收据为 `quality/receipt.json`。
P1本轮已知失败收据：`resumed-account-acceptance/pair-negative-known-native-gap.json`。
Mac phase38 owner已turn.completed并退出；Windows仅协调CLI的等待已收口（实际exit-1），
Styx App/Core保持存活，没有将协调CLI的退出算作产品正常退出验收。

精确安装输入：

- Mac DMG SHA256：`07a2d757c54f9b83f7bc2ef07ab568694e3ba8cdef2562b3b6c382a4cf3c7e97`。
- Windows Inno 0.4.20261108.23 SHA256：`2e35e1e4c59d4ddfbba439445205d4d95912517a3389167200055db49032cf6e`。
- Windows 预览安装器没有 Authenticode 签名；其已验证的 Runtime publisher 签名不能被表述为安装器 Authenticode。
- 本文新增文档不改变已冻结 C23 的源码归属、输入哈希和实际验收结论。

## 3. 负责人、租约与状态记录

| 负责人 | 独占写入范围 | 不承担的范围 |
| --- | --- | --- |
| 根代理/集成人 | 唯一 develop checkout 的共享源码、锁文件/合同、原 signer 就地集成、不可变候选输入；独立账号工具与跨设备公共事实核对；计划与证据索引 | 不再包办两端 GUI，不读/传私钥，不把真实账号效果换成 SSH 脚本效果 |
| PilotMac 本地 Codex owner | PilotMac 原生 App 操作、安装/进程句柄/fixture、该机私有邀请文件；保留原线程和可复用 helper | 不改共享源码，不操作 Windows，不替根代理完成账号验收 |
| NAB5 本地 Codex owner | Limited Interactive Sid 的原生 App、安装/进程句柄/fixture、私有收件槽；复用原 owner/helper | 不改已有 ACL，不操作 Mac，不自行批准身份不匹配的 Gateway |
| Linux 本地验收 owner | 获得具体切换授权后的本机安装/退出/恢复与原生场景 | 未获授权前不替换工作站服务 |

每个设备同一时刻只允许一个原生 GUI 写者。交接前核实原 CLI 的完成/退出及
未知操作状态，不能用“final 文件存在”代替真实结束。只读观察器不是 GUI 写者。
根代理不新建产品 checkout/worktree；现有历史 worktree 保留。

每阶段只发布：`阶段 → 已完成证据 → 剩余门槛 → 下一动作/阻断`。
公共计划和收据中不保存邀请、Runtime key、签名私钥。`/tmp` 状态只作辅助，不是第二套计划。
后续 owner 应在多个检查点之间保留上下文并等待明确门控，避免每个按钮都结束并
重启 CLI、重新审阅整段历史。只能在原 owner 已结束后切换上下文。

## 4. 既定路线与阶段出口

路线调整（2026-11-08）：核查证实C23缺少终结拒绝路径，且接口合同、App替换和Mac
资格确认存在边界不一致。旧路线“先用C23跑P1–P4、最后再修复”已不可执行。

当前顺序：**`P0 已核实 → D0 已决策 → R 有界实现/参考 → P5 冻结候选 → P6 安装与验收 → P7 交付核对`**。
P6内部按 **`首次设置 → P1拒绝 → P2批准/双方效果 → P3退出重开 → P4撤销/重配对`**
执行，再核对最新Linux旅程。P1–P4编号保留用于关联既有证据，它们不再是C23上的前置开发阶段。
**C23仅保留诊断和既有证据；新候选必须先关闭四项边界的必要参考场景。**

| 阶段/状态 | 执行人与具体工作 | 进入条件 | 必须留下的出口证据 |
| --- | --- | --- | --- |
| P0 已完成 | 根代理只读核实源码、精确包、两端安装/owner/原进程、fixtures、既有授权 | 不重放旧操作/producer | 固定候选与平台事实；测试/包/安装/真机分别记录 |
| D0 设计已完成 | 根代理完成四项边界状态/合同/复用点/失败分支与工时 | 架构核查已完成，产品草稿冻结 | 见DELIVERY-BOUNDARY-DECISIONS；不是实现或验收PASS |
| R 进行中 | 先D4来源参考与D1合同场景，再D3安装参考和D2全链路拒绝/reader；根代理共享源码唯一写者，两端owner做本机原生检查 | D0设计已选定 | affected crate检查、跨层持久/TLS/负控场景、Mac原生参考；未知触发不冒称已证明；参考未过不产候选 |
| P5 C25已完成 | 根代理按实际改动冻结同源码候选 | R参考、quality6及来源等价证明已过；原生构建和三平台完整包分别有收据 | C25提交1d34f8及精确三平台输入/签名/包收据；不重复已完成producer。必要产物构建与测试分开记录 |
| P6 C25进行中 | Mac已安装并GUI选择C25；Windows已产包待真实桌面退出/安装；独立Linux旅程并行。Mac/Windows首次设置后仍按P1–P4执行 | 同源码候选已冻结；每个安装有精确哈希；Linux服务切换已获具体授权 | 最终候选自身的安装、首次设置、双方真实效果、负控与恢复；不能继承旧 C23/C24、旧 b31、诊断参考或mock结果 |
| P1 最终候选待验；C23已失败 | 两个本地 owner 完成本次新邀请；Windows 审阅 CA 后一次请求；根代理比对设备身份/验证码；Mac 明确拒绝一次 | P5及P6精确安装/首次设置通过；双方原生路径、私密接收槽、helper **已实际READY**；新邀请未过期；私密传输已明确成功。P1不操作fixture，独立fixture在P2实际效果前就绪 | Gateway唯一requestID与Windows实际设备ID/公钥指纹/验证码绑定；Mac明确拒绝、Windows观察到拒绝，账号中没有新增已授权设备。Windows GUI不显示requestID，不能伪称双边显示；到期/超时不算拒绝 |
| P2 待执行 | 新邀请、新请求；比对后 Mac明确批准；Windows确认并连接；根代理在独立 Custom MCP 上核实两台设备及三类效果 | P1明确收口，无未知请求；当前 CA/设备身份一致 | 本候选双方 Exec续接/独立文件、Browser nonce页面/HTTP日志/关闭、Computer像素/新鲜树/一次输入点击/独立状态；原生负控单列 |
| P3 待执行 | 各端 owner 记录全部原进程/子进程句柄，正常 Quit 一次；全部明确退出后正常重开一次；根代理检查恢复 | P2效果已核实，原生动作无未知结果 | 原进程实际退出码、worker/监听/socket收口；配置/keys/pairing保留；双方重新连接及新的实际读取。接受 Quit 不等于已退出 |
| P4 待执行 | Mac GUI撤销精确 Windows设备；根代理对旧设备做无效果负控；用新邀请/新确认重新配对并验证恢复 | P3通过；撤销目标精确匹配，不能是本机 | 撤销明确完成；旧环境/旧 token 不能产生新文件、HTTP或桌面效果；重新配对后实际新读取/效果恢复。wrong-confirmation/self-revoke按当前产品支持入口单列核实，未覆盖不能标PASS |
| P7 待执行 | 根代理刷新已安装测试插件详情核对 Logo，校对全矩阵/安装说明/已知限制/回退与历史留存；提交可审查交付结果 | P6所有必需格已闭合、没有未处置Unknown | 六领域变化报告和直接证据链接；交付完成定义满足。Stable继续NO-GO，除非其现有门槛被另行明确核验和放行 |

P1–P4不再继续消耗C23邀请或安装次数；已证实的产品边界缺陷集中在R修复。
P5只在参考闭合后生产一轮必要候选；owner准备不足、邀请过期、连接器刷新或协调错误
不触发产品构建。新增产品缺陷先记录触发和证据，再决定是否需要另一轮候选。
任一阶段缺少必需产品路径时，先进入其R项定位；这一分支没有通过前不把后继阶段
记为通过，也不自动新邀/批准来绕过失败。需要调整诊断顺序时，先在本文记录原因。

## 5. 必须闭合的问题与失败分支

| 编号 | 事实/不确定性 | 下一动作与完成条件 | 禁止的捷径 |
| --- | --- | --- | --- |
| R1 首次设置 | C23新profile保存Tunnel后，Computer初始化因console epoch变化失败；正常重开恢复通过；精确首次源变化触发仍未证明 | 保留原失败；用新的只读参考源定位初始化资格与严格源校验边界，取得独立重现；最小修复后最终安装首次设置实测通过。默认修复，不请求降低标准 | 反复重启碰成功、调大timeout、放松锁屏/身份/ABA围栏，或用恢复PASS覆盖首次FAIL |
| R2 配对路径 | 本轮CA/设备指纹/验证码实际匹配，请求一次；Mac“不一致或取消”一次后仅关闭比较框，同请求仍pending、批准0。源码`ProductPresentation.swift::confirmPendingIdentity`对负向按钮直接return，与实测一致；该结果不是terminal拒绝 | 保存P1失败；确认现有后端合同/原生入口对pending请求的终结方式，形成绑定原requestID/身份的最小场景与修复。不要将取消比较直接改称拒绝。修复后重做P1，随后P2–P4 | 把未批准当作终结拒绝、把邀请过期当作拒绝、读旧剪贴板、猜测请求已提交、重复未知Join |
| R3 账号读取超时 | 重开后的list_windows一次超时无结构结果，随后Session terminated；刷新工具恢复；该请求是否原生派发未证明 | 该历史请求永久Unknown、不重放；后续不同的受支持读取已通过；若再现，保留连接/Host/native闭合诊断再归因 | 把会话问题直接定性为native失败，或自动重试同一请求 |
| R4 根代理协调 | 首邀早于Windows实际就绪；过严预备指令阻止授权内导航 | READY定义落实；允许owner自主进行已授权导航；多检查点复用owner；记录协调耗时 | 把协调错误当产品缺陷、让用户反复批准普通导航或触发新构建 |
| R5 Linux | 工作站仍运行较早构建，最新候选未安装验收 | P5准备精确包与可审查回退步骤；先只读核实服务/路径/出生时间；得到窄范围切换授权后进入P6 | 自行替换服务、重启工作站、宣称旧b31结果覆盖最终候选 |
| R6 接口合同 | full_output在公开schema合法、实际分类器却不支持；部分输入被广告但无准入路径 | 执行D1；分离上游catalog与Styx支持合同；跨层正反例及实际账号读取 | 只加提示、放宽原生授权、继续声称支持完整SDK |
| R7 安装选择 | 默认bundle内Runtime选择与App替换矛盾，曾保留profile启动失败 | 执行D3；先原生参考验证App外stage和保留profile；已有C23过渡也先参考 | 清配置绕过、原地改hash/identity、扩展延期维护协议 |

出现失败时按以下分支处理，不任意改变路线：

1. **明确未派发**：保留原因；修正参数/新鲜观测/前置条件后，可以发起新的、明确不同的请求。
2. **已确认操作/效果**：先独立核对；需要下一动作时使用新鲜目标，不重发前一动作。
3. **结果未知**：冻结该动作及相关目标；只读检查原句柄/收据，不能重放。缺少授权且确实需要强停/改配置时，先形成具体可审查方案，再只问一次窄权限。
4. **owner协调或工具问题**：优先解决owner/连接器/参数；不改产品、不重建。
5. **实际产品缺陷**：补齐最小场景、修复与增量检查，在R闭合后进入P5；新候选前在本文记录必要性和受影响平台。
6. **需要改变范围或安全边界**：列明与REDUCED-SCOPE/现有授权的冲突后交用户决定；不偷偷改变完成定义。

## 6. 邀请、资源与构建预算

- 新邀请只在两端原生路径和接收槽实际READY后创建；10分钟有效期不能拿来完成工具开发/流程审阅。
- Copy必须是本次明确动作，pasteboard计数实际推进后只读新值一次；只存设备私有文件。
- 只用已锁定身份/权限的空接收槽；两条SSH直连管道不落根代理文件、不打印token。写入未知或非空槽永不重放/覆盖。
- 审阅后先逐值比对canonical DER CA，再允许请求；请求后对比两端原始设备指纹、验证码、requestID，再明确批准/拒绝。显示名称不是身份。
- 邀请过期前必须留有足够时间完成本阶段；过期则明确收口，无请求不能声称拒绝。新邀请是新尝试，旧证据保留。
- 每阶段10分钟无新证据时，owner必须交付最小阻断与实际动作计数；根代理解决阻断或收口该尝试，不能靠重复轮询代替进展。未知操作优先于任何时间预算。
- 日常只做affected crate增量`cargo check`与改变的场景；候选冻结才跑一次工作区质量。原平台缓存保留，不clean、不为诊断新建完整产物树。
- 本轮C23质量125.66秒，Mac Core84.27秒、Windows Core215.36秒，是构建耗时证据；不把多小时协调成本算成编译成本。
- 需要的新构建使用已有平台并行生产者，保留实际jobs、timings和内存压力；未验证旧编译输入不能盲用缓存。
- 对路线的改变先修改本文并说明`原因/新增证据/影响阶段/额外成本`；普通授权内操作不再增加审批。

## 7. 最终验收矩阵与报告

下表保留C25阶段的历史待验状态，**不是2026-11-12重新派发测试的清单**。
当前缺口以上部最新开发检查点及已绑定的原始收据为准；复用未受影响的通过证据，
仅补当前修改影响的启动/恢复与尚未完成的正式入口，不因本表旧“待验”重跑全部矩阵。

| 必需格 | PilotMac | NAB5 | Linux最新候选 |
| --- | --- | --- | --- |
| 最终精确候选安装/签名与输入闭包 | 待P5/P6 | 待P5/P6 | 待P5/P6 |
| 最终候选首次设置/能力选择/实际就绪 | R1未闭合 | 待P6实际连接 | 待P6 |
| GUI邀请/拒绝/批准/身份绑定 | P1拒绝未通过；R2定位 | 请求/身份绑定已核实，上次观察awaiting_approval；未观察到拒绝 | 按既定Linux入口验收 |
| 真实Exec/Browser/Computer独立效果 | C23恢复路径已过；最终候选待验 | 待验 | 待验 |
| 效果后正常退出、全部原进程收口、重开恢复 | 待验 | 待验 | 待验 |
| 撤销负控/旧权限无效果/重新配对恢复 | 待验 | 待验 | 按既定能力与连接范围待验 |
| 最终安装插件详情刷新Logo | 跨平台共享账号项，P7待验 | 同左 | 同左 |

每条PASS应链接不可变收据，包含：候选提交/包哈希、设备/原进程身份、触发及实际
派发计数、工具结果、独立效果、负控、恢复、退出观测、限制。不能只贴测试数量。
FAIL保留第一次失败；UNKNOWN单列；后续恢复另建收据。

每次阶段出口用六项报告变化：**Product、Architecture、Integration、Release、Reliability、Decision**。
没有变化写“无变化”，避免重复历史叙事。必须区分测试/包/安装/真机，明确下一门槛。
所有P7门槛未满足前，结论固定为**交付未完成、Stable NO-GO**。

## 8. 本次路线调整的六领域变化（2026-11-08）

| 领域 | 相对架构核查报告的变化 |
| --- | --- |
| Product | 四项必要行为形成明确出口；实现/参考/最终平台验收仍未通过 |
| Architecture | D0选定工具子集合同、完整拒绝与reader门槛、App外Runtime选择、Mac资格阶段；保留既有四层依赖 |
| Integration | 唯一develop checkout；产品diff与审查冻结草稿逐字节一致；本次只改文档/辅助状态，链接和diff检查通过 |
| Release | 无新构建/签名/安装；P5移到四项必要参考之后，P1–P4改为最终候选P6内部旅程 |
| Reliability | 保留C23 FAIL/Unknown，不用恢复覆盖首设失败；把格式回退和旧claim复活等风险纳入必要负控 |
| Decision | goal仍active；先R1受控来源参考与工具合同支持表；工时区间撤回；四路并行且文件租约分离，统一源码检查点验证 |


## 9. 当前并行检查点（2026-11-08）

最终goal不重建，完成范围不缩减；本plan作为goal引用的执行入口已同步。

| 工作流 | 当前实际结果 | 下一门槛 |
| --- | --- | --- |
| 根代理/D4 | Mac五项受控只读原生参考、三项console合同场景及Swift类型检查PASS；取消重入/空drain两个审查发现已修并原机通过 | 最终候选真实首次设置/Tunnel保存；不能称已通过首次设置 |
| D1工具合同 | 静态35份schema/上游原catalog验证通过；7个Runtime/Gateway跨层场景PASS | 最终工具刷新与真实账号读取；不宣传完整SDK输入能力 |
| D2拒绝 | Core持久/身份/旧claim、实际签名C07/完整tip、写前floor、真实TLS拒绝/重开/旧claim、新seed拒绝文件分支均PASS；旧证书Expired和漏接genesis失败保留 | 实际旧C23二进制负控、两端最终GUI拒绝/批准与账号旅程 |
| D3安装 | 3个签名/FS场景及真实CLI文件+strict TLS双role替换/原profile重开参考PASS（测试原PID300476 exit0，165.33s；Gateway为同进程任务，无Host executor） | 已安装C23正常外移过渡、最终包与真机进程/能力验收 |
| Windows本地owner | check2实际csc exit0，源码哈希已记录，exe执行/安装/GUI均0；check1路径错误保留 | 最终候选原生GUI行为与账号工具验收 |

各subagent已交回完成部分的产品文件租约；后续接线先交patch，由根代理在共同检查点
审查后一次集成。主工作区没有新worktree；设备只有各自原owner，检查未替换安装。


## 10. 模型与设备责任（用户更新要求）

最新实测turn_context：根对话 gpt-6.1-sol/high；此前为xhigh，早期subagent曾继承根配置。
此前PilotMac owner是gpt-6.1-sol/high，NAB5是gpt-6.1-sol/medium，不能称曾按平台配置Terra。

现已用单任务CLI参数续接两端原线程，并核实实际turn_context：

| owner | 当前实际模型/effort | 当前具体任务 |
| --- | --- | --- |
| PilotMac原owner | gpt-6.1-terra / high | phase44修复/增量检查PASS；phase45现有C23双role外移Committed，一次正常Quit、原五进程exit0 |
| NAB5原owner | gpt-6.1-terra / high | source-check1完整源码检查PASS；install-check2只读占用正反控及Inno无输出语法检查PASS |

没有更改全局模型配置、重建线程或并发启动同设备第二个owner。平台专属客户端开发、
诊断、原生检查和GUI由相应本地owner负责，回交精确补丁/源码哈希/原机证据；根端负责
共享合同、架构决策、源码集成、签名候选与跨设备/账号事实。设备上的参考输入树不是
新的Git集成checkout。普通执行任务显式设置模型/effort，避免所有子任务默认继承xhigh。

旧binary当前任务只证明manifest verifier边界；新7 root激活负控、真实Runtime替换参考、
精确候选安装和完整GUI旅程仍单列，不能以此较窄检查代替。


## 11. 参考执行出口（2026-11-08）

受影响场景收据：`20261108-architecture-reference/checkpoint3-scenarios.json`，已修失败组均PASS；
此前工具合同和默认stage场景见checkpoint2收据中各自PASS项，FAIL历史不删除。
真实Runtime文件/strict-TLS/App替换参考见同目录`real-runtime-reference-RESULT.json`。
它执行实际HostApp库入口和配对，不是mock；Gateway为测试进程内任务，不冒称独立OS
进程exit。测试进程实际exit0，未启动Host执行器。最终GUI/账号效果仍待精确候选。

PilotMac phase42和NAB5 reader7-check1均以实际Terra/high完成，原C23 verifier的旧格式
正控exit0，新reader7及old-reader/state7不一致负控exit2；worker0、安装0。完整私有日志
留在设备，仅公开字段核对。不把manifest拒绝称为已完成新7 root实际激活负控。

下一出口：完整当前源码的平台check-only → 一次集成质量检查 → 冻结精确源码候选。
Mac已安装C23的双role外移仍需正常GUI操作并确认两者Committed；单stage或Unknown不够。
本轮平台检查已返回：Windows全源码check-only PASS；Mac测试直接构造带私有字段的事件失败，
原owner改用公开Gateway事件流保持原断言，增量check PASS；根端集成并执行对应测试PASS。
集成quality2因两个旧reader fixture提前拒绝而失败；仅更新签名测试fixture到reader7，
join-retry与tunnel两组场景PASS。失败记录保留；下一完整质量检查等待源码接线收敛后运行。
Windows安装预审证实普通Quit后非空安装根仍强制maintenance handoff，与v1范围冲突；
install-check2由原owner局部修正为已有Setup/App mutex和只读文件占用守卫，不扩展维护协议。
修正已集成，运行中O与存活fixture均exit1，fixture正常exit0后守卫exit0；
Inno `--output=no`实际exit0，不生成新安装包。真实升级/安装仍待最终包验收。
启动器首次在实际派发前因PID复用误拦：原Codex2960已exit0，后来同PID为另一node，
已按出生时间绑定修正并保留失败；没有终止该node或重复产品动作。
Mac phase45一次Stage/Update完成实际Host/Gateway双role Committed，选择相同App外C23
manifest `9cabcb4c6993561fc6725a22b6d81ee1eb6ca4d0c3d4e83faad0a4d3b9216227`；
随后一次正常Quit，原五进程均独立exit0，listener/Cua socket清空。C23保持停止，没有重开或安装。
Linux完整worker源已合并原已签Browser及修复版Cua/Codex，原signer就地签名、独立验签及
2148成员校验PASS；manifest `d5645a9471f2f1b851926ef07b6c1d54987b8c1af362fdaa07d58059e0038252`。
它是必要候选输入，不是新Runtime包、安装或能力验收。旧C23对reader7 root直接启动负控仍待执行。
phase46原Mac owner正用冻结774c982源码做一次必要debug CLI编译和隔离root激活负控；
这不触碰已停止C23 App或产品profile，不是重复release producer。
774c982集成quality3的所有执行场景、lint、ignored分类及输入稳定性PASS，但新增setup
测试断言的rustfmt格式FAIL；保留失败，仅格式修正后重新冻结并运行最终集成检查。
phase46参考源码与后续冻结源码的该项差异仅为test断言格式，不影响reader7产品逻辑。
Windows C盘最新空闲60,633,088字节；O程序树566,629,898字节。现有删除授权不覆盖O，
不得直接删除。最终包准备后需按实际安装/外部stage峰值形成具体空间方案；profiles/keys保留。
用户最终要求的安装、首次设置、真实三能力、拒绝/撤销/重配对、进程退出重开、Linux最新
安装与最后Logo刷新均保持原门槛。交付未完成，Stable NO-GO。
