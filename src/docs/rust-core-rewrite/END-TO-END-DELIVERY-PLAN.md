# Styx 原生 GUI 与 Custom MCP 端到端交付计划

2026-11-08。本文是**剩余交付工作的唯一执行入口**；范围由
[REDUCED-SCOPE.md](REDUCED-SCOPE.md) 决定，架构由
[README.md](README.md) 和冻结合同决定。
[GUI-CONVERGENCE.md](GUI-CONVERGENCE.md) 保留历史尝试与证据，不能把历史通过当作当前候选通过。
本文中的计划项不代表已经执行。**交付未完成；Stable NO-GO。**

> 当前阶段：架构核查完成，D0四项
> [边界决策](DELIVERY-BOUNDARY-DECISIONS.md)已选定，四项有界实现已集成；
> 受影响合同/FS/签名/TLS、真实Runtime替换/重开参考及旧binary manifest拒绝实证已通过。
> 两端当前源码编译检查和Windows安装守卫修正已通过；当前进入冻结源码的集成质量检查。
> 不继续用C23推进缺少入口的完整旅程；不在参考闭合前构建或安装新候选。
> 原4–8小时及后续9–18小时预测均撤回；按用户要求并行实施，按可验证场景出口报告进度。

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

## 2. 当前事实基线

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
| P5 待R出口 | 根代理按四项边界的实际改动一次冻结同源码最终候选 | R的合同/持久兼容/安装参考/Mac原生参考已通过；必需路径存在 | 一个集成检查点；精确三平台输入/签名/包收据；不重复已完成producer。必要产物构建与测试分开记录 |
| P6 待P5出口 | 本地 owner 安装最终精确包；首次设置后按P1–P4完整旅程；Linux完成最新候选安装和真实能力/正常退出恢复 | 同源码候选已冻结；每个安装有精确哈希；Linux服务切换已获具体授权 | 最终候选自身的安装、首次设置、双方真实效果、负控与恢复；不能继承旧 C23、旧 b31、诊断参考或mock结果 |
| P1 最终候选待验；C23已失败 | 两个本地 owner 完成本次新邀请；Windows 审阅 CA 后一次请求；根代理比对设备身份/验证码；Mac 明确拒绝一次 | P5及P6精确安装/首次设置通过；双方原生路径、fixture、helper **已实际READY**；新邀请未过期；私密传输已明确成功 | Gateway唯一requestID与Windows实际设备ID/公钥指纹/验证码绑定；Mac明确拒绝、Windows观察到拒绝，账号中没有新增已授权设备。Windows GUI不显示requestID，不能伪称双边显示；到期/超时不算拒绝 |
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

下表“待验”是当前真实状态；即使已有历史成绩，也不填成最终候选PASS。

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
Windows C盘最新空闲60,633,088字节；O程序树566,629,898字节。现有删除授权不覆盖O，
不得直接删除。最终包准备后需按实际安装/外部stage峰值形成具体空间方案；profiles/keys保留。
用户最终要求的安装、首次设置、真实三能力、拒绝/撤销/重配对、进程退出重开、Linux最新
安装与最后Logo刷新均保持原门槛。交付未完成，Stable NO-GO。
