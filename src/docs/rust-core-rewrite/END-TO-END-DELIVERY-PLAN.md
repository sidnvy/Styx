# Styx 原生 GUI 与 Custom MCP 端到端交付计划

2026-11-08。本文是**剩余交付工作的唯一执行入口**；范围由
[REDUCED-SCOPE.md](REDUCED-SCOPE.md) 决定，架构由
[README.md](README.md) 和冻结合同决定。
[GUI-CONVERGENCE.md](GUI-CONVERGENCE.md) 保留历史尝试与证据，不能把历史通过当作当前候选通过。
本文中的计划项不代表已经执行。**交付未完成；Stable NO-GO。**

## 当前开发检查点（2026-11-12）

以下补充本轮实际变化；后面的 C30 验收矩阵保留，尚未通过的格不因开发检查通过而关闭。

| 出口 | 当前证据 | 下一动作 |
| --- | --- | --- |
| 固定项目指导 | 三端 source 同步至 `997ad83`；Mac/Windows 父项目 AGENTS 薄入口与 Skills 发现链接均有 READY 收据 | 按需使用指导，不再每次加载历史或新建项目/聊天 |
| Windows staging 归拢 | 四祖先限定 ACL 完成；4326 文件复制/哈希一致，新树权限验证通过，正式 C30 reader 实际 exit0；新 Developer staging 指针已启用，旧树保留 | 此项收口，不再审计或复制一次 |
| Mac 真实开发入口 | 固定运行位置/隔离持久 dev profile 改动已集成；原机 Swift/Node 及 Root Node 合同通过；App 构建/原签实际 exit0（31.172秒），独立严格验签 exit0；旧 App91645 实际退出0，新 App27564/Core27569 到首次设置，startupStatus ok/bootstrap_completed | 当前已进入同 dev profile 正常重开验证，不重建或重签 |
| Mac 完整 Runtime | 复用已完成的 `5618911` Core 与原 workers，prepare/finalize 实际 exit0；原 publisher manifest 签名及独立验签通过；packet 已送到固定项目 | 供上述真实运行使用，不再重编 Core 或制作 DMG |

Mac 新 dev Gateway 通过实际 GUI createLocal/tunnelSave 各一次，三能力/自动 LAN/系统权限
已核对；独立验收 MCP 实际列出 `styx-7c7a313ee112506335705652` connected。
冷账号 Exec 文件30B已独立读回；Browser nonce页面/快照和关闭完成；Computer完整AX树、
实际PNG、输入/提交成功。无害Sheet66182的单次读取明确not_dispatched/uncertain:false，
同上下文后续主窗读取成功；旧消费token负控同样明确未派发且原输入保持。
fixture为29600/66165，真实5小时TTL，不因便利偏好再编译夹具。
正常Quit后原6个产品进程（含SDK worker30288）均由原观察器记录实际exit0；
同一App/同一dev profile重开尚待结果与Root新账号读取。独立效果计数/同worker收据随原owner归档。
开发配置结果不能回填原 C30 同配置 P3 恢复 FAIL。旧 App/配置/keys 保留。
为满足现有 Runtime 组装器的精确 Git HEAD 要求，使用过一次记录租约的冻结组装工作树；
无源码修改或编译，签包完成后已清退并保存 HEAD ref，当前集成 checkout/缓存不变。
Windows 原 App/Core 本轮新鲜核实已不存在、22022 无监听，原退出原因未知；
当前只有Session0 SSH app-server，无Sid桌面/Explorer/原生Computer Use pipe，产品启动0次。
Session0的新fixture不算交互GUI READY。用户仅能使用Moonlight，Sunshine已正常重启一次；
显示捕获仍需验证。仅启用既有微软兼容签名的Virtual Desktop Monitor（Code22→0），
未改另一未签名虚拟驱动、Intel、配对、安全策略或重启电脑；客户端复测待用户结果。
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
phase46原Mac owner正用冻结774c982源码做一次必要debug CLI编译和隔离root激活负控；
这不触碰已停止C23 App或产品profile，不是重复release producer。
774c982集成quality3的所有执行场景、lint、ignored分类及输入稳定性PASS，但新增setup
测试断言的rustfmt格式FAIL；保留失败，仅格式修正后重新冻结并运行最终集成检查。
phase46参考源码与后续冻结源码的该项差异仅为test断言格式，不影响reader7产品逻辑。
Windows C盘最新空闲60,633,088字节；O程序树566,629,898字节。现有删除授权不覆盖O，
不得直接删除。最终包准备后需按实际安装/外部stage峰值形成具体空间方案；profiles/keys保留。
用户最终要求的安装、首次设置、真实三能力、拒绝/撤销/重配对、进程退出重开、Linux最新
安装与最后Logo刷新均保持原门槛。交付未完成，Stable NO-GO。
