# Styx 交付困难的架构核查

2026-11-08 · 审查基线 `fd41fcefa3ea24f670eede6983105b2e1c762d35`（C23）。

> 后续更新：D0四项[边界决策](DELIVERY-BOUNDARY-DECISIONS.md)已选定，
> 原文中的“待D0”是审查时状态；实现、参考场景、最终候选和真机验收仍未完成。
> 交付计划已调整为先有界实现/参考，再冻结候选并执行完整旅程。

## 结论

**存在实质性的产品合同和局部架构债务。继续逐个症状追加判断，会继续消耗时间。**
目前证据支持保留四个 crate、Rust Core、Gateway/Host 分工和既有执行器，针对
公开接口、配对生命周期、安装/Runtime 生命周期、Mac Source 生命周期做有界收敛。
没有证据要求整体重写。构建速度不是当前主要瓶颈。

前期并非没有设计文档：SPEC/CONTRACTS 规定了依赖方向、单写者、独立故障域和
未知结果政策。问题在于一些用户旅程没有落实为贯穿 Core、存储、协议、GUI、
安装的完整状态转换；后续用局部适配补齐，形成了重复表示和边界不一致。
我的协调失误和验收推进方式也造成了独立的浪费，不能全部归因于源码。

## 审查范围与证据约束

- 沿实际失败链路审查：首次设置/Tunnel保存、配对/拒绝/claim、原生GUI到Core、
  signed Runtime选择与App替换、Computer Source初始化、Host结果投递、退出/恢复。
- 静态核查四个 crate 的依赖；结合真实 C23/C22 收据、已有质量检查与提交历史。
  这是重点链路的架构审查，未声称逐行审过全仓或完成全面安全审计。
- 区分“源码机制已证实”“真实失败已证实但完整触发原因未定位”“维护风险”。
  不能用文件长度判定质量，也不能用测试数量证明产品路径完整。
- 工作区有我刚开始的 R2 未完成草稿。有关基线结论用 `git show HEAD:<path>`
  复核，不能把草稿新增状态或编译错误算成 C23 历史缺陷。
- 用户提出先核查后，产品实现、构建、安装停止推进；只修改审查与计划文档。

## 已成立的架构基础

1. 依赖实际为 `styx → styx-runtime → styx-core → styx-contracts`，runtime也可引用
   contracts；Core没有依赖Tokio或平台IO库。`src/ci/rust-quality.py`还检查依赖及
   明显的Core IO导入，且明确其词法检查不是形式化证明。
2. Core的权限、操作许可、持久确认采用受信构造的类型和authority brand；普通
   JSON不是授权证明。Gateway/Host/存储适配没有被另一个JS管理核心替代。
3. Rustls、官方MCP SDK、Codex、Cua、Playwright等已有边界和固定输入；不需要
   为解决当前问题重写执行器或更换语言。
4. 单写者、签名闭包、原进程句柄、drain与实际退出的分离是有价值的约束。
   Windows对不安全制品路径ACL的拒绝不应为了省事被移除。
5. 质量收据明确写出 `native_platform_acceptance=NOT_RUN`、未打包/未部署以及
   `final_release_gate=false`，检查器没有把本地测试冒充真机交付。

## 关键发现

### A1 · 高：公开工具合同与实际支持子集不一致【已证实】

证据：

- [PUBLIC-MCP-V1.json](PUBLIC-MCP-V1.json) 的 `get_window_state` 声明了
  `full_output`、`query`、`since`等字段，`timeout_ms`上限120000；描述前缀虽然
  解释分开读树/截图，schema仍保留不支持的参数。
- [ax_target.rs](../../crates/styx-runtime/src/providers/cua/ax_target.rs) 的
  `AxReadRequest::classify`只接受固定8字段，额外字段返回Unsupported，timeout上限2000。
- [window_capture.rs](../../crates/styx-runtime/src/providers/cua/window_capture.rs)
  另有更窄白名单和截图尺寸/timeout上限。
- 本次用Python JSON Schema验证了含`full_output:true`的精确读树参数：公开schema
  判定合法；实际账号请求却返回CapabilityUnsupported/NotDispatched，去掉参数才成功。

因果：调用方按合法schema组装参数，仍在后面被静态形状拒绝。文案前缀不能补救
schema矛盾。之前我把这次失败仅归为自己误传参数，归因不完整。

处理：把**Styx对外支持合同**与**上游SDK完整catalog**分开。保留上游catalog用于
固定依赖验证，对外发布真实支持的字段/分支/上下界；不用放松native准入来迁就schema。
增加“公开schema接受的代表性静态形状能进入相应支持分支”的跨边界合同检查。
权限、目标过期等动态拒绝另行验证，不混为schema不支持。

### A2 · 高：配对缺少贯穿全链路的终结拒绝状态【已证实】

基线的 [enrollment.rs](../../crates/styx-contracts/src/enrollment.rs) 中只有
Pending/Approved/Revoked，没有Rejected；Mutation有Approve/Revoke，没有Reject。
[service.rs](../../crates/styx-runtime/src/enrollment/service.rs) 没有对应拒绝路由。
[ProductPresentation.swift](../../host/macos/product-ui/ProductPresentation.swift)
的`confirmPendingIdentity`在非首个按钮时直接return。

实测：双方CA、设备ID/指纹/验证码一致，请求一次；负向按钮一次仅关闭比较框，
同请求仍pending，批准0。Windows仍awaiting_approval，账号仅有Mac。
收据：`candidate-23/resumed-account-acceptance/pair-negative-known-native-gap.json`。

因果：这是**业务状态设计/贯通缺口**，单改按钮或提示不能完成需求。
拒绝还必须覆盖持久化、服务重启、原claim的终态、无凭据/无授权以及新邀请重新申请。

处理：先冻结完整转换表和原request/identity绑定；拒绝不得冒充已注册设备撤销，
不得永久废弃设备key，也不得允许旧claim因新请求批准而复活。明确取消比较与拒绝请求
两个不同动作。持久格式扩展同时处理reader兼容门槛。

### A3 · 高：默认Mac安装拓扑与持久Runtime选择不协调【源码与安装失败相互印证】

- [build-macos-native-runtime.mjs](../../host/build-macos-native-runtime.mjs) 把payload
  放在`Contents/Resources/native`。
- [ProductOwnedCore.swift](../../host/macos/product-ui/ProductOwnedCore.swift) 的`open`
  从当前`/Applications/Styx.app`验证并生成这个bundle内payload的selection。
- [release/mod.rs](../../crates/styx-runtime/src/release/mod.rs) 的`selection_metadata`
  包含payload绝对路径、root文件身份、manifest hash；后续按原选择核实。
- C23保留旧profile启动时仍选中C22绑定，在App原路径已被替换后无法通过核验；
  后来靠明确授权归档旧profile并重新设置继续。这是恢复手段，不是升级设计闭合。

系统已有 [release/stage.rs](../../crates/styx-runtime/src/release/stage.rs) 的不可变版本
容器，也有 [ProductPlatformUpdate.swift](../../host/macos/product-ui/ProductPlatformUpdate.swift)
和 [maintenance.rs](../../crates/styx-runtime/src/app/maintenance.rs) 的“Runtime独立于App”
检查。因此不是完全没有方案；**默认首设/普通DMG替换与已有方案没有形成一条完整产品路径**。

处理：先统一“App外不可变Runtime版本、profile选中的版本、当前App控制面、原生权限
载体”的关系。优先复用已有stage/update能力；核实正常Quit后替换App再恢复profile。
不盲改保存的hash/路径，不因旧选择失效而自动清profile，也不增加另一套installer。
fresh Rust安装与legacy迁移的区别不能用来隐藏Rust版本间正常安装路径的矛盾。

### A4 · 高：Mac Source在初始化完成前已走严格围栏，恢复粒度过大【机制确认；R1精确触发点未闭合】

链路：

1. [desktop_source_macos.rs](../../crates/styx-runtime/src/host/coordinator/desktop_source_macos.rs)
   的`start`在首次SDK读之前调用`observe_current`。
2. [macos.rs](../../crates/styx-runtime/src/providers/cua/macos.rs) 的
   `observe_windows_mode(initial=true)`也先调用严格的`observe_current_at`，随后才进入
   `observe_initial_native`和双FD的原子资格确认。
3. [macos_native_observation.rs](../../crates/styx-runtime/src/providers/cua/macos_native_observation.rs)
   严格比较包含seed，而初始化兼容规则允许同一console来源下的seed变化。
4. 失败会fence；[computer_startup.rs](../../crates/styx-runtime/src/foreground/computer_startup.rs)
   一次初始化失败后发布Unavailable。本次通过整个App正常Quit/reopen才恢复。

Apple公开XNU的`updateConsoleUsers`在收到用户表时也推进seed，而非只在用户表内容
改变时推进。故seed变化本身不能单独证明换了登录会话。
[Apple XNU原始源码](https://raw.githubusercontent.com/apple-oss-distributions/xnu/refs/heads/main/iokit/Kernel/IOService.cpp)
（核实`publish = (consoleUsers || ...)`及`OSIncrementAtomic`）。这不等于已证明PilotMac
本次为什么推进seed，也不授权忽略锁屏/身份/ABA事实。

因果：尚未完成资格确认的来源已经被部分路径按“已激活来源”严格处理；“允许一次
初始化资格确认”被散布在多个bool和函数分支中。可能在走到允许的资格路径前就被拒。
C23真实闭合诊断是`console_match/console_epoch_changed`，21ms、未到deadline；完整
具体触发调用仍需参考场景定位，不能现在声称一行修改已经修复R1。

处理：明确`Unqualified → Qualifying → Ready → Fenced/Ended`；把首次资格确认覆盖的
边界说清，在Ready前不暴露目标/输入authority。Ready后的严格失效保持。来源恢复必须
先结算旧来源并使旧target失效，不自动重放动作。先验证参考场景，不继续加timeout。

### A5 · 中高：App编排集中、状态投影与展示语义易混淆【维护风险与部分误导已证实】

[app.rs](../../crates/styx-runtime/src/app.rs) 的HostApp同时持有service、runtime更新、
gateway、enrollment的JSON、运行Host、cleanup、retained error、unknown、quit ticket等状态。
模块虽已分文件，`available_for`和各操作仍横跨多个故障域；错误/角色/readiness通过
字符串和Value重复解释。

[ProductSettingsViews.swift](../../host/macos/product-ui/ProductSettingsViews.swift) 的
Computers页把“native模式且gateway=null”也解释为“由管理电脑管理”；缺少Gateway
并不能独立证明这台Mac是已加入的Host。原先保留profile启动失败时的误导提示与此一致。
Windows有独立的判断/文案，跨端容易再分叉。

处理：先建立Core输出的明确角色、配置、连接、能力就绪和错误域投影；GUI只展示和
触发支持操作。局部抽出join lifecycle、runtime lifecycle、desktop readiness，避免
按按钮临时加bool。保留单一writer，不把这些状态迁到前端。
目前不证明所有unknown围栏都错误，不应全局取消它们。

### A6 · 中高：结果语义在多层重新编码，容易出现跨层漏洞【有真实历史回归】

Native reply → CuaEvidence → Core OperationState → Host dispatch字符串/可选payload
→ Gateway再匹配状态，是多个容易不一致的表示。
参见 [computer.rs](../../crates/styx-runtime/src/host/protocol/computer.rs)、
[backend_computer.rs](../../crates/styx-runtime/src/gateway/paired/backend_computer.rs)。

C22曾把已知拒绝读（Failed/NotDispatched）送进只允许Succeeded的读数据授权，
再投射为existing_no_replay/Unknown。fd41已修复此处，C23实际同worker读恢复通过；
这个修复有效，但也揭示边界映射脆弱。

处理：标准化类型化的完成结果与可交付数据规则，尽早归一化上游私有回复；保留
ACK/NotDispatched/Unknown的差别。覆盖完整Host/Gateway路径，不能仅验证SDK解码。

### A7 · 中高：质量检查没有覆盖当前GUI旅程的完整合同【工程设计缺口】

[rust-quality.py](../../ci/rust-quality.py) 是本地基础检查，不是完整GUI交付闸门；
已有真实TLS、持久化、Node独立crypto、真实Codex和Host场景，不能一概说成mock。
但它们没有使“GUI终结拒绝”“默认App替换后保留profile”“公开合法参数实际可接收”
成为这轮发布的必要出口。C23质量PASS与这些真机缺口可以同时成立。

处理：把用户旅程映射成一张需求→状态→入口→独立效果→恢复→证据矩阵；先检查
必需入口是否存在，再花成本装包。Mac先做受影响的真实冷启动入口验证，再启动剩余
候选生产。新增少量有独立断言来源的跨层场景，不追求更多断言数。

### A8 · 高（执行流程）：根代理协调成本被放大【已证实，不能归咎源码】

首份邀请在Windows helper/原生路径尚未即时就绪时创建；过期前输入/审阅/请求均0。
第二轮我又把“预备不输入私有链接”写成“不做GUI输入”，使owner停在General页。
多次按细小步骤结束/恢复CLI、重新审阅历史和检查收据，增加了等待。

源码/构建耗时与这些成本不同：C23质量125.66s，Mac Core84.27s、Windows Core215.36s；
前述多小时延迟不能说成编译慢。早期Darwin退出观察器的错误flag也属于验收工具错误，
已废弃相关零退出码声明，不是产品退出保证。

处理：设备owner保持一段完整旅程的职责与上下文；用明确检查点交接，不为普通导航
再问权限；只有两端实际READY才启动邀请。每阶段一个简短RESULT和证据索引，底层
收据保留但不让它们代替可见状态。沿用单写者、未知不重放和既有授权边界。

## 后续决策：先收敛四个边界，再实现和验收

下一步增加设计检查点D0。D0出口是四份简短、可审查的状态/合同决策：

| 边界 | 必须回答 | 通过门槛 |
| --- | --- | --- |
| 对外工具合同 | Styx到底支持哪些静态参数/分支？与native SDK schema如何分离？ | 代表性合法公开参数与实际支持分支一致，未知参数明确拒绝 |
| 配对完整生命周期 | 取消、拒绝、过期、批准、claim、撤销、重配对如何持久化和恢复？ | 状态表覆盖原claim不能复活、拒绝不发凭据、新邀请可重新申请、reader门槛 |
| App/Runtime安装模型 | 哪些文件可被替换，profile绑定哪个不可变版本，何时切换？ | 正常Quit/替换App/原profile重开路径可验证，不靠清配置继续 |
| Mac来源生命周期 | 哪个时刻完成资格确认，之后如何失效，恢复的最小范围是什么？ | 具体R1参考场景、有效/无效身份变化、锁屏/ABA、旧target与Unknown边界明确 |

这些局部设计完成后，优先复用已存在的stage/update、Core持久化和provider资源管理。
不新增总管服务、不重写执行器、不新建第二个状态权威。对HostApp拆分只做上述路径
所需的职责整理；不把本次审查扩成全仓清理或全面重构。

D0按90分钟时间盒执行：形成上述四项决策、已有实现复用点、仍未知的事实、必要场景
及新的分项工时。证据不足的项明确保留未知，并说明对实现/验收的影响，不把时间盒
结束当作设计通过。D0完成前不继续产品实现、候选构建或安装。

然后按“跨层最小场景 → 有界实现 → affected crate增量检查 → 原生参考 → 一次候选
检查/生产 → 完整真机旅程”推进。每个设计项明确旧行为/新行为/失败边界/验证方式，
完成前不再仅凭局部测试产下一候选。交付plan的P1–P7保留，D0作为实现前置。

## 当前草稿与估算

- 未完成R2草稿保存在当前工作区，另有
  `/tmp/styx-r2-incomplete-before-architecture-review.patch`；不提交、不打包、不安装。
- Core enrollment策略/恢复场景在该草稿下通过，4.00s；runtime增量check遇到草稿
  闭包生命周期E0373。这是当前未完成编辑的状态，不是C23基线编译失败。
- 拒绝持久格式新增variant后的reader兼容门槛、GUI与加入端完整收口尚未完成；
  不能因为Core测试通过就继续包装该草稿。
- 先前4–8小时估计只考虑补R1/R2，未包含此次确认的接口和安装模型收敛，已撤回。
  先以D0的四项决策与具体参考场景收紧工作范围，再发布分项工时；暂不承诺完成时刻。
- 本审查阶段没有新增候选、产品构建、安装、权限变化或未知操作重放。
  交付goal仍active，当前阶段为架构检查点；**交付未完成，Stable NO-GO**。

## 本次六领域变化

- **Product**：确认工具参数合同与终结拒绝两个完整性缺口；首次设置、最终三平台旅程仍未闭合。
- **Architecture**：保留已成立的四层依赖，新增四个有界设计检查点，停止按局部症状直接产候选。
- **Integration**：审查以fd41基线复核；R2未完成草稿完整保留，审查期间产品diff未变化。
- **Release**：无新候选、安装或签名动作；普通Mac App替换与Runtime选择的协调纳入设计门槛。
- **Reliability**：给出公开schema合法但实际静态拒绝的反例；区分已证实机制、真实失败与未证明根因。
- **Decision**：goal保持active；先D0四项决策，再有界实现/原生参考/冻结与最终验收；原工时估算撤回。
