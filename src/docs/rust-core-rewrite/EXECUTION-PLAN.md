# Rust rewrite execution plan

执行依据：[SPEC](SPEC.md)、[CONTRACTS](CONTRACTS.md)、[WORK-ITEMS](WORK-ITEMS.json)、[ACCEPTANCE](ACCEPTANCE.json)。本轮只产计划。下一轮直接从R00开始，不再讨论是否采用Rust；发现新信任/产品范围决策时才提交具体影响。

## 1. Milestones — deliver vertical slices

| Milestone | 工作 | Exit gate |
| --- | --- | --- |
| M0 Contract + feasibility | R00–R03并行：功能/兼容清单、工具链/协议spike、平台manager/IPC身份、独立oracle与性能baseline | contract v1、依赖锁定方案、platform lifetime/identity ADR、场景目录；明确阻塞，不开始盲目翻译JS |
| M1 Native foundation | R04–R08：四crate、typed codec、私有存储/lease、Operation/admission、Control IPC | Linux本地可运行styx status/doctor，raw状态只读不漂移、IPC负控制有效，仍无生产切换 |
| M2 First real Rust path | R09/R10/R13：Rust CLI/Host/Exec→真实Codex→旧受信Gateway | 实际命令、流/PTY、取消、断连不重放及进程退出，旧identity不变；不是echo假实现 |
| M3 Complete runtime paths | R11/R12与R14–R19并行：RustGateway/pairing；Session+三平台桥；Cua与Browser | Rust↔Rust真实三能力；旧新兼容适用范围明确；缺session或worker崩溃不拖其他lane |
| M4 Management + migration | R20–R27及R38：计划/事务、manager、UI client、bootstrap/包、cutover、故障与互操作 | 隔离profile完整旧→新及rollback证明，单writer，所有关键写入阶段可协调 |
| M5 One final source | R28退役JS核心→R29冻结同SHA四目标候选 | active入口无JS核心；hash/签名/闭包/源码可追溯。旧历史ref保留，无新vnext主线 |
| M6 Native acceptance | R30–R35分设备批量旅程、迁移、性能、安全独立审查，随后R37真实账号 | 声明支持范围的必需场景全部闭合，无伪PASS；Stable正式分发门槛另查 |
| M7 Release handoff | R36 | Owner报告、证据索引、操作/回滚手册、剩余项与发布分级 |

关键路径是contract→身份/ownership/格式→真实Exec→管理/切换→最终包→原生验收。Desktop与Browser可以并行，但不能先拖住最早Exec闭环。R02先交peer/平台事实，服务principal的必要owner决定由R38关闭，R22/persistent cutover等待R38；签名/服务身份阻塞只限制相关切换和发布，不让所有代码等待设备或云CI。

## 2. Parallel waves with four active slots

并行角色比固定agent名字稳定。当前最多4个active槽：集成者+3个worker；不为计划中的所有工作流同时spawn。现有intel_fixtures/package_prep/windows_scene可复用和重新分配，任务结束先交还路径/设备。

| Wave | 集成者 | Worker A | Worker B | Worker C |
| --- | --- | --- | --- | --- |
| A | R00合同/功能盘点 | R01依赖/SDK | R02平台manager/IPC | R03oracle/性能方法 |
| B | R04 workspace/locks；R07Core | R05codec | R06store/lease | IPC设计/负控制准备；R08待依赖满足 |
| C | 接口整合、R11Gateway | R09Exec→R10Host | R12pairing/crypto | R14Session→R15Linux |
| D | R20/R21管理事务 | R18Cua | R19Browser | R16Windows→R17Mac，或以设备可用性轮换 |
| E | R26cutover | R22manager | R23native clients | R24bootstrap→R25packaging |
| F | R27故障/兼容审查→R28退役→R29freeze | 独立审查/反例 | 平台closure | 来源/SBOM/签名准备 |
| G | R33/R35协调与报告 | R30Linux | R31Windows | R32Mac ARM/x64 |
| H | R37账号执行→R36最终门槛 | R34性能/soak分设备预约 | 独立review/修复复核 | 设备owner做必要定点复验 |

这是资源排程示意，不是全局barrier：任何依赖已满足且路径/设备lease空闲的任务可立即领取，避免等待整个wave结束。实际硬依赖以JSON DAG为准；不能因为某wave排了任务就忽略未满足的依赖。同一worker可串行负责多个模块，公共合同修改必须先回集成者。测试/审查角色与实现作者轮换，关键oracle尽量由另一worker核对。

## 3. File ownership and shared resources

- 集成者独占根Cargo.toml/Cargo.lock/rust-toolchain、crate根mod注册、共享contract变更、AGENTS、候选版本和Git集成操作。
- A/B/C按work item中`paths`领取互斥子目录。两项任务同路径不能并写；先lease后写，不能因“只是一个小改动”越界。
- 每任务记录base SHA、contract revision、owner、paths、device、depends、预期产物。完成时交付代码diff、有关测试/场景、已知缺陷、进程/临时文件清理证据。
- 所有worker使用已冻结Cargo.lock并`--locked`；新依赖向集成者提案，不各自重写lock。每任务可用外部CARGO_TARGET_DIR缓存，统一保留/清理owner，缓存不是worktree。
- 单元/contract开发可在dirty assigned tree运行，但不能称final质量gate；冻结时源码干净、tasks写入暂停，再跑最终门禁。

## 4. Worktree discipline — zero by default

基线共有58个worktree，其中大量属于保留输入、dirty/外部线程或运行路径。禁止为了agent/task/build/candidate再创建worktree。

- 使用现有`styx-capability-lifecycle`作为本阶段staging checkout；执行启动时可在同checkout建立一个Rust epic分支，保留旧ref，不增加checkout。
- 现有`styx-develop`为唯一集成checkout，只有集成者fast-forward。共享checkout内worker不自行checkout/commit/reset/clean/stash/rebase/merge。
- 新worktree只有真实分支隔离冲突时才允许：先登记理由、owner、具体路径、HEAD/ref、输入和清理条件；默认同时新增上限0，例外绝不能自动累积。
- 已有dirty、外部chat-browser thread、活进程路径、签名/依赖母目录均不征用。任何清理先refs备份、dirty/untracked/ignored/入向link/进程核对，禁止force删除。
- immutable `git archive`导出到设备build scratch是构建输入，不是可自由贴补丁的另一源码主线。设备不得修改产品代码再回灌“已验收”。

## 5. Cross-thread handoff

跨thread协作依赖共享task/contract/evidence，不依赖根聊天记忆。交接文件至少包含：task ID、base SHA、contract hash、owned paths/device、已完成/未完成、命令/结果/receipt、运行进程、不得重放项和下一步。

外部thread默认以只读审查或proposal patch交付；必须声明base和文件allowlist。集成者先核diff/依赖/合同及`git apply --check`再接收，不能自动合入未知分支或覆盖另一线程活文件。跨thread不能同时操作同一设备；没有可用通信工具时使用明确文件交接与root协调，不虚构已通知。

## 6. Device leases

| Surface | 唯一owner / scope | 限制 |
| --- | --- | --- |
| 本地Arch/Hyprland | Linux场景owner | 不重启、不注销/重启当前compositor，不碰用户应用；生命周期破坏场景用专用嵌套或测试session，不把它冒充物理prelogin |
| ssh nab5 | Windows owner | 安装、GUI、服务、SDK和重启属同一lease；保留原Pair/Startup；独立profile不能替原Pair验收 |
| ssh pho | Mac x64 owner | 安装、native权限/GUI和编译同一owner；不能以x64编译替ARM native |
| 原ARM/签名设备（可达时） | Mac owner按预约接管 | 先确认原identity与在线状态；当前签名交互阻塞保留，不导出key/换身份/改ACL绕过；不可达记BLOCKED |
| Gateway approval | 集成者指定一个owner | 仅协调既有批准/撤销事务，不让不同agent争同一record generation |

piermini绝对禁止。任何真实重启/注销/权限撤销，执行前必须核实针对该设备/场景的授权与恢复责任；当前Workstation约束优先。能做的非破坏开发不等待这些门槛，但报告不能假装native PASS。

## 7. Integration cadence and evidence

以可审纵向切片合入，不按agent交付一堆无法运行的孤岛。各切片满足自身exit gate即可集成，不每提交都重跑全部旧测试。定点回归通过后继续；新失败/接口变更才扩大检查。

候选冻结前：任务owner交回所有lease、源码clean、contract/锁/外部inputs冻结；一次完整local gate；同SHA所有包；atomic回收+hash；按每设备完整用户旅程批量执行。若冻结后产品字节改变，发新候选，记录哪些场景受影响；不复用旧包标签，也不无理由重跑未变场景。

每轮报告只写增量：Product范围；Architecture新增责任/协议；Integration SHA/dirty/lease；Release各平台build/sign/install/accept；Reliability真实失败与恢复；Decision需owner决定的具体事项。测试数量只作诊断附录，不计算完成百分比。

## 8. Start and stop conditions

启动：复核AGENTS/status/44cf147基线与现有spec commit，保留工作；R00–R03分配路径和设备lease。无需另问Rust是否确定。

停止依赖工作而继续其他工作：未冻结contract、未证明IPC身份、未知writer/事务、签名拒绝、会改变账户/信任权限、候选hash不一致。遇到这些条件保留证据，不能用mock或修改期望绕过。

结束：R36依赖全部满足，旧JS核心退役，明确Preview/Stable范围和未关闭门槛。缺任一required native/账号条件时交付可用切片但重写整体仍INCOMPLETE，不以token/时间压力标完成。
