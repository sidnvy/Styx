# Styx Rust Core Rewrite · execution baseline

2026-10-24 · Owner-directed implementation choice: **Rust is the final Styx core runtime**.

状态（2026-10-26）：Rust 是 Styx 自有核心的唯一目标实现，goal active；尚未完成三平台产品交付。`ab97cc8` 同源 Linux 原签候选的 Exec、headless Browser、Cua 实际效果/拒绝/清理场景已通过；Windows 原签 Runtime 与未做 Authenticode 的原生 App 已构建，配对/Exec 有实际证据，最终完整生命周期仍未通过；Mac ARM 原证书 App 已完成签包，尚未安装或运行。Mac Intel 正在接通原机编译→原签名机签发→原机校验，保留原身份，不安装未经授权的 Rosetta。新增 Windows Browser 已实现，`5beac76` 整合字节本地完整门禁通过，NAB5 原生编译发现的两个接点已在 `76b7c61` 修复，原生场景尚待验收。这些状态不能推导出跨平台三能力、同身份迁移、JS 管理层退役、安装/更新/回滚或最终账号验收已完成。`src/` 是唯一产品源码，已有成熟 Codex/Cua/Playwright 与必要原生桥继续复用。精确源码、安装包、进程及效果证据以外部 Owner Control Report 和不可变 receipts 为准，旧包结果不自动继承给新源码。行为/旧格式参考基线仍为 `44cf1470e6b0cfdfd2c2372e54e84ebd279c59c3`。

阅读顺序：

1. [SPEC.md](SPEC.md)：范围、架构、责任、平台、迁移、工程与发布完成定义。
2. [CONTRACTS.md](CONTRACTS.md)：身份、能力、Session、Operation、IPC、状态和包格式合同。
3. [EXECUTION-PLAN.md](EXECUTION-PLAN.md)：里程碑、并行waves、文件/设备所有权和集成纪律。
4. [WORK-ITEMS.json](WORK-ITEMS.json)：可领取任务、依赖、交付与验收条件。
5. [ACCEPTANCE.json](ACCEPTANCE.json)：威胁/触发/独立oracle/恢复/证据，不以assertion计数。
6. [DECISIONS.md](DECISIONS.md)：已决定事项及必须用实证关闭的技术决策。
7. [REFERENCES.md](REFERENCES.md)：官方技术资料及查询边界。

本目录是当前重写的唯一计划入口。`architecture-boundaries.md`保留历史审查，但其中“继续Node核心、不做Rust”的技术选择已由本次用户决定取代。原设备身份、publisher、配对、权限、未知结果不重放和worktree保护继续有效。

执行起点是R00/R01/R02，不要求再问一次是否采用Rust。涉及新的产品范围、信任模型、不可逆状态迁移、长期保存账户密码或降低发布门槛时，必须形成具体决策及影响后再推进。普通实现细节由任务owner处理，不把每个小修改交给用户裁决。
