# Styx Rust Core Rewrite · execution baseline

2026-10-24 · Owner-directed implementation choice: **Rust is the final Styx core runtime**.

状态（2026-10-25）：Rust 是 Styx 自有核心的唯一目标实现，goal 仍 active。已签名的 Linux 内部候选仍为 `a8572d2` / `.8`，其真实 TLS/Exec/Browser 与原身份迁移证据不自动继承给新源码。已集成 `1021fb2` 完成 Rust 1.97.1、目标绑定的原生 AX 写入及 Windows C07/Fresh Host 接线：完整本地门禁、Windows 实际 C07 提交/原事务恢复、Mac 编译检查通过；Windows 外层 controller 的 SDK 辅助进程清理失败另行保留，不能统称整批全绿。普通 Windows fresh join/Host/Exec 新候选流程尚未验收。当前增量补齐 Darwin 可写 journal、原生 Mac 根身份与同一 C07 coordinator（[ADR-033](ADR-033-MACOS-NATIVE-JOURNAL.md)），不改 App/TCC 或原 publisher/设备身份。三平台同 SHA 签包、安装、完整生命周期及迁移验收尚未完成。具体实现见 [IMPLEMENTATION.md](IMPLEMENTATION.md)，逐次结果以外部 Owner Control Report 和不可变 receipts 为准；测试数量不表示重写完成度。行为/旧格式参考基线仍为 `44cf1470e6b0cfdfd2c2372e54e84ebd279c59c3`。

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
