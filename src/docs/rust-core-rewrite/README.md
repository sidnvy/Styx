# Styx Rust Core Rewrite · execution baseline

2026-10-24 · Owner-directed implementation choice: **Rust is the final Styx core runtime**.

状态：owner已于2026-10-24授权执行，goal为active。四crate基础实现、精确legacy codec、独立Core准入/操作ledger、crypto互通和Linux只读私有store正在落地；尚未完成Rust Host/Gateway、跨平台包或真实迁移验收。实现状态与计划状态分开，见[IMPLEMENTATION.md](IMPLEMENTATION.md)。行为/迁移参考基线为 `44cf1470e6b0cfdfd2c2372e54e84ebd279c59c3`；既有date24.1安装包仍属于`8e4e645`，不包含后续修复。旧测试总数不作为Rust重写完成度。

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
