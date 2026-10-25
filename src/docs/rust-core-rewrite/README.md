# Styx Rust Core Rewrite · execution baseline

2026-10-24 · Owner-directed implementation choice: **Rust is the final Styx core runtime**.

状态（2026-10-25）：Rust 是 Styx 自有核心的唯一目标实现，goal 仍 active。已接受集成基线 `e321914c3eb9284be561a391e1f327c20fab478b` 已有同身份迁移/原凭据退役及普通前台恢复证据、Windows Headless 配对/Exec/跨 owner 拒绝/真实进程收尾证据，以及同 SHA Linux 签名内部候选包；Mac 目前只完成该 SHA 编译检查。它们不等于已部署、统一三平台安装包或完整平台验收。当前 R36 补齐全新原生 Gateway 初始化，见 [ADR-030](ADR-030-FRESH-NATIVE-GATEWAY.md)；新代码不能继承旧 SHA 的实际结果。具体实现与历史切片见 [IMPLEMENTATION.md](IMPLEMENTATION.md)，逐次执行结论保存在外部 Owner Control Report/不可变 receipts。行为/旧格式参考基线仍为 `44cf1470e6b0cfdfd2c2372e54e84ebd279c59c3`。测试计数不作为重写完成度。

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
