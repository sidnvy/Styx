# Styx Rust Core Rewrite · execution baseline

2026-10-24 · Owner-directed implementation choice: **Rust is the final Styx core runtime**.

状态（2026-10-26）：Rust 是 Styx 自有核心的唯一目标实现，goal active，三平台产品交付尚未完成。Linux 已有原签候选、真实 Exec/headless Browser 和同身份更新/回滚证据；Mac x64 原签 App 已安装到 pho，ARM Swift 修复已原机编译；Windows 三能力原签 Runtime 和原生开发 App 已构建，最新完整业务场景尚未通过，原生 Gateway 启动超时仍待解决。当前收敛正在补齐 Mac 常驻服务的安装准备、首次启动和停止链路；编译及合同测试通过不能替代系统注册、实际效果或注销恢复验收。`src/` 是唯一产品源码，成熟 Codex/Cua/Playwright 与必要原生桥继续复用。最终候选必须同一源码提交；已构建、已部署和已验收的证据分别记录于 Owner Control Report 和不可变 receipts，旧包结论不继承给新源码。Stable NO-GO；行为/旧格式参考基线仍为 `44cf1470e6b0cfdfd2c2372e54e84ebd279c59c3`。

> **Scope override (2026-10-27):** Legacy migration is out of the release scope; devices are freshly installed and re-paired. [REDUCED-SCOPE.md](REDUCED-SCOPE.md) defines v1, what is cut or deferred, and the execution sequence. It overrides conflicting parts of the documents below.

Rust CLI first run: [CLI-ONBOARDING.md](CLI-ONBOARDING.md) documents `styx setup`, `styx invite`, `styx status`, the answers schema, interruption behavior and the current validation gaps.

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
