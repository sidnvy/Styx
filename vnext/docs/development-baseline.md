# 共享开发基线

Styx 的公共集成分支是 `develop`。功能分支从 `develop` 建立，评审和验证后回到 `develop`；`main` 只接收经过评审、具有交付范围和验证记录的发布基线。平台目录或一台电脑上的开发副本不是另一套公共 Core。

## 日常开发与集成

1. 先确认 `develop` 的来源 revision、干净状态和当前集成记录，再建立 `feature/...` 分支。明确本次行为、平台范围与验收边界。
2. 公共 Core、权威配置、API、Exec / Computer Use / Browser 三项能力的选择与状态、会话和资源归属在同一分支体系内修改。平台 UI 和原生适配调用这些契约，不维护第二份角色配置，也不各自定义配对、会话或恢复规则。
3. 平台原生实现可以独立开发和构建；共享行为变化须回到 `develop`，由相关平台核对调用方与兼容性。某项能力受平台、权限或会话限制时明确报告，不能用另一能力的成功代替，也不自动重放不确定操作。
4. 合并前更新到受审查的 `develop`，检查差异并运行受影响的契约、集成和平台检查。涉及共享配置、签名闭包或生命周期时同时核对其他平台；文案修改不因此触发无关的全平台重建。
5. 从明确 revision 和完整输入清单构建候选。记录实际产物及未覆盖门槛，再决定是否把该候选提升为 `main` 发布基线。合并、发布文件和部署到已有设备是独立动作。

## 每个平台都要记录的来源

每次交付记录源码 revision；若混合来源，分别列出公共 Core、平台 UI/适配的 revision 和经过审查的文件差异。还需保留实际 source closure（输入文件清单与哈希）、依赖锁、工具链/原生组件版本与哈希、签名或包内一致性检查、产物哈希和检查 receipt。`HEAD` 相同不证明本机未提交文件、漏拷贝依赖或既有安装与该产物相同。

临时隔离源码回灌先核对来源和差异，再应用到明确的测试副本。未确认的远端执行结果不算完成；不能覆盖另一线程未提交工作，或顺带替换已装 App、后台任务、服务、权限和私有状态。

## 验证分层

| 门槛 | 可证明的范围 |
| --- | --- |
| 源码与契约测试 | 所记录输入下的行为、兼容性和失败边界；fixture 不冒充原生运行 |
| 平台原生检查 | 对应产物的真实进程、TLS、工具、控件、生命周期及独立读回；SSH Session 0 不证明交互桌面 Cua |
| 目标账号验收 | 所选 ChatGPT 接入方式、实际目标聊天、真实工具证据与用户确认；本机工具成功不能代替 |
| 发行与部署 | 受审查的来源闭包、发行信任、安装/更新范围和实际部署记录；工程候选不等于统一发行 |

分别记录 `PASS`、`BLOCKED`、`NOT RUN` 和来源版本。原始失败及后续修复证据并存，不把旧轮次改成通过，也不把某平台的历史原生证明移给新构建。

## 2026-10-22 整合进度

本地 `develop` 已完成真实 merge：`c4aafad5ba46c098b81498b58619cb8b2b5e1c64`，parents 为 `4eaaac1` 和原始 Mac 历史 `d2eca11`。相对 Windows / Linux 基线仅合入 8 个 Mac UI 文件（319 行新增、143 行删除）；涉及的 Mac Swift 文件逐文件与 `d2eca11` 一致，`gateway`、`onboarding`、`packages`、`plugin` 的共享 Core 文件保持 `4eaaac1`。

| 来源 | 已知状态 |
| --- | --- |
| Windows `4eaaac1` | 包含 `1b23221` 公共 Core；后两项提交为 Windows 启动呈现修改 |
| Linux `1b23221` | 与上述 Windows 来源的公共 Core 一致；原生适配和产物闭包分别记录 |
| macOS UI `d2eca11` | 原始历史和最新 UI 已合入本地 `develop`；Mac 隔离副本的公共 Core 仍为旧 `d0f41e6`，共享源码回灌待完成 |

`ae86337` 已实现同一 Gateway 的附加精确 TLS 入口、恢复与配对窗口关闭；`1b23221` 修正受限入口的公开 join 预检。真实 Linux / Windows 附加入口验收见任务证据 `outputs/cross-platform-ready-20261022/delivery.json`：Gateway 9 项、Windows 6 项通过，保留原 localhost MCP 会话，真实 Exec / Edge 和关闭窗口后的重连通过。它不证明 Mac 新 UI 已接线或目标 ChatGPT 账号已验收。详见[附加入口契约](add-computer-network-entry.md)和[Mac 来源记录](macos-cross-platform-sync-20261022.md)。

已用 `git cherry develop` 逐一核对 11 条相关平台、Browser 与验收分支，没有未回收补丁，原分支保留。历史 cherry-pick 以补丁等价核对；未成为 ancestor 本身不表示漏合，也不以 `ours` 合并补造历史关系。

CI 修正已独立提交为 `4964910`，涵盖实际产品源文件列表、`develop` push 触发、先编译再运行 native fixture，以及测试用 unsigned scratch 工件。本地定向检查为 17 项、16 通过、1 跳过；这不是远端 CI、整合后完整 quality 或原生编译全部通过的声明。

远端 `develop` 发布、Mac 隔离源码回灌、整合后的完整 quality / native compile 仍待完成。当前工作是三平台源码 consolidation，不代表已统一发行、已更新现有安装或已部署。
