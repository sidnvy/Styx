# 共享开发基线

Styx 的公共集成分支是 `develop`。功能分支从 `develop` 建立，评审和验证后回到 `develop`；`main` 只接收经过评审、具有交付范围和验证记录的发布基线。平台目录或一台电脑上的开发副本不是另一套公共 Core。


## 当前收敛：原生更新与实际组件一致

本轮实现位于 `feature/core-platform-upgrade-20261022`，尚待最终原生安装链验收后回到 `develop`。App 文件的安装、替换和卸载交给平台发行机制；Core 保留同一份配置、身份、Host 迁移记录及恢复规则。安装新版 App 不等于已更新 Host，启动时必须按包内组件核对已安装版本。

- macOS 接入可选 Sparkle 标准更新界面及 AppKit 正常退出；仅有有效更新源的构建才显示更新入口。候选包没有发布更新源，不能称已完成正式在线更新。
- Windows 私有文件权限改用包内固定哈希的原生 Windows ACL 读取器，保留实时检查和拒绝不明确权限。相同状态的全量读取从约 30.1 秒降至 9.8 秒；这仍不是即时响应。更新失败后，失效的读取会重新发起一次，失败提示不会被刷新覆盖。
- 原生 App 只按 Core 明确授权尝试一次随包 Host 更新。准备检查之前就记录事务，失败或取消后重开不会默默重试。用户明确选择恢复时复用同一套事务。
- Linux 新安装使用稳定 `install/node` 路径及 systemd `Type=exec`，仍等待真实连接就绪。旧包生成的、精确匹配且已停止并禁用的服务定义可加入现有 Host 迁移事务；更新和回滚均对账并重新加载 systemd，不修改系统目录权限、不自动启动服务。

截至 rc8 的实际证据：

| 平台 | 已验证 | 本轮边界 |
| --- | --- | --- |
| macOS / PilotMac | rc5 → rc8 Host 迁移、原生 helper 检查及重开、真实 Exec / Cua、正常退出后再打开；23 项身份文件和既有权限保持 | 本次由 CLI 恢复入口触发；旧取消记录阻止自动重试是预期行为。未计作 UI 点击、自动新目标更新或 Sparkle 发布源验收 |
| Windows / NAB | 私有文件 ACL、失败界面恢复、标准 per-user Inno 隔离安装/升级/卸载原型 | rc8 真正自动 Host 链发现路径前缀误判，更新器被误认为运行中的 Host；已修正并通过真实进程检查，完整新包链待重跑。Inno 原型不等于产品安装器完成 |
| Linux / Workstation | rc8 包内 Chrome、Exec、Hyprland Cua；关闭桌面能力不启动 Cua；旧已安装服务迁移、回滚和真实进程中断后的 CLI 恢复及远端 Exec | Edge 复用未变 provider 的已有证据；旧服务测试采用专属隔离单元名。未做物理注销/重启或新聊天账号验收 |

`91ccfbc` 完整工程门槛通过：970 通过、0 失败、47 环境/可选原生检查跳过，依赖审计、SBOM、锁文件一致性通过。Mac 包来源 `4fe9038` 相对该提交仅修正 Mac 临时目录测试别名。后续 Windows 路径修复及 Linux 旧服务迁移另有真实验收记录，不能把 rc8 的原始失败改写为通过。

当前任务证据：`outputs/unified-rc8-20261022/checkpoint.json`、`outputs/macos-updater-20261022/rc8-native-acceptance.json`、`outputs/windows-auto8-20261022/native-receipt.json`、`outputs/linux-rc8-20261022/receipt.json`、`outputs/linux-legacy-service-20261022/receipt.json`。证据目录不进入发行包；最终交付须记录精确来源及包哈希。三平台完整验收、新用户聊天账号、物理重启/登录及正式发行信任仍分开记录。

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
| macOS UI `d2eca11` | 原始历史和最新 UI 已合入 `develop`；Mac 开发源码已安全快进到共享代码 `824f3d9`，工作区干净，已安装 App 未替换 |

`ae86337` 已实现同一 Gateway 的附加精确 TLS 入口、恢复与配对窗口关闭；`1b23221` 修正受限入口的公开 join 预检。真实 Linux / Windows 附加入口验收见任务证据 `outputs/cross-platform-ready-20261022/delivery.json`：Gateway 9 项、Windows 6 项通过，保留原 localhost MCP 会话，真实 Exec / Edge 和关闭窗口后的重连通过。它不证明 Mac 新 UI 已接线或目标 ChatGPT 账号已验收。详见[附加入口契约](add-computer-network-entry.md)和[Mac 来源记录](macos-cross-platform-sync-20261022.md)。

已用 `git cherry develop` 逐一核对 11 条相关平台、Browser 与验收分支，没有未回收补丁，原分支保留。历史 cherry-pick 以补丁等价核对；未成为 ancestor 本身不表示漏合，也不以 `ours` 合并补造历史关系。

`develop` 已发布到 [GitHub](https://github.com/sidnvy/Styx/tree/develop)。初次实际 CI 暴露的旧 Xcode 弱引用跨队列捕获、Browser 独立依赖遗漏及 macOS 临时目录别名问题，分别由 `858b984`、`ed31eb4`、`824f3d9` 补齐。生产编译仍使用 warnings-as-errors，包输入仍拒绝 symlink；没有通过跳过失败检查来合并。

已完成的整合验证：

- 完整 quality（`858b984`）：依赖树、四套依赖审计/SBOM、锁稳定性全部 PASS；行为与集成检查 853 通过、0 失败、43 个环境或可选原生检查跳过。
- 发行包同版 Node 22.23.3（`824f3d9`）：完整 fixture 再次 853 通过、0 失败、43 跳过。相对上述 quality 的产品代码增量仅为两份 Mac Swift 回调兼容修复，由原生编译和检查覆盖。
- Mac 开发电脑（`824f3d9`）：独立工作树、完整产品 Swift 编译、native self-test、私有 HTTP/Core 观察及原生窗口 fixture PASS；确认输入闭包后，原开发源码仅作 clean fast-forward。未改安装、服务、权限或私有状态。
- [macOS 14 / Xcode 15.4 CI](https://github.com/sidnvy/Styx/actions/runs/39736072666)：实际产品编译、原生 client/Core/window fixture、官方 Cua owner SIGKILL/EOF 清理全部 PASS。Linux / macOS 的独立协议与产物检查也已通过。

任务证据保存在 `outputs/consolidation-20261022/`：来源 bundle 和 SHA256、11 分支补丁核对、输入闭包、原始失败及修复后的 quality、同版 Node fixture、Mac 回灌和原生 receipt。初轮 quality 因新工作树漏准备锁定 Exec 二进制失败；补齐原二进制后重跑通过，原失败保留。

尚未完成：GitHub Linux 完整回归仍有 CI-only 失败，同版本地检查已通过，正在通过实际失败日志定位；Windows CI 尚在执行。不能把现有结果称为整体 CI 全绿。Mac“添加电脑”的单接口默认路径已调用共享 Core；多接口选择、入口恢复与主动关闭配对窗口的原生交互仍需补齐和真实配对验收。

本轮完成源码 consolidation、共享分支发布和 Mac Core 回灌；三平台尚未从这一基线统一重建安装包，没有更新既有安装或部署，也没有完成新用户 ChatGPT 账号、完整重启及升级权限验收。
