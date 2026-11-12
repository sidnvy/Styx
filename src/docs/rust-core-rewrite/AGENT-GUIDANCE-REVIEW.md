# Agent guidance review · 2026-11-12

本次只调整仓库指导文件和按需加载方式，不修复或验收产品运行时。
规则可能放大停顿和重复工作；不能据此断言它们造成了某次原生启动失败。

## 依据与职责

- [OpenAI: Rethinking skills and prompts](https://developers.openai.com/blog/rethinking-skills-and-prompts-for-gpt-6-astra)：
  删除积累的重复/过时约束，按任务读资料，避免过度具体流程和不必要的审批停点。
- [OpenAI: Build skills](https://learn.chatgpt.com/docs/build-skills)：
  description 精确路由，内容渐进披露，仓库技能放 .agents/skills，每项聚焦一个工作流。
- [OpenAI: AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md)：
  根规则常驻，目录规则按作用域组合；不是所有资料都应成为全局前置条件。
- [OpenAI: Skill evals](https://developers.openai.com/blog/eval-skills)：
  检查触发、实际行为与效率，语法通过不能证明执行效率提升。

以上是官方通用原则。下面的文件划分和具体边界是 Styx 的本地设计选择，
不把官方示例中的审批或目录结构照抄成新要求。

| 文件 | 职责 | 不放入 |
| --- | --- | --- |
| AGENTS.md | 稳定产品边界、默认开发方式、所有权和真实安全限制 | 进程/PID、候选状态、每台机器的构建配方 |
| WORKSPACE.md | 固定源码/缓存/工具位置、入口及上下文路由 | 连续追加的交付历史或“下一步必须…” |
| .agents/skills/styx-native-development | 原生增量开发、运行和生命周期回归 | 安装器/全平台发布前置门槛 |
| .agents/skills/styx-release-acceptance | 冻结、签名、安装和最终真机/账号验收 | 日常修改都执行一次的流程 |
| END-TO-END-DELIVERY-PLAN.md | 已验结果、剩余出口、当前执行依赖 | 常驻全局指令 |
| WORKSPACE-HISTORY-20261112.md | 原 WORKSPACE 原样历史，按旧路径/收据查询 | 当前状态权威或默认必读文档 |

## 改正的决策边界

| 原问题 | 调整 |
| --- | --- |
| 根规则引用不可变候选，日常原生开发也被推向发包 | 日常增量构建/真实运行；冻结后的输出不可变，正式发布才走生产门槛 |
| 原生检查默认 check-only，被用作不运行的停止点 | 类型问题只需检查；行为修复必须验证真实 GUI/Core，保留现有验签与资格检查 |
| WORKSPACE 同时存在多段“current”、旧 cwd/chat/cache | 当前文件只保留固定路径和入口，旧内容完整移入历史 |
| 无条件读架构入口，又遇到旧重写任务和阅读序列 | 按任务查合同/范围/进度，不重新从 R00 开始 |
| Unknown 限制被扩展到只读诊断和隔离本地回归 | 禁止自动重放结果未知的状态变更；允许新鲜只读核实、已证未派发后的授权尝试 |
| 六领域报告用于每次小更新 | 仅发布检查点完整报告；平时给结果、阻塞、下一动作 |
| 反复询问已授权的配对或正常运行 | 复用明确授权；仅缺失权限或本人现场动作才请求，工具限制仍遵守 |
| 两端聊天 cwd 是项目父目录，规则仅在 source/ 子仓库 | 父目录使用版本化的薄 AGENTS 入口和 Skill 发现链接，规则内容仍只有 Git 中一份 |

保留：Rust 唯一管理权威、src/ 唯一产品源码、平台 owner/单写者、
固定项目与缓存、签名与 Runtime 资格、不传私钥、不改生产连接、不关闭沙箱、
不动 piermini/工作站重启、真实独立效果与恢复、最终 Stable 门槛。
Git 能恢复受跟踪代码，不能恢复任意 profiles、keys、缓存或未提交唯一工作。

## 轻量验证用例

以下是文档的人工场景走查，用于检查路由和边界；不是已运行的模型行为评测。

| 请求 | 预期路由与动作 |
| --- | --- |
| 改文档错字 | 不加载两项技能，不编译/签名/安装 |
| 修改 CLI 参数合同 | 受影响 Rust/合同检查，不自动加载原生或发布技能 |
| Mac 同 profile 重开失败 | native-development；保留配置、捕获首错、受影响回归和真实重开 |
| Windows GUI 增加一个状态提示 | native-development；原机检查/必要显示验证，不默认 Inno |
| 改角色退役记录 | native-development；同根重开和历史/部分完成负控，不靠 reset |
| 原生点击结果 Unknown | 新鲜只读核实，不自动再点；其他独立任务继续 |
| 只读窗口列表未返回 | 可做新的只读诊断，不把“不重放写操作”变成禁止调查 |
| 原始 producer 收据未知 | release-acceptance；核实原 producer，不重新构建 |
| 已授权本轮 GUI 配对 | release-acceptance；证书核对后继续，不逐按钮再请示 |
| 冻结最终统一源码并交付 | release-acceptance；集成/产物/安装/独立效果分开证明 |
| 原聊天有 active writer | 保留 owner，通过既有队列协调并等实际结果，不另起 writer |
| 需要新私钥传输或放宽沙箱 | 保留禁止边界，不能以“可信环境”替代授权或工具规则 |

本次验证只证明格式、链接和指令的一致性。后续首次真实开发任务观察：
是否在同项目/缓存内完成、是否少一次无必要发包/确认，以及生命周期故障是否保留首错。
不为验证指导文件启动新候选或重放现有 Unknown。

验证结果：两项 Skill 均通过 skill-creator 的 quick_validate.py；6 个指导文件的
21 个本地 Markdown 引用存在；历史 WORKSPACE 的 SHA256 与修改前完全一致。
local-tests.py 的 affected-package 示例经 --dry-run 核对，未运行产品测试或构建。
12 个表中用例已人工走查；尚未进行独立模型 trace 评测，不能宣称已有实测提效。

路径核查：PilotMac 与 NAB5 的固定项目根均没有 AGENTS.md 或 .agents/skills；
两端 source/AGENTS.md 均仍为原始哈希 55d6315f…。已有聊天可能曾手工读取规则，
本次发现不证明它们此前完全没有遵循规则，但不能继续假定父 cwd 自动加载子仓库指导。
src/ci/native-project-AGENTS.md 是父入口模板，不另建产品源码/项目/聊天。
