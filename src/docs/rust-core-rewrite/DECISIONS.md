# Decisions and feasibility gates

## Decided — execute without reopening language choice

- D01 用户选择Rust核心：取代旧ADR“不做Rust”的技术选择。所有Styx自有运行/管理权威迁入Rust；保留成熟外部执行器和OS桥，不保留JS Core作为长期后门。
- D02 四crate、向内依赖、单原生CLI/daemon组合；进程只按权限/寿命/故障域拆分。
- D03 Session显式目标失效不fallback；env只是hint；generation和owner不得混用。
- D04 Remote grant、OS权限和capability事实分离；细分可用性不自动扩大授权。
- D05 Unknown不重放；终止、结果、输出EOF分开；UI超时不杀Core。
- D06 单writer切换；版本化状态/包格式；旧代码可退役，身份/配对/权限责任必须保留。
- D07 测试数不是完成率，必需场景有独立oracle及负控制；mock/compile不能替native。
- D08 默认0新worktree；复用已有checkout，公共文件/Git由集成者独占；设备单owner。
- D09 既有App-managed Quit语义迁移不变；persistent模式GUI detach与Stop Host明确分离，不凭实现方便切换管理模式。
- D10 Browser attach、新UI、租户、通用自主任务不纳入本轮；旧CAS实验保存原ref和证据，后续需要时明确Rust迁移。

## Must resolve with short executable spikes in M0

这些不是无限期TBD；每项有产物/失败边界和不影响的并行任务。

| Gate / owner | 默认方向与要验证的事实 | 决策产物 / 无法满足时 |
| --- | --- | --- |
| G01 R01 tools/protocol | Rust stable+2024，Tokio/rustls/rmcp及成熟crypto；验证冻结MCP版本、OS targets和legacy签名。 | 固定toolchain/dep/features/许可表与spike结果；某SDK不适用可换成熟库或薄protocol adapter，不能降安全或重新发明整个MCP。 |
| G02 R02 feasibility / R38 decision closure | Linux普通用户systemd；Mac普通用户Host+原TCC agent；Win合法用户principal的非交互service+交互Desktop agent。 | 每平台lifetime_scope/执行身份/注册权限/凭据可用性/网络与home条件。Windows如需服务登录credentials仅用OS机制，Styx不存密码。新账户/信任/权限扩展提交owner具体决定；其他Core/provider开发照常。跨logout未证明就保持该gate BLOCKED，不能自动降范围。 |
| G03 R02 local IPC | Unix private UDS+peer/platform事实，Win restricted Named Pipe+token/server身份。 | 互认证/Session绑定负控制；无法取得可验证会话事实时用native bridge，不以自报PID/env代替。 |
| G04 R03 budgets/oracles | SPEC初始性能目标，真实executor与独立观察器。 | 参考机/负载/容量/测量冻结，observer能识别零次/两次。预算修改需证据和影响记录，不能放宽timeout掩盖失败。 |
| G05 R00/R24 migration format | 旧JSON raw-read，signed native_rust_v1，原生bootstrap或一次签名bridge。 | 兼容矩阵/loader reader barrier/不可逆写入点；无法回滚的状态明确标Barrier，不能用旧授权snapshot回滚复活权限。 |

## Owner decisions only when materially necessary

无需用户逐项选择crate、文件、错误枚举或普通实现方法。以下需要具体可审方案：新增系统服务权限/账户或保存凭据、改变默认Quit/持久运行产品语义、跨用户执行、轮换身份/publisher/CA、不可逆数据迁移、扩大Browser/自主任务范围、降低required发布门槛。

提交方式：问题→最多两项可执行方案→用户/安全/迁移影响→已完成的隔离验证→建议。必要决策等待期间推进无依赖工作。现有原身份签名失败是环境门槛，不以换证书或清TCC作为默认恢复。

## Why this plan does not freeze legacy architecture

旧实现只约束外部可信合同，不约束Rust内部目录、状态类型、async模型或包成员路径。允许删除低价值测试、收拢冗余状态、替换内部协议/loader和过度耦合，只要迁移及授权语义明确。保留Codex/Cua/Playwright是复用执行器，而不是为JS Core保留产品权威。
