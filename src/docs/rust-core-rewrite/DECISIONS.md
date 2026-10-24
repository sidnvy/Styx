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

- D11 依用户2026-10-24补充，通用机制优先标准库/成熟依赖：Tokio异步/进程/同步、tokio-util有限codec与取消、Serde、Clap、官方rmcp、rustls、AWS-LC/Ed25519、UUID、encoding_rs、nix安全OS接口及标准文件锁。Styx自研只承载领域政策、资源绑定和事务语义。每项依赖固定版本/features/lock和许可证；SDK默认新增功能不能自动扩大公开协议。

## Implementation decisions from first source/OS review

- I01 恢复旧SDK全部五个MCP协商版本；R00初稿只列两版是遗漏，不作为兼容性裁剪。rmcp需显式method/capability allowlist、legacy session mode及2024-10适配，未实现前不标兼容完成。
- I02 public工具库存从Gateway包装后的schema冻结：Cua内部session不向模型暴露，Cua/Browser公开environment_id保留。provider manifest不是公开wire的替代品。
- I03 Host内owner注册加入不回绕incarnation，并绑定lease及reservation；同epoch重注册不复活旧lease/旧操作。Owner DTO仍不认证。
- I04 token sequence接近u64耗尽时直接fence新prepare，必须显式建立新HostGeneration；不在旧generation内循环序列或复用epoch。调用方为Host/token issuer，公开MCP无变化。此为C04“不得回绕”的保守实现，溢出拒绝源审，尚无运行至耗尽的验收宣称。
- I05 output drain与outcome/liveness独立；维护fence只拒绝新副作用，查询、取消和执行器结算继续。已退出但未drain不能作为完全settled或可清退资源。
- I06 Linux writer/execution锁只是各自资源；不声称它们能协调尚未接入该锁的旧JS进程。live迁移仍须R26，Mac/Windows私有store未实现时显式Unsupported。

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


## ADR-029 — Original CA continuity for a bounded maintenance endpoint

Status: accepted implementation boundary, 2026-10-25. R33 source is being integrated; real paired network validation has **not** passed. This entry does not promote the migration to Verified/Committed or ordinary runtime readiness.

Keep the original protected CA certificate/key, publisher pin and paired identities/credentials unchanged. A CA certificate cannot be used as an ordinary server leaf to bypass strict TLS. The maintenance issuer creates a separate `CA:false` server-auth leaf/key, binds its SAN/origin to the original configured endpoint, and retains the original CA PEM bytes in the chain. It does not install a trust root or change an explicitly pinned old leaf; such a profile is refused by this slice. Expiry is no later than issuance time plus 24 hours or the original CA expiry, with only the existing 60-second not-before skew allowance. This is a maintenance certificate, not an implemented ordinary-runtime renewal policy.

The same original C07 owner, mutex, writer, maintenance transaction and management namespace retain the endpoint. Cutover intent schema2 binds fixed `endpoint-binding`, `endpoint-chain` and `endpoint-key` attachments by hashes, exact root/transaction/candidate and target extension `gateway_endpoint_v1`. Key bytes are private 0600 journal material, not public binding/diagnostics. Endpoint data is not TLS or admission authority. Schema1 without endpoint retains its original serialized shape and behavior; a schema1 target cannot smuggle the endpoint extension. Unknown/partial data and old readers fail closed. Original signed package bytes are never edited to assert newer reader support.

Construct the maintenance validation plan while the original canonical state/profile is still readable, **before canonical apply**. The retained original plan/profile/dual-scope proof must survive apply and actual cleanup; no second writer, journal, fresh enrollment snapshot or post-apply reconstruction substitutes for them. Ordinary admission remains fenced. Schema2 currently rejects Verified/Committed because local candidate Exec validation is not a paired Gateway verdict. Actual paired network validation, final migration commit/activation and ordinary certificate lifecycle remain unfinished.

Implementation and exact scope: [R33 original-CA maintenance notes](r33-original-ca-maintenance.md).
