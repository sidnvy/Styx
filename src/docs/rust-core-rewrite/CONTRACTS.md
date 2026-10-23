# Rust core contracts · semantic revision 1

语义v1已由R00冻结，见CONTRACT-V1.json；这些是实施要求，不是已实现的API。此后变更须提交兼容影响、调用方清单、迁移方式和场景更新。不得由某agent在其实现中私自改变共享类型。

## C01 · Identities and authority

使用不同newtype：`DeviceId`、`GatewayId`、`OwnerId`、`HostGeneration`、`ConnectionGeneration`、`SessionId`、`SessionGeneration`、`AgentInstanceId`、`ObservationId`、`OperationId`、`TransactionId`、`ReleaseId`。不能用同一个String或“connected”状态替代所有身份。

`OwnerId`由已认证Gateway会话分配，不能由工具参数自报；Host信任的是已认证Gateway及协商的owner namespace，不声称独立识别ChatGPT账户。`TrustedCaller`只能由认证adapter构造，不能直接从JSON反序列化成权限。

权威分工：

| Owner | 唯一权威 | 不拥有 |
| --- | --- | --- |
| Management Core | 本机配置意图、计划、变更事务、manager desired-state | 代替OS授桌面权限、代替Gateway批准设备 |
| Gateway | enrollment、设备审批/撤销、允许能力、远程owner namespace与路由 | 本机图形Session事实、具体桌面执行 |
| Host | 已验证本机身份、实际provider/session目录、子进程、执行准入 | 未批准能力、其他用户会话的隐式访问 |
| Session Agent / OS bridge | 对应会话事实、OS授权及原生动作结果 | 配对私钥、组管理员凭据、全局产品配置 |
| CLI / GUI | 认证调用、用户交互、展示 | 独立配置数据库、绕过事务或重做执行策略 |

有效准入=`Gateway grant ∩ Host local policy ∩ target/session binding ∩ observed provider availability ∩ current OS authorization`。Descriptor是事实投影，不是新增授权。配置根一次只能有一个mutation writer；同进程内部通过同一协调器，跨进程通过OS锁/lease及kernel process identity验证。

## C02 · Capability

```text
CapabilityDescriptor {
  contract_version, capability_id, scope: Host|Session|Browser|Target,
  provider_id, configured, remote_grant,
  availability: Available|Unavailable|Degraded|Unknown,
  authorization: Granted|Required|Denied|Revoked|Unknown,
  target_session?: {id,generation},
  reason?: ErrorCategory, observed_at, observation_generation,
  recovery: None|Reobserve|Rediscover|Reconnect|ExplicitAuthorization|ManualReview
}
```

至少区分exec、managed headless/headed browser、window read/control、capture、pointer、keyboard；accessibility为可选。字段unknown不能提升为available。不能因为capture成功推断input/AX可用。

现有exec/computer/browser批准保持原值；细分可用性不静默授予新权利。Attach明确Unsupported，本轮不实现任意CDP接管。Headed Browser引用C03 Session绑定，headless不依赖Session Agent。

## C03 · Desktop sessions and selection

```text
SessionDescriptor {
  id, generation, user_identity, login_instance,
  seat?, display_identity, desktop_backend, desktop_instance,
  agent_instance, state, permission_facts, capabilities,
  provenance, protocol_version
}
list_sessions / inspect_session / attach_session / detach_session / subscribe_events
```

身份是同一有效生命周期内的稳定标识；重登录、compositor/WindowServer/agent重建、权限撤销、lock/unlock边界均撤销旧generation或observation。一个username、PID、session number、DISPLAY变量均不足以单独证明身份。

选择规则按优先级固定：

1. 显式目标：只尝试该目标；失效立即结构化拒绝，不fallback。
2. 已批准绑定：验证其当前实例和授权；重建后进入重新发现，不自动继承旧引用。
3. 无绑定：发现候选。仅唯一、属于当前授权用户且可证明关联的候选可按既有批准策略建立绑定；多候选返回SessionAmbiguous。环境变量只作发现hint，绝不授权或决定切换。

Linux必须验证logind/user/seat与实际compositor/display/agent实例关联；user manager环境不是身份源。SSH/旧tmux不需要手动export全局环境。Linux进程内探测异步、有总deadline和子进程清理；优先会话事件，低频有界reconciliation补漏。

Windows至少绑定SID、logon/authentication LUID、Session ID、WinSta0、input desktop、integrity和agent instance。Mac绑定UID、login/audit session、console/lock、native agent及可获取的WindowServer实例事实。不可获取事实明确unknown，不伪造跨平台一致性。

## C04 · Operations, outcomes and cancellation

```text
OperationContext {
  id: HostIssuedOperationToken, trusted_owner, device_id, grant_revision, host_generation,
  session?: {id,expected_generation}, target?, observation?,
  capability, deadline, disconnect_policy, cancellation_authority
}
OperationState = Created|Validated|Dispatched|Running|
                 Succeeded|Failed|Cancelled|Unknown
ExecutionLiveness = NotStarted|Running|Exited|Unknown
Cancellation = Requested|NotDispatched|TerminationConfirmed|Unknown
```

Operation outcome、进程liveness和输出drained分别记录。`Cancelled`只能由未派发证明或backend终止证据建立；终止不证明历史副作用回滚。仅stdout EOF不能证明进程退出（44cf147已修复旧缺陷）。

- dispatch前再次检查owner/grant/session/generation/deadline，变更必须经过同一准入协调器，避免排队期间撤权仍执行。
- readonly观察可以在明确错误类别下重新观察；click/type/write/process-start等不能因timeout/IPC断线自动重放。
- 新协议先由Host `prepare_operation`签发token并登记Reserved，再`dispatch_operation`；不允许client自造一个未见ID就触发执行。token包含随机HostGeneration、OwnerEpoch和单调sequence，绑定owner/payload digest；counter溢出须换epoch，不能回绕复用。prepare不派发副作用，丢回复可安全查询/放弃reservation。
- 重复token+同owner+同payload只返回既有记录/Unknown，不再次派发；payload不同拒绝。只有当前ledger的Reserved可首次dispatch。终态记录有界保留后淘汰，淘汰token不再Reserved，后续一律Expired/Stale而非“新请求”；这样不需要无限保存used-ID集合。Host重启生成新HostGeneration，所有旧token失效；旧操作可协调结果但不能自动创建新token重放。活工作或执行liveness仍Unknown的记录不能为腾位置静默淘汰，容量不足先拒绝新reservation。结果Unknown但已证明执行终止的记录可按已声明audit/retention政策归档；过期后仍不能重新dispatch该token。
- Rust内部首次dispatch返回不可Clone、不可Deserialize、无公开构造器的`DispatchPermit`；executor按值消费并仅执行其中prepared payload，不接受另一个raw operation ID/payload作为start后门。Core保留token状态权威；provider在已确认exit且drain后可退休实际资源，不能自行重新签发许可。该所有权约束不替代运行时撤权协调及独立副作用验收。
- prepare/dispatch为受信内部协议，不强加给公开MCP原生工具。legacy单帧路径通过明确compatibility adapter提供旧语义，不能宣称旧端具有新token去重保证。R00/R05冻结token格式、ledger容量/retention、owner lease结束与重启拒绝规则。
- 序列化到正确资源粒度（目标桌面/窗口、owner Browser context、Exec stdin），避免一个owner长期饿死其他owner。队列是有界资源，拥塞显式返回Busy及可安全建议；不驱逐运行任务来伪造空闲。
- cancel只作用于原owner有权控制的操作；管理者另需明确授权。接收取消请求不等于已取消。
- client读取超时只终止该等待，不Dispose整个Core；未知写事务用transaction id查询。caller取消不自动证明backend取消。

Gateway网络连接与Host executor寿命分离。短暂网络丢失保留同一Host executor；重新认证且owner/generation一致才能续取结果或继续stdin，旧引用不能给新聊天。Gateway epoch变化或owner不可确认时标为待协调，禁止新owner接管或重派发。明确owner结束/授权撤销按事先声明的终止政策处理；网络丢失本身不算撤销。Host崩溃后的任意长期任务恢复不属于本轮承诺，必须报告已知退出或Unknown，不能自行恢复命令。

## C05 · Error contract

结构化`ErrorEnvelope {category, provider_code?, stage, retry_class, execution_certainty, operation_id?, transaction_id?, target?, generation?, public_message}`。

类别至少：NoGraphicalSession、SessionAmbiguous、SessionDisconnected、SessionLocked、CompositorRestarted、PermissionRequired、PermissionDenied、CapabilityUnsupported、StaleObservation、TargetNotFound、BrowserNotAttachable、OperationTimeout、ResultUnknown、Unauthorized、Busy、ProtocolMismatch、IntegrityFailure、StateConflict。

retry_class仅None/Reobserve/Rediscover/Reconnect/ReadTransaction/ExplicitAuthorization/ManualReview等；不允许笼统`retryable=true`导致动作重放。保留底层精确码；不从任意stderr文本猜权限。网络错误与执行错误、未执行与未知、worker死亡与已取消分开。

## C06 · IPC and trust

统一Control协议：版本协商、角色、实例、request id、deadline、method、有限payload；响应有关联id和结构化结果。管理变更含request/transaction id并可查询。普通read、管理mutation、agent注册、provider dispatch不同scope。

Unix固定private目录UDS并验证peer UID及平台可验证的process/session身份；Windows采用拒绝远端连接、受限ACL的Named Pipe并验证token/SID/session/integrity与server身份。payload中声称的PID/session/socket不可信；不得接受网络client任意路径。peer UID不等于会话归属，也不声称抵抗同UID已完全控制账户的恶意进程。

Desktop Agent握手绑定Host challenge、kernel peer事实、agent实例、Session descriptor/generation、协议版本和只允许的capability。Unix若仅UDS信息不足以绑定登录实例，须经平台bridge提供可验证事实，不用env自证。对现有Cua使用已认证的父子stdio或经核验的原App私有socket；不能把试验GuiBroker的保证移作正式证据。

frame长度、排队字节、请求数与deadline在R00固定；运行时超限拒绝/隔离，不允许无界内存。cancel、断线、reconnect和generation invalidation均有事件；连接重建不保留旧native句柄授权。

## C07 · State, ownership and recovery

首个迁移切片读取现有JSON及原始bytes，保存version和raw hash；不顺手格式化身份/配置文件使`configSha256`或事务证据失效。Rust唯一管理写者；旧Core只能作为不同配置根的参考或已停用旧版，禁止同root双writer。

原设备RSA身份/PEM、SPKI fingerprint、Gateway CA/pin、令牌、publisher、Browser登录状态与OS权限责任分别列入preservation manifest。RSA-PSS/SHA256 saltLength32、OAEP/SHA256、claim HMAC、签名域/字段顺序/缺省字段语义来自真实legacy codec，逐字节vector校验。publisher使用的Ed25519不能与设备RSA身份混淆。无授权不轮换、不重新配对。

通用事务持久阶段：Planned→Prepared→Applied→Verified→Committed，异常进入Recoverable或Unknown；需要影响运行工作的事务在Prepared前增加Fenced。普通配置/能力写入不释放管理writer lease，也没有必需的OwnerReleased/Activated。

owner切换是单独子协议：fence旧执行→结算→释放旧runtime execution lease→取得新execution lease→激活verified payload→验证→commit。管理事务协调器在该事务内持续持有mutation writer lease；runtime execution lease与配置writer lease是不同资源。新runtime可在受控maintenance下读取/运行获准validation probe，不能在commit前另当配置writer或开放普通dispatch。只有明确handoff/commit后才转交管理写权，不允许释放锁后继续写入。

每个持久边界都有journal与读取协调；append/replace/flush的OS语义由adapter实现及故障注入验证，不把POSIX fsync假定成NTFS行为。

claim lease绑定boot instance、PID creation identity、配置scope和随机owner generation，不能依赖会抖动的wall-clock boot timestamp或PID存在。遇到活owner、不明锁、执行liveness未知或未协调事务先拒绝切换；历史operation outcome为Unknown但已确认执行结束/资源清理的，可保留其Unknown审计并在无未结事务时切换，绝不将其改写成Success/Cancelled。禁用服务的desired-state不会被generic recovery复活。

有不可逆schema写入前明确设置reader compatibility barrier。回滚不得覆盖较新操作产生的身份、授权撤销或业务状态。保存旧包不等于可以还原旧授权快照；只回滚代码/明确可逆状态，不复活已撤销权限。

## C08 · Signed package/runtime format and compatibility

`runtime_format: legacy_js_v1 | native_rust_v1`等由签名manifest明确声明；包含component、entrypoint、target、最低reader、contract versions、source manifest、外部executor/worker闭包及hash。只从verified release派生可执行路径，私有配置不能指定任意代码入口。

现有loader固定host/connect.mjs和JS sourceContract，不能将Rust binary塞进旧包冒充兼容。新原生installer/bootstrap先实现旧格式只读验证和明确新格式；若旧更新入口无法安装新bootstrap，使用一次经原publisher签名的bridge installer。桥接不成为长期JS核心，迁移完成后删除。

Mac原bundle ID、certificate/designated requirement/TCC链及Host publisher保持；Windows保留设备/安装身份和publisher。新Rust helper的权限归属必须实测，不能仅以相同文件名/证书推断延续。保留旧包原字节，最终新包可采用新的内部成员布局，不为旧vnext路径永久牺牲新架构；路径变化由versioned loader和迁移覆盖。

互操作矩阵：旧Gateway↔Rust Host先验证Exec；Rust Gateway↔旧Host仅发布旧端实际可证明的能力。新Session/Operation保证需要协商支持，不为兼容模式编造generation或降低授权。Rust↔Rust是最终完整验收目标。public MCP工具名/必需参数/输出语义与现有正常产品兼容；新内部context通过受信边界附加，不强迫每个上游工具改schema。
