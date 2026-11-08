# GUI交付边界决策（D0）

2026-11-08 · 基线 `fd41fcefa3ea24f670eede6983105b2e1c762d35`。
状态：**四项有界实现已集成，受影响参考/FS/签名/TLS场景已通过；真实Runtime参考和最终验收未完成**。本文件落实
[架构核查](ARCHITECTURE-REVIEW-20261108.md)，执行状态只在
[交付计划](END-TO-END-DELIVERY-PLAN.md)维护。

## 范围和责任

保留 `styx → runtime → core → contracts`、Rust管理核心、单写者、现有原生桥和
Codex/Cua/Playwright。只收敛以下四个实际失败边界，不扩大为全仓重构。
不新增服务、自动更新或维护协议，不降低Unknown、原目标、锁屏和身份检查。

根代理负责共享合同、Core/适配实现和候选集成；两端原有本地Codex负责本机原生检查
和GUI旅程。设备上没有共享源码写者。先通过参考场景，再冻结候选；不按每个按钮产包。
旧C23失败和未完成R2草稿保留，不能将草稿能力算作已安装产品能力。

## D1：公开工具合同表达Styx实际支持的路由

**决定**：上游SDK catalog继续作为固定依赖输入；Styx公开schema与它分开。
静态参数先归一化成受支持的请求类型，再经过Core动态准入。
公开schema通过不保证权限/目标新鲜，但不得随后因为相同静态形状而返回“不支持”。

| 路由 | 公开合同与归一化 |
| --- | --- |
| 窗口树读取 | `pid/window_id`为正整数；`include_screenshot=false`选择此分支；树=true、format=elements。默认max_elements=250、max_depth=25、timeout_ms=1000，范围分别1–2048、1–64、100–2000 |
| 窗口截图 | `pid/window_id`为正整数；`include_accessibility_tree=false`选择此分支；截图=true。默认max_image_dimension=1024、timeout_ms=1000，范围分别1–1024、100–2000 |
| 两分支共同限制 | schema使用互斥分支和`additionalProperties:false`；不接受full_output/query/since/文件输出/组合树与截图。pid还满足实际OS进程ID范围，JSON整数不超过安全表示范围 |
| set_value | 必需pid、window_id、element_token、value，精确四字段；value的UTF-8字节数上限16KiB；token仍需当前Host持有的观察映射 |
| click | 必需element_token；pid/window_id可省略，但若提供必须与观察匹配。默认主键点击；Windows可显式right+foreground。不引入像素点击或隐式前台输入 |

公共契约的字符串长度按JSON Schema字符数计，不能冒充UTF-8字节上限。
跨层验证必须包含多字节value边界；无法以标准schema完整表示的语义限制写进描述，
由统一请求解码器明确验证。不能用重复的手写字段白名单代替一个一致的入口模型。

`type_text/press_key/scroll`目前没有Host-owned target准入路径，不能继续以“完整支持”
宣传。先完成现有Computer工具的支持表，保留已实现的元数据/读取路由；没有支持路径的
输入不对外广告，也不临时加SDK直通。核心要求仍包含真实观察后的点击/设值，未缩减。
跨平台仅支持某个分支时，公开说明平台条件，不能把Windows专用模式写成三平台保证。

复用：`PUBLIC-MCP-V1.json`、Gateway tools/list、`CuaAction`、`AxReadRequest`、
`WindowCaptureRequest`、`ClickRequest`、`AxWriteRequest`。固定上游catalog验证不改为
验证Styx子集；对外发现和实际路由共享同一支持表/请求模型。

出口：读树、截图、设值、主键点击的最小/默认/边界参数通过公开schema后进入对应请求
分类；多字段冲突、旧参数、越界和错误类型在派发前拒绝；旧target仍无效果。
真实账号树和截图分开读取，不能用分类器测试代替像素/效果验收。

## D2：拒绝贯穿Core、持久化、协议和GUI

**决定**：取消比较与拒绝申请是两个动作。拒绝针对唯一pending request，不是撤销设备。

| 当前状态/动作 | 新状态/结果 | 必须保持的约束 |
| --- | --- | --- |
| Pending + 取消比较 | Pending | 不写拒绝、不发凭据，不算拒绝通过 |
| Pending + 明确拒绝 | Rejected | admin授权；原requestID/deviceID/公钥指纹/验证码精确匹配；先持久确认后回报完成 |
| Pending + 到期 | Expired | 到期不算用户拒绝；不能再批准/claim |
| Pending + 明确批准 | Approved | 只授予实际批准能力；原绑定保持 |
| Approved + 原claim/confirm完成 | Claimed/可连接 | 原凭据与准备/提交证据保持；缺失或部分提交继续Unknown |
| Rejected + 原claim/旧批准 | Rejected/拒绝 | 无凭据、无授权、无副作用；新申请不能使旧claim复活 |
| Rejected + 新邀请/新申请 | 新Pending | 允许同一设备key重新申请，旧拒绝记录不改写 |
| Claimed + 撤销 | Revoked | 现有永久退休策略不改；重配对走既有明确的新身份设置流程，旧key留存 |

Core返回类型化结果；Runtime负责原有事务/IO、协议和展示投影；GUI只呈现批准、拒绝、
取消和结果，不推断授权。拒绝结果绑定原seed/request/identity，单独持久化本地terminal
negative证明；其存在禁止后续凭据/Ready写入。重开可只读显示已拒绝，不因网络失败降成
Pending。过期后的历史拒绝仍可显示；Gateway保留必要的有界历史，原claim绝不复活。

### 格式兼容必须先于新状态写入

拒绝会扩展持久journal和join marker，不能仅给旧schema增加enum然后发布。
使用现有C07 canonical state和签名release reader机制声明新能力，名称采用
`NativePairingLifecycleStateV1` / `NativePairingLifecycleV1`，新管理state schema为7。
这是一个新的reader能力，不按OS/角色再组合出一批reader variant。

- immutable root marker继续保留原genesis，不能原地改pin/所有权；由canonical state
  的reader合同形成旧reader不能消费的门槛。新鲜root从一开始声明新能力。
- 现有Rust profile通过单写者C07事务提升reader，并保留原runtime选择、身份、配置和
  既有update历史。新schema区分fresh和selected历史；复用已有history语义校验，
  不把没有update历史的fresh root伪造为一次update。
- 在提升完成前，Reject入口不可用、不得追加新格式；App、Gateway和Host激活均先检查
  signed release支持当前reader。旧C23不得在已提升root上启动能力worker。
- 尚未形成C07 root的join seed使用明确的新版格式，旧reader在Join派发前拒绝；
  新代码保留旧seed只读检查，不对旧的未结算Join自动重试或悄悄改写。
- 回退只能选支持此reader的已验证runtime。回退到不理解Rejected的C23会明确拒绝，
  不能靠删除journal/marker使回退成功。service相关历史只保留读取兼容，不扩展延期功能。

复用：Core enrollment事务、durable ack/recovery、Gateway原admin认证与claim，
NativeHostJoinStore原前缀/原工作者保留机制。当前草稿不是这个完整设计的实现。

出口：真实TLS + 持久重开场景中，错误身份/验证码/权限无变化；明确拒绝后原claim终态且
无凭据/授权；新邀请批准不复活旧claim；中途失去确认不宣称完成。另用旧reader验证新状态
在worker激活前被拒；两端GUI分别观察终结拒绝，再开始新邀请。

## D3：App可替换，选中的Runtime不可变

**决定**：默认首设就把已签名payload stage到App外现有私有版本容器，再生成profile
选择。App内payload是候选输入；canonical profile选中的独立版本才是运行时来源。
继续使用现有`release::stage`与Runtime更新事务，不引入第二套安装器或自动更新。

| 对象 | 所有者/生命周期 |
| --- | --- |
| /Applications/Styx.app | 签名App、当前控制程序、固定原生权限载体和cua-driver；正常Quit后可由DMG替换 |
| App外runtime-versions | Rust单写者创建，完整原签闭包校验后得到不可变selection；不覆盖或接纳未知partial目录 |
| profile | 绑定独立版本和原目录身份，保存能力/连接/keys/pairing；App替换不自动改其selection |
| Runtime切换 | 现有显式stage/update、C07提交与恢复；Host/Gateway相关选择一起核实，旧worker结算后再激活 |

已完成stage但profile未创建：保留stage结果，明确恢复原尝试；不自动复制第二次。
stage/切换未知时停止该次写入并保留证据，不靠换随机目录名重试。
原生Cua仍绑定当前原App及daemon，App外Runtime中的代理需要重新验证当前原生桥，
不能沿用被替换App的原进程/旧目标。普通Quit/DMG替换流程不得依赖延期的App维护协议。

### 已安装C23的有界过渡

当前C23选择仍在App内，不能先覆盖App再要求它验证旧文件身份。
先验证C23已有stage/update入口能将**当前C23**复制/选择到App外，分别覆盖实际Host/
Gateway root；确认该转换已完成后正常Quit并核实全部原进程退出。随后安装新App，
新控制面读取保留的旧独立选择，再通过新代码选择新Runtime并完成D2 reader提升。
旧C23无需也不得验收新的未知reader manifest。

这是待验证的过渡路线，不是设备操作已完成。若已有入口不能闭合双role，先报告具体
参考失败并修复受影响路径；不能重新归档/清空profile绕过，也不能偷偷修改保存的hash。
不做legacy迁移或旧JS兼容。版本清理由独立的已有窄授权覆盖，不自动删除旧包/keys。

出口：首设profile指向App外；正常Quit→替换App→原profile重开，身份/设置/配对保留；
实际运行使用所选版本；旧target无效、新读取有效；坏签名/未知partial/不兼容reader拒绝。
先跑临时原生参考目录，再对最终精确DMG/Inno实际安装验收，二者分开报告。

## D4：Mac来源资格确认与运行期围栏分开

**决定**：来源显式经过 `Unqualified → Qualifying → Ready → Fenced → Ended`。
首次资格确认是一个有界、独占、只读的过程，覆盖discover后到首次SDK观察完成的整个
阶段，不能在其前半段误用Ready时期的seed严格比较。

| 阶段 | 允许/禁止 |
| --- | --- |
| Unqualified | 固定原App/daemon身份、原FD和console来源；没有输入授权 |
| Qualifying | 在原control/facts FD上获取协议完整的前后native事实及一次SDK只读probe；无target暴露、无输入、无自动补读 |
| Ready | 两FD同一来源且最后事实一致后，只提交一次baseline，才发布Computer就绪和目标观察 |
| Fenced | 身份/锁屏/来源/协议部分结果等失效；旧目标失效，新输入拒绝；保留原FD做结算 |
| Ended | 已核实原工作者/transport结算；新来源要走明确的新连接，不沿用旧目标或重放动作 |

Qualifying只容许同一UID/audit session/console UUID/registry对象/原App与daemon/原peer
内的seed变化，且每个样本均有可靠未锁屏事实。变化不生成输入authority；最后两FD的
稳定样本必须一致，现有已观测锁屏/来源ABA/来源替换检查保留。不能据采样宣称初始化
期间从未锁屏；资格期间的SDK列表不产生可跨越该期间使用的输入target。协议部分回复或超时不能重新读取
来拼出一次成功。资格确认过程与Ready不能继续靠散落bool隐式组合。

Core session的console身份与source fingerprint已核对，不包含seed；不能因此泛化为
任意console都兼容。初始注册维持Connecting和不就绪，只有原子资格提交后才发布Ready。
Ready后的seed/身份变化继续严格失效，本轮不设计持续忽略seed的运行模式。

失败仅使Computer故障域不可用，Exec和独立headless Browser不随之停用。
恢复先结算旧source/原worker，并使旧target失效；本轮复用已有正常断开/重开入口，
不增加自动来源替换或后台重试。若原清理未知，不能启动新来源掩盖。

复用：MacProxySource、BoundMacSource、DesktopSource、DeferredComputerFactory、
现有probe诊断与原FD drain。C23的21ms console_epoch_changed说明失败存在，具体调用
触发仍未证实；参考场景通过也不能冒称实际首次设置通过。

出口：受控参考分别在discover后、首次probe前、probe期间推进同源seed；应允许一次完整
资格提交。UID/audit/UUID/registry对象/peer变化、锁屏/ABA、部分回复必须拒绝；Ready后
变化必须fence、旧target无效果。采样间不可观测事件的限制单独记录，不虚构原子性保证。
最后用新候选真正首次设置/Tunnel保存，不借重开碰成功。

## 实施顺序与停止条件

1. D4最小参考先定位R1，D1静态合同场景完成支持表；这两项先暴露设计是否可行。
2. D3默认stage及保留profile参考闭合，再完成D2 reader/拒绝全链路和两端原生检查。
   四项实现存在接口依赖，根代理仍是共享源码唯一写者，不让设备owner各写一套合同。
3. affected crate增量check与跨层场景通过；Mac真实原生参考通过后，才一次冻结同源码候选。
4. 最终候选实际P1–P4和三平台P6旅程；P7最后刷新已安装插件Logo、校对证据与限制。

每项先取得一个明确反例及其修复证据；约2小时没有新增可验证闭合则按已有规则收口并
重排，不继续无界补丁。未知结果优先于时间盒。新证据如要求改变信任边界或范围，先把
具体影响列给用户；普通实现细节不反复审批。设计/测试/原生参考/包/安装/真机分别记账。

## 并行实施与检查点（用户更新要求）

用户指出此前工时区间没有参考意义，要求尽可能并行推进。9–18小时/1–3工作日的
预测撤回，不再以没有实测支持的日程汇报进度。最终目标保持，依阶段出口与真实证据报告。

- 根代理：D4 Mac来源实现/参考、共享contracts/readers与所有接线、唯一集成和证据核对。
- subagent public_tool_contract：D1合同已交回；继续准备reader7完整补丁，由根代理审查/集成。
- subagent pairing_lifecycle：D2 Core/协议/双端GUI和场景已交回；补旧reader下Reject广告门槛提案。
- subagent runtime_install_model：D3默认stage及floor helper已交回；独立审查D4的提前授权/未知/清理边界。
- PilotMac、NAB5：继续原本地Codex线程，本机源码快照原生检查与GUI独占；不由根代理包办。

产品路径租约互不重叠；shared合同、manifest和Git集成始终由根代理持有。
验证前冻结一份共同源码检查点，一次编译后运行相关场景；新增提案在/tmp留patch，不把
正在补的半个helper混入运行中的编译。平台缓存分开复用，检查不耦合发布生产者。

下一门槛：R1受控只读原生参考、reader7及持久/TLS负控、两端原生编译、保留profile
跨App替换参考；全部闭合后才冻结候选。每个结果分别写测试/原生参考/包/安装/真机，
不会把并行派发或文档完成当成交付。当前交付未完成，Stable NO-GO。
