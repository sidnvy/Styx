# “添加电脑”的附加网络入口契约

状态：待实现。当前源码的入口预检、邀请和独立审批不能组合成已完成的普通用户 LAN 添加流程；本文不是实现或验收凭据。

适用起点：主台已有 localhost Gateway、本机 Host 和可用的 ChatGPT 连接。用户点击“添加电脑”后，应增加一个经授权的设备入口，继续使用同一个 Gateway，而不要求修改原聊天配置。

## 必须保留的既有状态

- 原 Gateway 的 localhost 地址、端口、证书、私钥、model/admin 凭据与 owner 配置保持原值。
- 本机 Host 的连接地址、身份、凭据、能力和系统权限保持不变。
- 隧道、插件地址及账号配置不重建；不自动更改默认设备。
- 新入口与原入口使用同一进程中的 registry、EnrollmentController、Host relay 和撤销记录。不能由 App 另起一个 Gateway，或用第二个 controller 并发打开同一配对数据库。

现有 `device-ingress-change.mjs` 是离线首设备主入口迁移：会改变主 URL、证书和 Host 配置，并明确拒绝已有 tunnel/plugin。它不能充当这里的在线附加入口实现，也不能通过移除拒绝条件来冒充实现。

## 最小用户调用链

1. App 经共享 Core 读取当前 Gateway 的实际归属和入口能力；无归属、状态未知或运行版本不支持时明确停止，不新建 Gateway。
2. 点击“添加电脑”即进入局域网邀请，不另设技术角色或网络范围选择页。Core 在已授权的局域网范围内选择并核对本机实际拥有的精确 IPv4 地址及可用端口；出现多个无法明确选择的网络或需新增系统授权时才说明阻塞。邀请中呈现另一台电脑需要核对的入口和信任信息；不使用 `0.0.0.0`，不自动修改防火墙、路由或系统权限。
3. Core 执行受控附加入口事务，并让当前 Gateway 进程启动该入口。确认实际监听成功后，才能发出包含该入口的限时邀请。配置成功和本机 TLS 探测都不等于新电脑可达。
4. 新电脑明确选择“加入已有”，核对邀请地址和证书，通过真实 TLS 建立连接并提交既有签名加入请求。
5. 两端显示同一次请求的公开核对摘要。主台核对后批准设备；批准范围遵从设备端已经确认的能力选择。摘要不是连接密钥，也不替代 TLS、签名和独立审批。
6. 新 Host 领取既有加密凭据并主动连接。原 ChatGPT 连接通过同一 registry 看到新设备；用户明确选择新设备执行真实命令及其所选能力的实际验收，不重新创建插件或搬运私钥、API key、配置文件。

## Gateway 运行时与 owner 控制

可以复用 `gateway/enroll-admin.mjs` 的 ownerCommand 传输：本机 HTTPS、独立 admin 凭据和既有固定命令校验。已有 invite/approve/revoke 命令没有启动监听器的功能；应增加窄的入口状态、准备、启用和配对窗口控制命令，不把网络变更藏在创建邀请或只读探测中。

前台 Core 和后台 signed Gateway runner 必须接入同一个入口管理实现。后台 Gateway 已运行时，App 通过原 localhost owner 入口请求它处理；不在 App 进程中另建配对数据库或 relay。LAN 上不提供 owner 控制命令。

最小 LAN HTTP 路由仅为 join、claim、confirm；升级路由复用既有 Host exec/computer/browser 认证和能力检查。不开放 LAN MCP 或 invitations、approve、revoke 等管理路由。

`gateway/outbound.mjs` 当前只允许一次 attach，并在 attach 中建立 heartbeat；`gateway/http.mjs` 的 close 会关闭整个 Gateway。新增入口前必须拆分：

- 多监听器共享同一 relay 的连接表、重复 Host 检查、generation、撤销和 heartbeat；不能每个监听器各建一套 relay。
- 原 Gateway 总关闭负责全部资源；附加入口的局部关闭不能调用 gateway.close 或 relay.close，不能清除原 MCP session、本机 Host 连接或其他监听器的资源。
- 原 localhost 服务先独立启动。LAN 地址缺失、端口占用或证书异常只使附加入口进入待处理状态，不能拖垮原聊天入口；不能为恢复而偷偷换地址、端口或身份。

## 配对窗口与连接入口是两个生命周期

关闭“添加电脑”窗口或到达邀请时限，只关闭新加入权限并使该窗口尚未使用的邀请失效。已经批准的设备仍可连接、断网重连；有效批准请求的 claim/confirm 按其独立期限处理。

因此不能把“关闭配对窗口”实现成关闭 LAN listener。只有用户明确关闭“其他电脑连接入口”，才停止该入口，并告知远端设备连接会受影响；localhost 和原 ChatGPT 入口仍保留。撤销单台设备继续使用既有 durable tombstone、凭据拒绝及 relay 断开机制。

入口属于实际 Gateway 进程：前台 Gateway 退出时其入口结束；持久 Gateway 按已授权的登录恢复策略重新对账。恢复使用原 Host 身份和凭据，不重新配对。新入口不需要 Cua 或桌面权限。

## 配置 authority 与事务

建议把附加入口期望配置纳入现有 deployment.json 的 Gateway 范围，例如新增严格校验的 `gateway.deviceIngress`，保留原 url/listenHost 语义。证书路径、运行时描述和服务使用数据由 Core 派生；可以有独立的派生入口 runtime，但它不是第二份角色或网络授权 authority。

不能简单添加一个字段后只更新 state.configSha256：

- `deployment-config.mjs` 和 `gateway-deployment-reader.mjs` 目前只认识单入口，后者严格校验 canonical runtime 字段和证据。
- background/capabilities 等 journal 绑定完整配置 hash；foreground 的 scopeValid 也捕获完整配置 hash。直接改配置会使已有前台连接失去有效 scope。
- `shared/onboarding-evidence.mjs` 的聊天验收 binding 同样包含完整配置 hash。附加网络授权不能静默改写成一次新聊天验收。

事务需持有相关共同锁，记录精确 before/after、派生材料、当前 Gateway 的接收确认和可回滚阶段；不自动重放不确定操作。须为纯附加入口变更建立经过验证的 scope/adoption 或版本化迁移，使既有 Host 执行范围继续有效，并对账所有关联 hash。保留既有验收时，应保留原证据来源和受审查的 binding 迁移记录，不伪造新证明。

原 tunnel/plugin 继续绑定原 localhost URL、证书与凭据，不需要改变账号配置。回滚只撤回本次附加入口变更，不能删除已存在的身份、配对记录或其他设备凭据。已由新入口完成的设备批准属于独立事实，不能靠恢复旧数据库副本抹掉。

## TLS、可信接入 scope 和续期限制

不能承诺现有证书一定是 CA。若观察到原证书确实允许标准 CA 签发、密钥匹配且仍有足够有效期，可使用标准 PKIX 为精确 LAN 地址签发独立叶证书；原证书及私钥文件字节不变，原根身份不更换，新 Host 校验 hostname 与完整信任链。

也可选择同一 Gateway 的独立 LAN TLS 证书，但首次必须向用户明确展示并授权这个新增入口的信任。它不等于原 canonical TLS 身份，也不能静默替换旧身份或声称已由原根认证。已有入口再次启用、重启和重连不得随意重新生成证书身份。

原 Gateway 当前创建的是 30 天自签证书；附加叶证书不能消除根证书到期问题。计划和状态必须呈现证书有效期、续期所需条件及信任变化。非 CA、临近过期或到期状态需要明确的续期／迁移处理，不能以“重新配对所有设备”替代升级方案。

当前公开核对摘要包含 origin、实际 TLS 叶证书 hash、requestId 和设备公钥指纹。Host 已按所连接的 TLS peer 计算；owner 端目前按主 localhost 地址和主证书推算，新增入口后会不一致。应由 Gateway 在收到 join 时记录经实际 listener/TLS 握手确认的入口 origin、叶证书 hash 和入口 generation，再用于 owner 投影；不能信任客户端 JSON 自报这些值。邀请也应绑定对应入口和窗口。

入口预检的 HTTPS 校验机制可复用，但现 verifier 固定 canonical URL，并期待 owner pending 路由返回 401，不能原样用于屏蔽管理路由的 LAN 入口。新检查从受控派生入口取目标，使用无副作用的明确响应核验；例如 GET join 得到预期 405。仍需新电脑实际 TLS、加入和 Host 连接来证明跨设备可用。

## 实现位置和明确限制

主要接入点：Core/config/reader 与现事务基础；gateway/http、outbound、enrollment、enroll-admin；Core 前台启动和 gateway-signed-runner；onboarding/server 与“添加电脑”UI；Host 保留既有加入、领取凭据、连接和重连链。

第一版只承诺用户已授权且真实可达的精确网络入口。没有自建发现／中继服务，不承诺扫码即可跨越任意 NAT；LAN、VPN 或已知 IP 也不是自动信任依据。IP 变化需明确对账和受信任的地址更新，不自动改现有 Host 身份或凭据。旧运行版本缺少入口管理能力时，需先通过既有受控更新流程升级，不临时绕过签名或再起服务。

## 只需闭合的用户关键案例

1. 已可用的单机主台实际加入另一台电脑；原 ChatGPT、localhost、本机 Host、证书和凭据保持，能在原聊天中选择新设备运行真实命令。
2. 新电脑看到的核对摘要与主台同一请求一致；错误核对、过期或已抢用邀请不能获得批准或凭据。
3. 关闭配对窗口后，已批准设备持续工作且能断网重连；撤销设备后旧凭据拒绝，原本机和其他批准设备不受影响。
4. App 退出／登录恢复以及网络暂不可用时，分别遵守当前 Gateway 的前台或持久生命周期；不重建身份；LAN 失败不影响原 localhost 聊天入口。
5. 附加入口事务失败、IP 变化和证书将到期时，有明确可执行的恢复状态；不清空部署，不静默换信任，不把配置成功或本机探测当跨设备／账号验收。

这些案例未完成前，应继续明确报告“网络入口尚未接通”，不能以离线迁移或低层跨机 smoke 代替普通用户“添加电脑”流程。
