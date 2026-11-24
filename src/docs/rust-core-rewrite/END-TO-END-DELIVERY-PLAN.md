# Styx 重构当前交付清单

## 当前源码与实机基线（2026-11-24）

当前已发布并全量部署运行的最近预发布基线为 [v0.8.1-rc.12](https://github.com/sidnvy/Styx/releases/tag/v0.8.1-rc.12)（源码 `99fd609face2b7af2d98ff23bf7265bf0a0ae62f`），已核对资产保存在 `/home/sid/Developer/Artifacts/Styx/release-0.8.1-rc.12/`：

- **Gateway (`moedeu-apps`)**：已升级并稳定运行 `0.8.1-rc.12`，保持既有身份、配对与 Tunnel `/healthz`；Public MCP 同步 JSON 握手、clean SSE framing、`public-mcp-subject:` 稳定归属与 `destructiveHint: false` 工具契约已生效。
- **跨平台 Hosts**：Linux (`niuda`)、macOS (`pilotmac`)、Windows (`NAB5-WIN`)、Android (`Pixel 7 Pro`) 及授权的独立节点 `piermini` 均已升级到 `0.8.1-rc.12` 并通过在线能力连接校验。
- **双端真实账号冒烟**：在 Google Gemini Web（`https://styx.sidnvy.com/mcp`）与 ChatGPT Web（`Styx Gateway`）完成 `list_execution_environments`、并发隔离标签页、会话切换/续读与 `browser_close` (`profile_preserved: true`) 验证。
- **收口转 Stable (`0.8.1`) 修复项**：
  1. 修复 Linux Host systemd 停止路径在局部 lane 未完成时在 `TimeoutStopSec=infinity` 下无限自旋 `cleanup_unknown` 的问题（增加固定类别诊断 `reason` 并在 20s 服务停止预算后如实返回未完成收据），以及 `native_service::install()` 对先前 `failed` 但主进程与 cgroup 已清空 unit 的状态判定。
  2. 将 opt-in `existing-browser` CDP 的 Playwright `connectOverCDP` 超时提升至 25s，并将 Rust `SessionMode::Cdp` 动作预算统一到 `BROWSER_WAIT_PREPARE_TIMEOUT_MS`（35s），避免首次 Chrome 远程调试授权弹窗期间误落入 4-5s `outcome_unknown`。

下文保留历史交付节点记录，不覆盖上述当前状态。

## 历史源码与实机证据节点（2026-11-21，rc.2）

本次重新核对的 niuda Host 与 moedeu-apps Gateway 都在运行
[v0.8.1-rc.2](https://github.com/sidnvy/Styx/releases/tag/v0.8.1-rc.2)，
源码 `b0c675faa81e806e6363cc00e187cdaf9aaa20cf`。
选定 Runtime、实际进程与原生 worker 记录位于
`/home/sid/Developer/Artifacts/Styx/release-0.8.1-rc.2/delivery-verified.json`。
其他设备的 0.8.0 验收是此前记录，不代表本轮重新检查了那些设备。

### Desktop CUA 的已证实结果与当前缺口

- PR81 的错误分类修正只解决误报 PermissionDenied；新增 `type_text` 的成功
  不代表原 `set_value` 恢复。PR82/rc2 才恢复 Linux 正常 setter 与现有原生
  Hyprland 替换输入，并在实际日常 Chrome 的公开 MCP 路径上验证 ASCII、
  中文/换行与清空。该验收只有一个 owner。
- rc2 上已用两个正常认证的独立公开 MCP session 复现
  A 读树 → B 读树 → A 写入返回 `UNAUTHORIZED / not_dispatched`，测试框未改变。
  Host 把带有 owner/resource 归属的 AX observation 放在全局单槽；
  B 的正常读取覆盖 A，随后 owner 检查拒绝 A。这不是 Chrome OS 权限不足。
- 同一 rc2 session 已复现“读树 → 列窗口 → 写入”和“读树 → 纯截图 → 写入”
  均返回 `STALE_OBSERVATION / not_dispatched`，测试框未改变。
  这些只读原生调用保留 AX snapshot，Host 却额外丢弃了绑定。
- 原始复现证据保存在
  `/home/sid/Developer/Artifacts/Styx/desktop-observation-owners-20261121/`，
  分别为 `public-two-owner-rc2.json` 与 `public-read-continuity-rc2.json`。
  未取得另一对话所贴失败的完整请求 trace；不能把上述可复现条件直接认作
  那一次历史请求的唯一原因。
- 另一个现有 fixture 回归确认：合法派发并收到 native ACK/Core Succeeded 后，
  `click/type_text` 的结果授权仍按原观察的 30 秒年龄拒绝 receipt，最终公开映射为
  `outcome_unknown`；`set_value` 不受该年龄检查影响。修复只移除结果交付阶段的
  年龄复查，派发前仍要求 fresh observation。此证据来自 Core/native-slot fixture，
  不表示已在真实 Chrome 中注入长延迟；见 `chrome-read-debug/desktop-receipt-age-red.json`。
- 当前 `fix/desktop-observation-owners` / 0.8.1-rc.3 为工作分支候选，
  未合并、发布或部署。生产修复限定在 Host 既有资源记录和观察失效时机；
  权限、owner、target、原引用年龄、source fence 与一次派发约束保持。
  三项 Host 生命周期定向回归均已由红灯转绿，独立审阅通过；修复后的公开实机验收尚未完成。

### 本次原生输入完成条件

验收必须通过公开 MCP → Gateway → Host/Core → 原生 Cua → 实际 Chrome，
并独立观察最终输入；源码/fixture 测试、打包、安装和实际效果分别记录。

- 单 owner 的 click、set_value 与 type_text；替换、清空、Unicode 与读回。
- 完整 AX 树后经过 metadata、纯截图等只读调用，原引用仍可在原有效期内使用。
- 两个独立 owner 在同一 Host 重叠读取，然后各自交错写入并读回；
  关闭一个 owner 后，另一个已取得的观察与后续读写继续有效。
- 新完整 AX 树替换旧引用；错误 owner、过期/错误引用仍拒绝；
  同一 operation 不二次派发，不自动重放 outcome unknown 的输入。

并发读取和交错写入不能证明两个物理前台输入可安全同时执行。
Linux/Hyprland 前台输入会聚焦窗口/控件，不恢复原焦点，不承诺后台无干扰；
原生结果为 unverifiable/unknown 时必须再观察，不能据派发成功推断效果。
全源码 quality receipt 的 `native_platform_acceptance=NOT_RUN` 和
`final_release_gate=false` 也不能替代上述实机流程。

### 已部署的 0.8.0 基线


- Browser 的完整原生 profile 保留在 Host 固定私有目录；关闭 context 或重启 Host
  后可按同一 profile ID 复用。后续对话先列出已有 profile，需要时沿用现有接手工具。
  恢复时不恢复旧 caller、operation、target 或页面引用；多 profile 需要明确选择，
  活跃操作者不会被隐式替换。旧版本的临时 profile 不作自动迁移。
- 真实 headed Chromium 已验证 HttpOnly 持久 cookie、localStorage、IndexedDB 在
  worker 退出并重开后保留；并行 profile 的登录数据和另一运行中 worker 不受影响。
  Host 回归覆盖保存、恢复、接手、并发领取和对话结束时的操作者释放。
- macOS 复用原 owner lock，在原 PID 已消失且 socket 明确拒绝连接时清理残留端点。
  PilotMac 原生测试覆盖残留恢复、活跃监听者、尚未监听的活跃子进程及独占 owner。
- Gateway 只在原诊断流记录 MCP HTTP 4xx/5xx 的数字状态；不记录请求内容。
  新诊断不追溯旧 429，也不替代 Tunnel 上游证据。
- Android release APK producer 已完成真实 unsigned release 构建验证；
  当前手机仍使用原有开发签名。正式 Android 签名身份与 CI 分发尚未配置，
  unsigned 测试 APK 不用于安装或发布，也不阻塞本轮四种既有桌面/Gateway 包。

源码检查、正式 Release 和实际安装验收分别记录。只有对应 GitHub Release 的完整
资产才可部署；安装后仍需核对实际二进制身份与受影响功能。后文 0.4.x 等记录为历史
证据，不表示本轮新源码已经发布或安装。产品规则以
[REFACTOR-PLAN](REFACTOR-PLAN.md) 为准。

## 独立 Android Host 开发验收（2026-11-20）

这是所有者新增的 Android 工作范围，不改变此前桌面版本的发布结果。

- 源码：独立 Android 身份、共享 SPAKE2/配对/TLS 客户端、同一个 Host WSS/Core
  生命周期、独立 Android 能力与三个 MCP 工具；Kotlin/JNI App 位于
  src/host/android 与 src/crates/styx-android。桌面配对调用重用提取后的共享模块。
- 编译与包：ARM64 Android Runtime/JNI、真实动态库、Kotlin 与开发 APK 通过；
  APK v2 签名与 16 KiB 对齐验证通过。0.5.1-android-dev APK SHA-256：
  681827b16362feab0be7d5b6b500135e4020fd823206b7a022b201c904813abf。
- 实际协议：真实回环 SPAKE2→TLS→WSS→MCP 集成测试通过，Android executor 使用替身。
  覆盖 Android-only 发现/状态、MCP 图片、原操作响应丢失后重连不重放、权限未就绪、
  批次阻塞时关闭能力、重新启用和撤销。旧 Host 三项 generation 解码为第四项为零；
  未协商 Android 的 Host 在发出 Android patch 前拒绝，原控制连接保持可用。
- 手机平台实测：Pixel 7 Pro（API 37）安装、JNI 与 Accessibility 真实 fixture 的
  12 项检查 PASS：服务就绪、前台、UI Tree/双 caller、旧引用拒绝、Unicode、坐标手势、
  成功批次、部分失败结果、耗时采样、截图、FLAG_SECURE 遮蔽及引用清理。
  无障碍服务保持绑定，测试前后 PID 17730 不变，Crashed services 为空。
  小型 fixture 的树读取中位数 8.98 ms、截图 152.94 ms，不能当作 Gateway 链路耗时，
  也不能直接与另一 App 的 ADB 历史耗时比较。
- 上轮验收障碍已定位：普通 Instrumentation 会停止目标进程，改用既有 --no-restart；
  独立测试 Activity 的 Kotlin 运行库缺失，改为无额外依赖的 Java fixture；进入动画
  期间的 stale_node 用测试开始前 waitForIdle 解决，未放宽产品目标校验。
  Wildlife provisioning 实际反复打开 VPN 设置页，使用其既有 issuance-paused 标记
  暂停新发行以避免前台冲突，未停止 VPN、路由续期或设备服务。
- Gateway 候选：精确 c903a27 干净源码检查 PASS、Debian 原生构建 PASS；同 publisher
  签名与独立验证 PASS。0.5.1-android.1 是开发验收候选，不是正式 Release。
  manifest：0ddc9ab0869563c903b1bcde1d151d0e66e0c081dab95fc25b4f954918e859f5。
  此记录写入时尚未部署；待确认真实独立配对、ADB 断开后的工具、后台/锁屏/撤销。
- 证据：/home/sid/Developer/Artifacts/Styx/native-android-host-20261119/；
  手机实际结果：/home/sid/Developer/Artifacts/Styx/android-host/platform-acceptance-result.json。
  构建和测试入口见 src/host/android/README.md。

## 2026-11-15 发布历史

C1/C2 结构清理已完成；Linux Desktop、Linux Gateway-only 和 Windows 最终包绑定
`d34887c1ca554b91c3246645de533e2b3e91e9cc` / `0.4.1`。Mac 绑定
`ea84ac7f3abba4f7d7f34f0bb47df996c5aea805` 的 macOS 条件编译并发修复，不能将其他
平台包重标为该 SHA。moedeu-apps Gateway、niuda 和 NAB5 已原配置更新并实际验证。
四项最终下载资产、公钥、安装说明和校验文件已齐，Mac 新修复安装及双 owner 实测通过。
**Stable：GO，已发布。** [Styx 0.4.1](https://github.com/sidnvy/Styx/releases/tag/v0.4.1) 于 2026-11-15 正式公开。

## 2026-11-15 桌面更新与账号验收（历史）

- Windows NAB5：最终 Inno `0.4.1.2019` / `d34887c` 已正常安装，原 GUI 单一
  “Update Styx”完成持久化组件切换。旧 App/Core 14264/5812 正常退出均 exit0，
  重开 App/Core 13940/12064。安装和选定 manifest 均为
  `8d3e59de6495fe4c2d078da9f5d6604b8017933b4400d18405376f1a1d0ca872`，
  实际与选定 Core SHA 均为 `358829a4e50bea43222b5c48fbd2b61d060b3683972a27e3552e77c4da0d35d7`。
  配对三文件与 deployment 摘要不变。经 moedeu-apps 的独立 MCP 通过 Browser 导航、
  nonce 写入及另一次读回、关闭；窗口树读取、Computers→General 安全跳转读回、
  740×940 PNG 实看通过。自有 MCP 会话与一次性任务已清理，日常 Host 保持运行。
  证据：`/home/sid/Developer/Artifacts/Styx/release-0.4.1/final/installation/windows/result.json`。
- Mac PilotMac：最终 `ea84ac7` / App `0.4.1` build 2020 已安装并完成更新。
  选定 manifest `b47ca2e3bdfa3379d65ea8b2a1d1e7cee9f3723f7d718c40a4db001c61b0513c`，
  实际与选定 Core SHA 一致（完整值见原始记录）。原 App/Core/Cua
  43250/43255/43256 正常退出，Core exit0；新进程 43507/43509/43513，配对与配置
  摘要不变。两个独立 owner 共 6 次重叠窗口树读取通过；A 关闭后 B 继续读取 26 行树、
  1024×958 截图（已视觉核对）、Browser nonce 写入及另一次读回、关闭。两 MCP 会话
  均 close0，当前账号已读取新 App 43507 的窗口。
  证据：`release-0.4.1/final/installation/mac/dual-owner-fixed/result.json` 及对应 Mac 安装/版本记录。
  保留 `d34887c` 的 `computer_not_dispatched` / `capacity_busy` 原始失败结果；
  `ea84ac7` 修复 macOS desktop source 的并发观察，不新增配额、队列或重试。
- Linux niuda：最终 `d34887c` / `0.4.1` 已沿用原安装和配对更新，manifest
  `1f6e34021662549c95f9a7f3035b747163a4338743eb32d40f8ac649e13bcd7b`。
  旧 PID 1186076 正常退出 exit0，正常启动 exit0，新 PID 1209911，配对摘要不变。
  当前账号 Browser nonce 独立读回、5 个窗口、1024×611 截图及截图后继续列窗口 PASS。
- moedeu-apps Gateway：最终 `d34887c` Gateway-only 已正常更新并重开，身份、配对、
  Tunnel 保留。远端 `artifacts/gateway-release-0.4.1-final/verified.json` PASS；
  后续 Mac/Windows 验证期间保持该 Gateway 稳定。
- 发布身份沿用既有 Styx publisher 和 Mac 本地签名。不新增 notarization、Authenticode
  或在线自动升级门槛。四包在 `release-0.4.1/final/assets`，当前 SHA256SUMS 六项核对
  通过；新 Mac 包已替换，SHA256SUMS 六项已刷新核对，旧 Mac 包留存 `assets/superseded`。

以下旧版本章节只保存已完成的安装/账号证据，不覆盖上述当前运行状态，不产生新待办。

## 用户安装后的 niuda 能力修复与验证

用户原安装和配对保留，Host PID 929414 未变，配置摘要前后相同；没有重装或重新配对。
修复源码 `70e634a2aaff2aadfc135c40c59583a2e0409a8b`：管理列表改用实际共享连接状态，
删除 MCP 出站 256 KiB 限制及其关闭会话路径。保留入站请求边界，没有增加会话/能力配额。
完整整合质量门与官方 SDK 大图片后同会话继续调用回归 PASS；Debian 12 构建及原身份签名 PASS。
moedeu-apps 通过正常退出、备份、发布选择、重开更新为 `0.4.1-gateway.2`，选定与运行组件一致，
Gateway 身份、配对与 Tunnel 配置摘要不变，旧 22026 服务未动。

原 niuda Host 经 moedeu-apps 的认证 MCP 实际通过：三项连接 connected、4 个真实窗口、
1024×611 PNG（响应 357646 bytes，超过旧限制）、截图后同会话再次读窗口、浏览器写入文字并独立
snapshot 读回、关闭自有浏览器会话。截图已视觉检查。证据目录：
`/home/sid/Developer/Artifacts/Styx/niuda-capabilities-20261115/result.json`。
随后按用户授权在 ChatGPT 正常创建并 Connect「Styx moedeu-apps」，复用原 Tunnel，
没有改安装、配对或 Gateway 密钥。账号对话 `6af85143-d800-83ec-98c2-6538d0609351`
实际发现 niuda、读 4 个窗口、返回 1024×611 PNG、截图后再读窗口；Browser evaluate 写入
`Styx-ChatGPT-acceptance-20261115` 后由 snapshot 独立读回并关闭测试会话。
账号验收回复保存在同目录 `chatgpt-account-result.json`；Gateway 的 ChatGPT last seen 已刷新，
Host 仍为 PID 929414。该历史单项不含 Computer 点击/输入、双对话或长驻验收，当时未作 Stable 放行。
用户要求清理旧同名插件：旧 0.1.0 已删除；旧 1.0.1 App-backed「Styx」两次返回
`Couldn't delete plugin. Try again`，仍未删除。新连接可用，不因清理错误重建或改配设备。

## Linux 双形态安装交付（0.4.1-preview.2）

本机首次安装前清场已完成：旧测试 Gateway PID 860339 正常退出，临时 unit 已回收，
38443 端口释放，本机无 Styx 用户服务/进程，默认配置与命令入口未创建。剩余测试配置
已迁入既有归档；moedeu-apps Gateway 只读认证查询成功、未修改。证据见本版
`local-test-retirement.json`。

[双形态预览版已公开发布](https://github.com/sidnvy/Styx/releases/tag/linux-v0.4.1-preview.2)，四项资产摘要匹配。
源码 `27a61d61107b56e328001e011ad8f379750a50e1`；完整材料在
`/home/sid/Developer/Artifacts/Styx/linux-install-preview-0.4.1-preview.2`。
Gateway-only、Desktop（Host＋可选 Gateway）两个包均带单一 `./install.sh`：
安装验证并复制至持久用户目录，注册固定命令，再进入原设置或更新流程。
Gateway-only 通过明确确认及系统授权处理已有 user manager 的 linger；桌面不改 linger。
Linux `styx quit`/`styx start` 复用原 service authority，不增加后台进程或持久管理层。

- 20 项最终整合检查 PASS，Debian 12 构建与两套原发布身份签名、分发校验 PASS。
- Desktop 最终包真实安装、下载目录移走后运行、同版本重装不改变进程/配对、
  原进程退出、原身份重开、卸载服务 PASS：`Artifacts/Styx/it2/result.json`。
- Gateway-only 最终包安装、systemd 启停/卸载 PASS，未创建 Host：
  `Artifacts/Styx/ig2/result.json`。两份结果已复制到本版本交付目录。
- 两次测试环境失败完整保留：第一次测试路径超过 Unix socket 长度限制（155字节），
  第二次 tmpfs 用户配额阻断复制；没有据此报告产品验收通过或重放未知服务动作。
  最终测试使用持久磁盘上的短测试目录。默认用户配置未创建，moedeu-apps 未改配。
- 独立代码审核发现并修复连续升级 CLI 链接及未完成升级恢复问题；
  当前安装入口委托既有 updater 处理原步骤，只在其确认完成后补齐命令入口。
- 正常 CI 的 Linux assets 已改为同一 distribution producer；其 9 项局部测试 PASS，
  不再保留第二套手工 README 包装。
- 用户本人首次安装与加入已完成；直接 MCP Browser/Computer 验证见上。该历史检查时账号与并发验证尚未完成，当时未作跨平台 Stable 放行。
 不要替用户预配对再声称其首次安装已通过。

`/tmp` 历史材料已迁移至 `/home/sid/Developer/Archives/Styx/tmp-20261115`，
记录见 `relocation.json`；当次占用由约23GB降至8.7GB，运行中的测试 Gateway 配置保持原位置。
后续大文件与证据统一走 WORKSPACE.md 的持久目录。

## 前一轮安装交接（已由 preview.2 替代）

所有者要求：开发验证完成后，由用户亲自从完整安装包走首次安装、配置、加入
moedeu-apps Gateway 和 ChatGPT 验收；不得预先配置后宣称用户流程通过。

- 完整 Linux 包 `0.4.1-preview.1`，源码 `61101aa5e0334bea3b3a08d99e0a12ed950206eb`，
  包含 `6c97598` 的 worker 配额修复。20 项质量门、Debian 12 构建、原发布身份签名、
  实际 CLI release verify 均 PASS。非 Stable 放行，不代表已安装或账号端到端通过。
- 包与证据：`/home/sid/Developer/Artifacts/Styx/linux-user-preview-0.4.1-preview.1`。
- 旧测试 Host PID 469180 已单次 SIGTERM 正常退出，服务 inactive/dead、Result=success；
  原文件保留，退出前后快照位于该目录的 `test-host-backup/`。未替用户建立默认配置、
  执行 setup 或生成新配对；moedeu-apps Gateway 保持原配置。
- Linux 入口仍为 CLI。完整包解压到持久目录，用户用 `styx install` 注册命令，
  在本机图形桌面终端运行 `styx setup`，选择 Join an existing Gateway，填地址及短码。
- 发布暂缓：所有者再次明确 Linux 必须交付 Gateway-only 与桌面 Host＋可选 Gateway 两种包，
  并把正式安装方式纳入验收。完整包已经包含组合角色，但当前手动解压、注册链接和
  setup 分离的入口仍需收敛；不能把本地预览包当作正式交付。自动审批在执行前拒绝了
  tag/公开 Release 发布，尚未重新提交。
- systemd 现状：两种角色都使用现有 user service，setup 安装/enable/start，
  `WantedBy=default.target`、`Restart=no`；不自动 sudo 或开启 linger。
  Gateway-only 必须明确无人登录时的持久运行方案；沿用原 user manager 的实现时，
  由安装流程明确处理服务用户与 linger，而不是声称 login service 就等于开机常驻。
  桌面包使用当前用户，Computer Use 跟随实际图形会话；不把整台 Host 绑定某个桌面窗口。
- 待用户完成：首次安装与加入、ChatGPT Exec/Browser/Computer 独立效果，
  双对话并行与其中一个退出后另一个继续，以及修复后桌面 watcher 长驻观察。

## 已发布的 Linux Gateway 先行版

2026-11-15 按所有者要求先交付 Gateway：
[0.4.1-gateway.1](https://github.com/sidnvy/Styx/releases/tag/gateway-v0.4.1-gateway.1)，
源码 `2d3fe693a4b38a75974cc972f2ee8d4af4bd784b`。仅 Linux Gateway/Core + Tunnel，
不包含桌面 App/Host 执行器，不将跨平台重构版 Stable 标为通过。

- 同源 20 项质量门 PASS，Debian 12 原生构建与签名 PASS；GitHub 三项资产摘要逐一匹配。
- 本机 38443 原配置更新，实际 Core/选定 manifest 与包一致；原 Linux Host PID 469180、
  身份及配对不变。双独立 MCP 的 Exec/Browser 与 A 退出后 B 继续通过。
- moedeu-apps 22027 原配置更新及新版正常退出重开通过，revision 7；新 Core PID 2611732，
  TLSv1.3/认证管理查询通过，身份/配对/Tunnel 配置保持，旧 22026 服务未修改。
- manifest `5cea14d3ca06a012924671b4c9fb399265cfc891f9c1bad9511c611db9cdac9a`，
  Core `9300e96c32f6223c979d46e6a55342f7c60eb3b9c2a90f2457f74ee51112f571`。
- moedeu 原旧版退出 4/两个远端 owner 未确认完整保留；独立确认本地所有组件退出后继续，
  没有重放 stop。新版再次正常退出为 0，owner/transport 未确认数均为 0。
- 本机第一次即时读取新进程 `/proc/exe` 权限失败；独立读取确认实际新 Core 后补记，未重放更新。
  时钟下界与 Tunnel 运行期临时头/健康文件正常刷新，不把它们当持久身份变化。

最终证据 `/home/sid/Developer/Artifacts/Styx/gateway-preview-0.4.1-gateway.1/release-verification.json`。
该 gateway.1 历史验收时四个 Host 离线，本机旧日常 profile 已于 11/13 清理；当时不能
宣称原身份恢复或账号可用。随后用户正式安装、配对与当前版本验证以上文结果为准。

## 新发现的 Host 配额遗漏

本机 Computer Use 返回 `SESSION_DISCONNECTED`。独立系统日志证明旧 Host 的
`__linux-desktop-watch` PID 469223 在 11:20:23 因 SIGXCPU 退出，早于 Gateway 更新
15:29。原因是 hidden worker 仍有累计 CPU 2/3 秒以及 AS/DATA/NOFILE 自设配额。

`6c97598` 删除这些配额及 watcher 以低内存额度判断身份的旧检查；保留原父进程身份、
父进程退出清理、请求期限与禁止 core dump。实际子进程超过 3.25 秒 CPU、128MiB 分配、
64 个文件句柄后正常退出，以及 3 项来源/并发/取消清理回归通过；整合后 20 项标准质量门
PASS（`computer-concurrency/host-worker-resource-quality/receipt.json`）。修复已纳入上述完整 Linux
预览包，旧测试 Host 已退出；仍待用户安装及实机长驻观察。Gateway 先行包不含此修复。

## 已完成，勿重新列为待办

| 边界 | 已有结果 | 证据 |
| --- | --- | --- |
| Gateway 路由，Host 持有 Exec/Browser | 任务与页面跨对话保留；Gateway 不保存第二份 Exec/Browser 目录 | [生命周期与实现记录](DELIVERY-HISTORY-THROUGH-20261115.md#host-运行期与连接生命周期分离2026-11-14开发验证) |
| 本机能力由 Host 执行 | 能力关闭停止对应任务，其他能力继续；Mac、Windows 有原生记录 | 历史中的能力设置、Browser、Windows 原生验证检查点 |
| 短码自动加入、更新后改配 | Windows 正常短码加入及更新→换中心→退出已通过 | [Windows 闭环](DELIVERY-HISTORY-THROUGH-20261115.md#更新完成后的所有权释放与-windows-实机闭环2026-11-14) |
| 统一导航、单窗口、单一更新入口 | Mac/Windows 普通入口已收敛；两端原配置更新、退出重开有证据 | [桌面收敛](DELIVERY-HISTORY-THROUGH-20261115.md#桌面统一入口与单窗口收敛2026-11-15) |
| 运行时数量配额及清理锁误拒绝 | 已删除数量准入，清理期间等待原锁；Windows/Linux 各 17 次双对话窗口读取及 Exec/Browser 延续通过 | [最新实机检查点](DELIVERY-HISTORY-THROUGH-20261115.md#取消运行时配额与双对话实机验证2026-11-15) |
| ChatGPT 单对话使用两台 Host | 真实账号 Exec/Browser 双设备效果已通过 | [账号路线](DELIVERY-HISTORY-THROUGH-20261115.md#独立-chatgpt-账号路线2026-11-14) |

## 源码收尾审核及具体清理清单

C1/C2 已实施源码删除，Mac/Windows 原生编译、安装及三能力实测已有结果。剩余的是当前
发布动作；最终绑定及 Mac ea84ac7 并发实测已完成，不再重复编译或重装。

| 项目 | 审核证据与判断 | 下一步及完成标准 |
| --- | --- | --- |
| C1 Windows 旧 UI 模式 | InitializeCore 只接受 rust_host；已删除 ShowPage/ShowStatus 的旧模式路径、ReconnectResult 等专用回调及旧测试状态 | 源码完成，草稿/状态检查已迁到原生状态，共享向导保留；Windows 原生编译、正常主窗口、设置及图标安装路径已验证；托盘正常退出与同配置重开已通过 |
| C2 旧预算对象与参数 | 已删除 bootstrap Partitions、HostLinkBudget、Codex partition 句柄及 BrowserIoBudget/CuaIoBudget 空对象 | 源码完成，保留实际传输缓冲、期限及进程清理所有权；Linux 本机验证见下文，Windows/Mac 条件编译消费者已更新且原生构建和三能力实测通过；Mac ea84ac7 双 owner 实测已通过 |
| C3 低层私有协议 | `host/protocol` 的 prepare/dispatch 仍服务 Core 资源协议、Computer 及回归；公开 Exec/Browser 经 Host 目录 | 保留有消费者的部分；删除前给出具体调用者清单，不能因为名为 private/legacy 就整片删除 |
| C4 Gateway 的 ComputerContexts | `gateway/paired/backend_computer.rs` 按 owner/device 保存 Cua 操作关联；backend cleanup 清理该 owner | 属于当前 Computer 关联，不是重复 Exec/Browser 目录。未发现需要另造 Host 管理层的依据；不为形式统一迁移 |
| C5 更新事实归属 | `app/runtime_update.rs` 持有原更新记录；Windows UpdateStyx 调用同一 Core 操作 | 保留原记录恢复和身份保护；不把准备/提交等内部接口重新暴露成用户步骤。不凭接口数量断言重复状态 |

审核覆盖 Gateway 公共路由/owner cleanup、Host 目录与启动组合、Windows 模式分支及
更新入口；不是对全部源文件的穷尽证明。未发现 Gateway 重新持有 Exec/Browser 目录。
C1、C2 是结构收尾，不能仅凭编译通过关闭。本次已删除 Windows 被替代的旧页面、
回调和测试状态，以及 Host bootstrap/link、Codex、Browser、Cua 的逻辑预算对象和透传参数。
保留真实传输缓冲、执行期限、原生进程所有权与清理；没有新增准入层。
Linux Runtime 严格检查通过，348 项单元测试通过；真实 Codex 保留/归档场景通过，
确认未知结果不重放、进程退出及 reader/stderr 回收。整合源码 `8f8d278` 的 33 项质量门
全部 PASS，包括完整 workspace、真实 Codex 动作、Browser Host 和 Browser 引用场景。
证据：`/tmp/styx-browser-handoff-20261114/computer-concurrency/refactor-cleanup-quality-v2/receipt.json`。
首轮失败原件保留在同级 `refactor-cleanup-quality`：旧动作测试要求已删除的 slot Busy；
修正过时断言，未恢复配额。Browser 首轮因开发项目缺依赖未启动，复用原锁定依赖后通过。
两端条件编译接口、原生构建与正常更新已有上述当前证据；Windows 页面和正常退出重开
已通过；Mac 当前账号读取及 ea84ac7 双 owner 实测已通过。

## 角色与入口证据核对

下表归并可复用的历史证据；最终运行绑定以上述当前状态为准。

| 角色/入口 | 已有依据 | 本轮边界 |
| --- | --- | --- |
| Windows Host-only | 历史“更新完成后的所有权释放与 Windows 实机闭环”：正常短码自动加入、更新后改配、原配置退出重开；“取消运行时配额与双对话实机验证”：d1cb41c 双对话独立效果 | C1 后原生编译、设置/主窗口和托盘正常退出重开已通过，最终 d34887c 安装、同配对更新与正常重开已通过 |
| Mac Host-only | 历史“本机测试 Gateway 与 Mac 能力开关”：正常短码自动加入，三项能力关闭/重开及原配置恢复；“桌面统一入口与单窗口收敛”：用户确认单窗口、正常更新退出重开 | 最新配额/C2 已完成安装和直接三能力验证；当前账号读取及 ea84ac7 双 owner 实测已通过 |
| 桌面 Gateway+Host（Mac/Windows） | 历史“已完成的设备选择基础”记录 GUI Tunnel 配置；`app/runtime_bootstrap_tests.rs::desktop_gateway_setup_requires_tunnel_before_pairing_local_host` 覆盖必配 Tunnel；更早平台矩阵有组合角色运行记录 | 本轮共用 Core 的必配 Tunnel、本机自动配对及正常清理回归通过；最终入口按下文差分证据关闭，不宣称重新全程 GUI 创建 |
| Linux headless Gateway-only | 历史“本机测试 Gateway 与 Mac 能力开关”明确本机无 Host、无 Tunnel 的 Gateway，随后独立账号路线接入测试 Tunnel | CLI 可先运行再接入 ChatGPT 有实际记录；最终 d34887c Gateway-only 已正常更新、重开并保留 Tunnel/配对 |
| Linux 桌面角色 | 当前 Linux Host 有 d1cb41c 窗口读取、双对话 Exec/Browser 记录 | 实际入口是 CLI 桌面向导；本轮隔离组合角色设置及原配置恢复通过，不代表 GUI 验收。首次 Exec 可取消遗漏已修复并通过真实开/关两条设置及重开场景 |
| 能力关闭、明确撤销、断线恢复 | 历史 Mac 能力开关、Windows 原生验证记录本机关闭只停止该能力；“Host 运行期与连接生命周期分离”记录真实 CLI 在线撤销停止任务、Gateway 重启后原任务继续 | 保留不受影响证据；C2 的执行器生命周期以本轮真实场景复核，Windows 最终安装已覆盖；Mac 最终并发修复实测已通过 |

本轮补验（2026-11-15）：`refactor-desktop-setup-exact.log` 的共用 Core 场景 1 项通过，
`refactor-cli-hub-setup.log` 的真实 CLI 组合角色首次设置、原配置恢复不重新配对场景 1 项通过。
`refactor-join-recovery.log` 的短码一次消费、Gateway 重启领取与未知结果不重放场景 1 项通过。
日志在原 `computer-concurrency` 证据目录。CLI 使用本轮已构建的 debug CLI 与原 d1cb41c
签名 payload；这是入口与恢复验证，不宣称最终同版本发布包已验收。第一次 Core 测试过滤
未匹配（0 tests）的记录保留，正确模块路径执行后才计通过。
Linux 桌面现有 CLI 首设缺 Exec 可取消选项，违反 REFACTOR-PLAN 的初始能力规则。
源码 `96aa1eb` 已补齐默认开启且可取消、部署传递与重开保持；CLI 局部 15 项测试和
all-targets Clippy 通过；整合后 `refactor-role-quality/receipt.json` 的 20 项标准质量门全部 PASS，
绑定源码 `96aa1eb1153ebab60547ccc0c74ef695d39f8d7b`。`refactor-cli-exec-roundtrip.log` 中两个真实隔离场景并行通过：
Exec 开启/关闭均连接成功，正常结束后原配置重开，部署与配对文件保持不变。无新增 GUI。
该历史检查时两端离线；现已完成最终原生构建、安装及上述实测，离线不再是待办。

## 最终决定与发布动作

**Stable：GO。** Windows、Linux Desktop、Gateway-only 的最终运行绑定与 Mac 新修复
安装、正常退出重开、双 owner 独立效果均已通过。最终四包、公钥、安装说明和刷新后的
SHA256SUMS 已准备，不新增测试门槛。

正式版本 `v0.4.1` 已于 2026-11-15 14:31:16 UTC 公开，非草稿、非预发布。
[Release](https://github.com/sidnvy/Styx/releases/tag/v0.4.1) 的四项下载、公钥、安装说明及
SHA256SUMS 共七项均已上传，GitHub 服务端摘要与本地已验收资产逐一一致。
证据：`release-0.4.1/final/github-upload-verification.json`；本轮无剩余发布阻塞。
Linux/Windows/Gateway 实际源码为 `d34887c`，Mac 为 `ea84ac7`；保留 macOS-only
条件编译差分依据及未受影响平台证据，不将所有包标成同一源码 SHA。

组合角色新增入口按差分证据关闭，不另设改配或重建生产拓扑的门槛：旧 Mac/Windows
Gateway+Host 运行/退出证据，共享 Core 的必配 Tunnel、成功创建及本机配对实测，初始
Exec 与 CLI 首设/恢复实测，最终原生编译/控件及适配层审查共同覆盖变化。Windows 最终
`--self-test` 在隔离可执行文件副本中 exit0，7 页原生控件、新建/已有角色导航保护、Exec
草稿保持通过；无 Core 启动或 Gateway/日常 profile 变更。证据在
`release-0.4.1/final/role-entry/windows`。两端 GUI 将 Tunnel 和 Exec 字段传给同一
`createLocal` 操作；此结论不宣称最终包两端 GUI 全程重新创建 Gateway。

源码清理完成不等于发布完成，安装完成不等于保存的组件选择已经切换。当前选择以
持久化 `state.json.runtime_selection_v1` 和实际进程为准，不能以保留的初始 deployment
输入路径判断更新失败。

## 不属于本轮阻塞

在线自动升级、Mac/Windows 常驻 OS 服务、新增登录启动实现、自动中心接管、Claude 接入
仍遵循 [延期范围](REDUCED-SCOPE.md)。已工作的能力不删除，但不借收尾扩展建设或验收。
上一轮口头列出的“在线升级、Mac 登录启动待补”不应自动升级为当前发布门槛。
不改生产 Tunnel/plugin，不操作 piermini，不负责底层网络保障。

## 维护方式

每次只更新本页的当前状态和剩余项。详细过程、失败原件和旧“下一步”放入
[历史记录](DELIVERY-HISTORY-THROUGH-20261115.md)或原 artifacts，不把它们追加为新待办。
关闭一项写明对应源码、实际入口和结果；新增一项必须指出违反了哪条已确认行为，
或哪项必要证据确实缺失。不要为每一步建立新候选、新项目或新的批准流程。
