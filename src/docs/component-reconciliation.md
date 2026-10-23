# 组件更新对账（2026-10-22）

App、Core 与 Host payload 是不同的版本来源。替换 App 并不证明已安装 Host
payload 被替换；进程在线也不能证明它使用了新 payload。已安装 release 的
`active.json` 和受信任的签名 manifest 是组件版本的依据。

## 当前接入

`readDeploymentComponents` 是 Core 的只读接口。App `/api/status` 的
`components`、认证后的 `/api/components`，以及
`components STATE [PRIVATE_ARTIFACTS_JSON]` CLI 使用同一实现。App 使用启动器
传入的随包 artifact defaults，CLI 可传入同一私有文件作比较，不另建角色配置。

接口验证配置与执行记录绑定、active pointer 与 manifest 绑定及 Ed25519
manifest 签名；不在每次界面刷新时重新读取整个 payload。
`payloadIntegrity: not_rechecked`、`runtimeHealth: not_observed` 是明确限制。
完整文件校验和实际新进程验收仍属于更新事务。

- `aligned`：受信任的 manifest 与候选完全相同，不代表进程或权限就绪。
- `update_available`：同一 publisher 下的不同版本；尚未证明可升级，也不自动降级。
- `publisher_changed`：必须先审查信任迁移，不能直接替换旧 pin。
- `same_version_conflict`：版本号相同而内容不同，不能覆盖。
- `candidate_unverified` / `unavailable`：证据不足，不推断已更新。
- `needs_recovery`：存在未完成事务，先恢复。
- `candidate_not_supplied`：只观察已安装版本，没有候选作比较。

Mac 设置和 Windows 状态使用该来源显示未更新/需处理的提示。对账不停止任务、
不替换配置、凭据或发布者，不改变既有启动行为。

## 两种签名身份

macOS codesign 身份用于 App 的系统身份和权限连续性；Host publisher 是签署
Host manifest 的 Ed25519 身份。保持前者不等于保持后者。

Mac 构建现在支持显式持久 Host publisher，并在公开 receipt 记录模式和 pin。
详见 [Mac 打包](macos-app-packaging.md)。历史预览使用每次构建产生的临时 key，
新的持久 key 不能直接获得旧安装的信任。

## 尚未完成

此改动不等于完整自动更新。macOS 无常驻服务的离线 publisher 迁移现已接入
[Host payload 事务](host-payload-migration.md)。macOS/Windows 已安装服务更新、
Host-only 的独立健康证明、活动任务排空，仍需实现并验证。
迁移必须保留设备身份/配对与可回滚的旧 release，不得用重装或改 pin 冒充更新。

Linux 的现有 stopped-service 更新与恢复能力不能直接外推到上述平台或运行模式。
每次交付仍分别记录源码、安装包、已安装 App、实际 Host release 与真实验收。
