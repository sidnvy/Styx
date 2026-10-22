# 离线 Host payload 升级与发布者迁移

本流程解决 App 已替换、已安装 Host 仍选择旧 release 的情况。它是同一 Core 的
维护事务，保留设备身份和配对。首个原生适配器面向 macOS、无常驻 Host/Gateway
服务且 App 已退出的部署；不把停止连接当作任务排空，不主动结束用户任务。

## 使用边界

- 当前可执行入口是离线 CLI。App 后端共用接口已接通，但运行中的 App 会被原生
  检查拒绝；没有“一键在后台升级完成”的承诺，也不增加一个无效的更新按钮。
- 相同 publisher 的候选必须通过已安装信任的完整签名及文件校验。
- 更换 publisher 时，只接受已登记的同路径、同稳定证书 Styx App 内固定资源位置。
  新包的公钥自声明、局域网信任和任意 API 路径都不能替代原信任锚。
- 系统权限、设备私钥、配对凭据和浏览器资料不在迁移写入范围。
- 不安装、删除或修改原生服务。存在服务定义、已加载任务、运行中的 App/Host/
  Browser 或无法确认的原生状态时拒绝，而不是尝试关闭它们。

## 事务

1. `host-payload-plan STATE BUNDLE` 验证原配置、已安装代次、候选与原生离线边界，
   产生绑定当前文件内容的计划。计划是私有维护文件。原生边界不满足时返回
   `blocked` 和固定原因（运行中、服务仍存在或需要独立更新器），不产生可执行 planId。
2. `host-payload-apply STATE PRIVATE_PLAN --authorize` 再验证计划，在共享管理锁下
   stage 完整签名 release，保存旧/新文件快照并逐项写入执行记录。
3. 同步 publisher、active pointer、稳定启动文件、服务描述和 Core 配置/证据，
   不只替换某个二进制。完成后保持停止，结果不宣称进程或聊天账号验收成功。
4. `host-payload-status STATE` 查看事务；失败或中断后使用
   `host-payload-rollback STATE TRANSACTION --authorize`，只恢复已记录且未被外部
   改动的原始文件，不自动重放启动或命令。

App API 的 plan 只选择启动器提供的随包候选；客户端不能替换公钥或候选路径。
apply 只消费该管理会话刚生成的一次性 planId。CLI 和 API 调用相同 Core 方法。

## 恢复和历史版本

未完成事务保留 `advance.lock`，旧 Core/Gateway 也依靠它阻止启动。
**不要手工删除锁。** 显式恢复验证记录与所有权后处理该锁。
新 Core/Gateway 还会检查迁移日志，拒绝半更新状态；此额外检查不会追溯改变已发布
旧二进制的行为。Gateway source contract 3 包含该检查，同时保留 contract 2 和
历史无版本应用的读取/回滚兼容性。

跨 publisher 时，普通单公钥 release rollback 无法验证旧代次；必须使用本事务
保存并核对的原发布者及原始文件。旧 release 不删除。

## 仍需后续实现及验收

活动任务的原子停止接收与排空、App 退出后独立更新器交接、macOS/Windows 已安装
服务更新、Windows/Linux 对应原生迁移适配器、更新后的真实 Exec/Computer Use/
Browser/聊天账号验证不由本离线文件事务替代。测试中的原生文件迁移、服务观察、
任务运行、系统权限和账号验收分别记录。

## 历史热修复对账

旧安装回执可能仍描述更早的版本。计划会明确列出回执版本与已验证 active 版本，
并单独记录旧 host.prepare.serviceConfiguration 校验值的修复。只有当前签名 release、
publisher、bootstrap、服务路径、身份及部署绑定全部通过时才允许这项对账；
历史回执不提供执行路径或新信任。其他已完成步骤的证据漂移仍拒绝。
执行记录保留原始字节，回滚恢复原来的记录，不补造过去的运行成功。
