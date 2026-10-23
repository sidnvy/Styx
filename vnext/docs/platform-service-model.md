# 跨平台服务与网络授权边界

2026-10-23；源码审计基线 `30dd53e`。这是实现边界，不是全部验收通过声明。

## 共用 Core，平台监督进程

Gateway 是普通 HTTPS/WSS 服务，三平台均可承担该角色。当前产品不提供 VPN、
虚拟网卡、系统流量过滤或透明代理，因此不引入 macOS System Extension / Network
Extension。平台监督机制负责启动、退出与崩溃恢复；Core 继续负责同一权威配置、
身份、计划、事务及回滚。不能为后台模式再建一套角色配置或复制配对身份。

| 模式 | 当前实现 | 无人登录时的边界 |
| --- | --- | --- |
| macOS App | 用户登录会话中的 App/Core；关闭窗口不等于退出 | 现有 LaunchAgent 不等于 LaunchDaemon；不能据此承诺开机未登录可用 |
| Windows App / 已有后台任务 | 当前用户登录启动；任务为 InteractiveToken + Limited | 现有任务不是 Windows Service，不能据此承诺 Session 0 可用 |
| Linux CLI / 用户服务 | 前台 Core 或 systemd user units | 需分别观察 user manager、linger 及各角色 unit 是否启用；不能从配置 enabled 推断运行 |

无人登录 Gateway 或 Exec 必须使用明确的受限服务身份及平台现成服务机制。
不能将桌面任务简单改成 root/SYSTEM 服务，也不能让 Exec 隐式获得更高权限。
Linux 已有用户服务可以复用显式配置的 linger；不得由普通状态检查自动启用。
macOS LaunchDaemon 与 Windows SCM 模式仍需要单独实现和原生验收。

Computer Use 只有在有效交互桌面及系统授权满足时才就绪。服务存在、WebSocket
已连接都不足以证明桌面可操作。Windows Session 0 不承载用户桌面；Linux 无
Hyprland 会话时不宣称 Computer Use 就绪。Browser Automation 单独验证浏览器
及 profile 的实际可用性，不能借用 Cua 的状态。

## 生命周期与所有权

- 关闭设置窗口：App 继续运行。
- 正常退出 App：停止该 App 所有的组件及其自动恢复；保留 CLI 独立管理的服务。
- 注销：桌面会话能力不可用；只有已配置且实际运行的无人登录服务可继续提供对应能力。
- 重启：启动机制、进程恢复、网络连接恢复及聊天账号调用分别验收。
- 网络未就绪：恢复连接并复用身份；不自动重新配对，不重放结果未知的操作。
- 更新或回滚：保留身份、权限身份和配置；按既有事务对账实际 App/Core/Host 版本。

## 网络授权属于操作系统

macOS 应用防火墙的传入连接提示，与“本地网络”隐私授权、辅助功能、屏幕录制是
不同机制。普通 TCP listener 不需要借助系统扩展。建立安全入口需同时满足监听、
路由、TLS、系统网络政策与 Styx 配对验证；不能将 TCP 可连接等同 TLS 或配对成功。

PilotMac 的实际日志与系统窗口已证明存在待处理的 `node` 传入连接提示。产品应
使用可识别且签名稳定的组件，并在等待时明确提示用户完成系统操作。不能把手动
寻找 App 内部 Node 文件并添加防火墙规则作为正常 onboarding。Helper 包结构和
显示名调整必须实测系统提示；它们本身不证明 TCC responsibility chain 已修复。

用户亲自处理系统授权。程序不代点允许、不修改 TCC、不关闭防火墙、不修改 VPN
来掩盖问题。没有新提示也可能是旧提示尚未处理，不能凭此判断签名或 Helper 失败。

## 验收证据分层

依次记录配置意图、服务定义、实际进程、连接/能力、系统授权和账号调用。
Linux 的 linger 与 enabled unit 只证明开机启动前提；物理注销/重启仍需独立记录。
签名验证不等于授权延续，编译成功不等于界面可用，已有账号成功不等于新用户引导通过。

### 平台依据

- [Apple：Local Network Privacy](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy)
- [Apple：应用防火墙](https://support.apple.com/guide/mac-help/block-connections-to-your-mac-with-a-firewall-mh34041/mac)
- [Apple：SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)
- [Microsoft：Interactive Services / Session 0](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services)
- [systemd：loginctl enable-linger](https://www.freedesktop.org/software/systemd/man/latest/loginctl.html)
