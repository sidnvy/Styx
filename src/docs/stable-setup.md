# Styx 0.4.0：Gateway 与三平台 Host 设置

部署方式：**moedeu-apps 只运行 Gateway；Windows、macOS、Linux 电脑作为 Host；ChatGPT 只添加一个 Styx 连接。**
本指南不代表 Stable 已放行；正式 GitHub Release 链接在发布时补充。

## 1. 下载并核对

从同一个正式 0.4.0 GitHub Release 下载对应资产及 `SHA256SUMS`、`styx-publisher.pub`：

| 用途 | 资产 |
| --- | --- |
| Windows x64 Host App | `Styx-0.4.0-windows-x64.exe` |
| macOS Apple silicon Host App | `Styx-0.4.0-macos-arm64.dmg` |
| Linux x64 Host | `Styx-0.4.0-linux-x64.tar.gz` |
| moedeu-apps（Debian 12 x64）Gateway | `Styx-0.4.0-gateway-debian12-x64.tar.gz` |

计算下载包的 SHA256，与 `SHA256SUMS` 同名行比较：Windows 用 PowerShell `Get-FileHash -Algorithm SHA256`，macOS 用 `shasum -a 256`，Linux 用 `sha256sum`，命令后接实际下载文件路径。
安装包内不包含你的设备身份或配对；固定 Runtime 发布者公钥的 **SPKI SHA256** 为：

```text
bbb49c2626c3d4ef3cf9e1679db5305b100cee4a8c41c29c958ede82fb868bed
```

这个值是公钥指纹，不是安装包哈希；设置时从可信发布说明核对，不能只相信下载包自带的公钥。
Windows 安装器目前没有 Authenticode 签名；Mac App 使用本地证书签名，未获 Developer ID 公证。Runtime 的 Ed25519 签名不等于操作系统发布者认证。

## 2. 在 moedeu-apps 设置 Gateway

1. 以日常管理该服务的普通用户登录 moedeu-apps；将 Gateway 包解压到长期保留、仅该用户可访问的目录。
2. 在解压目录运行 `./payload/bin/styx setup`，角色选 **Gateway only (headless VM; pair other computers later)**，不要选 Hub。
3. 按提示核对 payload、公钥 PEM 和上面的发布者指纹；包内公钥为 `publisher.pem`。
4. 选择其他电脑实际能访问的 LAN/VPN 地址及 HTTPS 端口；只选 loopback 无法让其他设备加入。Tunnel 不代替 Host 到 Gateway 的网络连接。
5. 按[官方 Secure MCP Tunnel 说明](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)创建或复用 Tunnel，关联目标 ChatGPT 工作区；在 Styx 的隐藏输入提示中填写 runtime API key。
6. 核对设置计划后确认。记下 Styx 输出的 Tunnel ID 和图标保存位置；Linux 默认使用当前用户的 systemd 服务。
7. 运行 `./payload/bin/styx status` 查看 Gateway 状态，再运行 `./payload/bin/styx invite`，选其他电脑可达的地址，生成一次性邀请，并选择等待加入请求。

如果原来使用了自定义配置根，继续使用同一个 `--root`；不要为升级另建身份。邀请链接与 runtime key 只在你自己的终端和可信私密渠道使用，不粘贴到 ChatGPT 对话。

## 3. 让电脑作为 Host 加入

每台新电脑使用独立邀请；邀请有效期十分钟。已配置的电脑先恢复原配置，不重复首次加入。

1. **Windows：**运行安装器，打开 Styx，选择 **Join an existing Gateway**。
2. **macOS：**打开 DMG，将 `Styx.app` 放入 `/Applications`，打开后选择 **加入已有 Styx / Join an existing Styx**。
3. **Linux：**将 Host 包解压到长期保留的私有目录，在其中运行 `./payload/bin/styx setup`，选择 **Join an existing Gateway**。
4. 粘贴邀请；App 中先审核链接，核对 Gateway 地址及 CA 指纹，再确认准备。只启用你需要的 Commands、Browser、Computer Use 能力。
5. 回到 moedeu-apps 的邀请终端，核对请求 ID、设备 ID、公钥指纹及比较码，确认与该电脑一致后批准所选能力。
6. 等待 Host 完成加入。在 Gateway 上运行 `./payload/bin/styx computers`，核对设备及各能力的实际连接状态；进程启动不等于已经连接。

Browser 使用设置界面列出的本机已安装浏览器；setup 不自动安装浏览器。
Mac 新签名身份可能需要你重新确认辅助功能、屏幕录制等 OS 授权；由你本人按系统正常流程处理，不关闭 Gatekeeper/SIP 或使用绕过命令。
Windows Computer Use 需要已登录的交互桌面；Linux Computer Use 需要图形会话。各平台保留原有配置、身份和配对文件，不清空 AppData、Library 或 Linux 状态目录来排障。
Windows/Mac 正常 Quit 会停止该 App 的连接；重开后使用原配置。若旧身份未被找到，先核对配置路径，不自动删除或重新配对。

## 4. 在 ChatGPT 添加唯一的 Styx 连接

此步由你自己操作；此前已删除的旧插件连接不会自动重建。各 Host 不再单独添加插件或配置 Tunnel。

1. 保持 moedeu-apps Gateway/Tunnel 在线，打开 [ChatGPT Plugins](https://chatgpt.com/plugins)，选择 **＋ → Add custom MCP server**。
2. 名称填 **Styx**，可上传上面保存的 Styx PNG；Connection 选 **Tunnel**，选择或粘贴同一个 Tunnel ID。
3. 本方案 Authentication 选 **No authentication**：Styx 本地 tunnel client 已向 Gateway 提供 model-only bearer；不要把 runtime key 填入 ChatGPT。
4. 阅读提示，确认后选择 **Create as a plugin**，再安装/Connect；在新对话选择该 Styx 连接。
5. 发送“列出我的 Styx 电脑”，确认返回的是刚加入的设备；再明确指定一台电脑，尝试需要的能力。

若 Tunnel 不出现，核对它关联的 ChatGPT 工作区及 Tunnels Read + Use 权限；若没有添加入口，核对工作区自定义 MCP 权限。步骤依据：[添加自定义 MCP](https://developers.openai.com/api/docs/guides/custom-mcp-server)。
出现结果不确定的操作时，先查看当前状态和实际效果，不反复点击提交、清配置或重配。升级前正常退出 App，并保留原配置；不要把“已装新 App”直接当作“已切换新 Runtime”。
