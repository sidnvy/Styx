# Styx 产品边界与实现对照

2026-10-19：用户确认的目标架构。本文件区分目标与当前实现，不是功能完成声明。

## 三种用户流程

1. 单机：一个Styx App，默认Gateway＋Host；Codex调用确定性安装接口，用户完成系统授权、
   私有MCP关联及聊天端真实验收。无需理解角色或开启多设备。
2. 多机：主台“添加电脑”负责安全可达入口及配对；新电脑明确选择加入后仅运行Host。
   网络发现不构成信任，也不能自动切换已有部署角色。
3. 高阶：Core在headless环境运行，由CLI管理；支持Gateway-only、Host-only（Exec）、
   或两者是目标。没有桌面会话不启用Cua。

App与CLI是管理入口，能力由角色和环境决定。CLI可以管理GUI设备上的Cua，但不会因此
继承桌面权限。GUI主台也可以仅运行Gateway。新增Host不获得设备组管理员凭据。

## 组件与数据责任

| 组件 | 责任 |
| --- | --- |
| Gateway | MCP入口、设备身份/审批、能力授权、转发；不承担本机桌面权限 |
| Host | 本机连接、Exec Server生命周期、可选Cua连接 |
| Cua | 有效桌面会话内的观察与操作，不管理网络信任 |
| App | 原生权限身份、设置、状态、后台生命周期 |
| CLI | 同一Core的确定性管理接口 |
| Core | 共享配置验证、计划、执行、状态与恢复 |

一个安装有一个受保护配置根。期望配置、执行日志、实时状态与凭据各自有明确权威来源，
不能互相冒充。App与CLI使用同一API。Gateway目录负责整组授权，Host保存自己的身份与
本机能力意愿。运行时配置和服务定义是派生数据，变更应通过迁移事务生成，而非分别手改。
系统权限以OS为准，不能在JSON中伪造授权。

## 当前实现

| 领域 | 现有源码依据 | 缺口 |
| --- | --- | --- |
| 单机/加入 | onboarding/core.mjs的create-local和join-existing；加入无Gateway准备步骤 | 两种模式都要求Host配置，缺统一Gateway-only |
| 共用核心 | onboarding/cli.mjs与server.mjs共用core.mjs | CLI未覆盖全部App工作流 |
| 配置 | deployment.json、state.json、派生gateway/runtime.json、Host配置、service.json | 缺完整迁移和统一对账；能力设置与初始安装意图须区分 |
| 生命周期 | onboarding/background.mjs与平台服务适配器 | 前台/后台交接、App退出行为与权限责任链未统一 |
| macOS | host/macos/Styx.swift启动嵌入Cua和权限界面 | macos-launchagent.mjs直接启动Node，Exec子进程可能归Node |
| Windows | windows-task.ps1与Host安装/测试基础 | 尚无与Mac同等完整且验收通过的App配对体验 |
| Headless | gateway/cli.mjs可以单独运行Gateway | onboarding/gateway-service.mjs依赖已准备的Host及其签名Node |
| 配对 | enrollment.mjs、pairing-links.mjs具备一次性邀请、独立审批、公钥加密凭据及撤销 | 两端易读确认及完整产品流程待补 |
| 网络入口 | 默认127.0.0.1，可明确配置本机IPv4接口 | 缺既有部署入口迁移、远端可达性验收、防火墙指导、证书续期 |
| 聊天连接 | 已有私有MCP和隧道 | 聊天端可达不代表配对/Host反向连接入口可达 |
| 桌面并发 | cua.mjs共享连接、排队和引用归属检查 | 同一桌面仍有状态干扰，必须重新观察 |

## 权限与连接设计约束

桌面执行应由稳定身份的App/Helper承载。把Node放进App、改名或补提示词都不能证明责任链
正确。普通桌面走Cua；明确请求的应用脚本另有Automation授权，不能与Accessibility混同。
Exec是否也纳入App责任链需要平台实测，不能保证任意子进程都继承授权。
Windows必须区分用户桌面会话与后台服务；headless Linux仅启用实际可用能力。

添加设备：检查Gateway → 授权开放范围 → 准备安全入口 → 新设备验证TLS及可达性 →
限时邀请 → 双方身份确认 → 能力审批 → Host主动连接 → 实际验收。
不默认信任局域网，不自动开放所有接口或改路由器。异地接入若无中继服务，必须有可达入口。
关闭配对窗口不切断已批准设备；撤销应断开并拒绝旧凭据。
emoji/短码是绑定双方身份和当前握手的确认界面，不是连接密钥；需限制重试及有效期，
正式实现前选用成熟协议并评审中间人攻击防护。用户不手传私钥。

## 实施顺序与验收

1. 角色状态：统一Core plan/status和App输出，加入不创建Gateway；配置意图不冒充健康。
2. 生命周期：Gateway-only脱离Host安装依赖；App/CLI共用安装、启动、停止、恢复。
   覆盖单机桌面、主台桌面、仅Host桌面、Gateway-only、headless Host和headless双角色。
3. 原生包装：稳定Mac权限身份和Windows用户会话组件；实测重启、登录、App退出、升级、
   回滚及授权保留。新系统权限必须由用户亲自批准。
4. 多设备：局域网入口事务及两端确认；验收Mac主台+Windows Host、headless主台+桌面Host。
   覆盖不可达、邀请过期/抢用、错误确认、身份变化、断网重连、撤销与证书续期。
5. 新用户真实聊天端验收后发布；单台热修复不能替代产品验收。

本次先落地角色状态投影onboarding/roles.mjs：从现有配置派生，未新增角色配置文件，
Core plan/status及App后端返回一致字段。computer=requested仅代表安装意图，
deviceIngress=configured_unverified不代表远程可达；不将Gateway-only伪装成已支持模式。
本次不修改piermini运行配置，后续迁移必须保留身份、设备配对和回滚点。
