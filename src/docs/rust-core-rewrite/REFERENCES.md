# Primary technical references

查询日期2026-10-24（Asia/Shanghai）。这些资料用于核实技术边界，不宣称当前机器已安装所列latest版本。R01必须固定实际版本，不能将在线latest直接用于候选。

- [Cargo workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html)：workspace共享Cargo.lock与统一管理，crate边界不等于进程边界。
- [Official MCP Rust SDK](https://github.com/modelcontextprotocol/rust-sdk)：作为MCP实现候选；仍需以Styx冻结协议版本/headers/schema进行兼容spike。
- [Tokio sync/async bridging](https://tokio.rs/tokio/topics/bridging)：异步与同步边界需要明确。
- [Tokio spawn_blocking](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html)：已启动blocking任务不能靠abort终止；deadline和退出事实必须另行设计。
- [Tokio process Command](https://docs.rs/tokio/latest/tokio/process/struct.Command.html)：原生子进程监督接口候选；drop/kill/退出回收与业务副作用分别处理。
- [Axum official crate docs](https://docs.rs/axum/latest/axum/)：HTTP/Tower集成候选，是否单独引入在R01决定，不额外建RPC栈。
- [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)：外部Browser依赖及Node边界；不用latest示例替代当前pin。
- [Windows TASK_LOGON_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type)：InteractiveToken需要已登录会话；S4U非交互且有网络/加密文件限制，不能当作无条件持久用户服务。
- [Windows task security contexts](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)：注册主体、凭据、权限与运行上下文不同。
- [systemd special targets](https://www.freedesktop.org/software/systemd/man/latest/systemd.special.html)：user manager与图形session target的关联应按实际配置验证。
- [Apple launch daemons and agents guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)：历史官方资料说明用户agent随登录存在/注销结束；当前API与注册方式在目标macOS上验证，不能据老文档宣称新系统已验收。

本地一手证据：44cf147源码；`src/docs/architecture-boundaries.md`；工作区`outputs/architecture-review-20261024`的四个模拟probe/57项受影响Exec通过/完整quality收据；`outputs/release-convergence-20261024`的旧候选build/sign/install状态。旧测试通过不代表Rust已有实现。

实施选型补充（2026-10-24）：[encoding_rs Decoder 0.8.35](https://docs.rs/encoding_rs/0.8.35/encoding_rs/struct.Decoder.html)用于增量文本解码；[tokio-util LinesCodec](https://docs.rs/tokio-util/0.7.20/tokio_util/codec/struct.LinesCodec.html)采用显式长度上限。Linux标准File::try_lock实际调用和nix/getrandom安全接口按本机1.94.1与固定crate源码核实；不把Linux行为推断成macOS/Windows已测试。


Enrollment profile validation uses pinned `regex = 1.12.4` for the existing Unicode Letter/Number label and cross-platform path/shell patterns, rather than a hand-maintained Unicode classifier. One OnceLock compiles constant bounded patterns; request values are never patterns. See [upstream Unicode conformance](https://github.com/rust-lang/regex/blob/master/UNICODE.md) and [pinned crate documentation](https://docs.rs/regex/1.12.4/regex/). Cargo.lock pins the added transitive closure; this is not a claim that the newest release was required or that regex validates OS authorization.

Paired native fixture uses the [official MCP Rust SDK HTTP client](https://rust.sdk.modelcontextprotocol.io/) and pinned [reqwest 0.13.5 TLS configuration](https://docs.rs/reqwest/0.13.5/reqwest/struct.ClientBuilder.html#method.tls_backend_preconfigured), rather than implementing an SSE parser. Runtime dev-dependency enables `rustls` (official AWS-LC default); the test supplies an explicit AWS-LC Rustls configuration, TLS 1.3 and only the owned fixture CA, disables proxy/redirects, and never disables certificate/hostname validation. Cargo.lock adds its platform TLS closure without changing preexisting locked versions. This feature is for the test client, not a second product ingress or OS certificate authorization.
