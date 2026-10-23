# Fresh conversation acceptance handoff

Use the merged commit of https://github.com/sidnvy/Styx/pull/37 from the repository main branch. Record its exact SHA before starting. This is a candidate code merge, not a published production release or completed account-side onboarding.

Start a new Codex conversation with this request:

> 从 https://github.com/sidnvy/Styx 的 main 开始，先记录实际 commit SHA，读取 src/docs/fresh-conversation-acceptance.md、src/docs/fresh-onboarding.md 和 src/plugin/README.md。我要从零验收独立 Styx 插件的 onboarding。新建独立 Gateway 状态和凭据、新连接、新插件及新设备注册；不要依赖旧对话、Charon 或任何 pilot 的配置和令牌。先盘点真实可用的构建产物与部署条件，再完成安装、配对、Exec、PTY 和选定设备的 GUI 验收。需要我操作的账户登录、密钥输入、设备指纹确认或系统权限，请在对应步骤明确指出。不能完成的步骤记录为阻塞，不要用 SDK 测试替代实际插件验收。

## Source-to-account sequence

1. Inspect the public source at the recorded SHA. Follow `fresh-onboarding.md` for native setup and `../plugin/README.md` for the package contract. Existing acceptance evidence is supporting history, not a new onboarding result.
2. Inventory deployment targets and trusted signed native artifacts. This merge does not provide public release download URLs. If artifacts are absent, build a candidate using the repository's native build/signing instructions and record provenance plus an independently confirmed publisher fingerprint. macOS GUI additionally needs its signed app and interactive system permission flow.
3. Deploy an independent Gateway with separate owner/admin and model credentials. Choose a fresh supported Secure MCP Tunnel or verified HTTPS MCP endpoint. Hosts still need a reachable trusted HTTPS/WSS Gateway route. Never copy another service's account credentials or device state.
4. Verify authenticated MCP discovery, retain the real discovery receipt, generate the portable plugin package and install it through the supported account workflow. No placeholder endpoints or fabricated verification receipts.
5. Prepare a fresh native installation with `setup-native.mjs`, issue a one-use invitation, compare its actual device fingerprint, obtain owner approval and start the independent service. Existing signed apps may be inspected as artifacts, but their prior permission or device state is not proof of a cold install.
6. In the actual new plugin connection, discover the device, verify passive status, run a harmless exact marker, bounded PTY and cleanup, then a self-expiring owned GUI fixture with independent effect readback. Verify revocation through the owner control plane.
7. Record exact source/artifact revisions, platform, connection identity, results and cleanup. Distinguish PASS, FAIL, BLOCKED and NOT RUN. Do not claim a production release, 24-hour stability or clean-machine installation from narrower tests.

The implemented onboarding is CLI based. A graphical installer is not provided. Prior Linux/Windows/macOS native acceptance and macOS SDK-over-TLS results do not establish actual account-side plugin acceptance. Existing unrelated services remain unchanged until a separately intended production transition.
