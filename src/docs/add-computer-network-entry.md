# 添加电脑的网络入口：历史说明

本页原描述 2026-10-22 的 JavaScript 管理实现及验收，相关入口已删除。
当前实现由 Rust Gateway 持有邀请、设备信任和撤销，Host 通过当前原生配对流程加入。
生成邀请即批准一台设备加入，界面不再要求第二次管理员审批。

当前职责与启动模型见 [架构](architecture.md)，产品行为见
[已确认的 Gateway/Host 设计](rust-core-rewrite/REFACTOR-PLAN.md)，
CLI 操作见 [原生配对](rust-core-rewrite/NATIVE-CLI-PAIRING.md)。
过去的源码、平台验收和设备状态不能代替当前发布或部署结果。
