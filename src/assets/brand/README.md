# Styx 品牌源资产

2026-10-20 用户提供的正式黑白两版图标，原始文件未重绘或修改像素。

- `styx-icon-dark-source.jpg`：2338.jpg，黑底白色圆形与波纹。
- `styx-icon-light-source.jpg`：2339.jpg，白底黑色圆形与波纹。

用于后续 Styx App、安装包及默认插件品牌，不再用 S、随机图形或其他占位符代替品牌。
能力和系统操作图标保持各自功能含义。原型中的显示裁切不改变这两份源文件。

JPEG 是不可修改的品牌原稿。按照用户后续确认，App、插件与菜单栏实际使用中央圆球和波纹，
不把原稿的展示底板、外框或白色留边一起缩放进图标。

macOS 构建通过 `host/macos/BrandGlyph.swift` 提取同一个透明字形，
`render-brand-icons.swift` 生成黑色圆球 PNG 与 ICNS 各尺寸；界面与菜单栏按当前外观着色。
这属于原稿的确定性资源导出，不重绘波纹。隔离构建已验证；安装中 App 尚未因此更新。

`styx-custom-mcp-icon.png` 是上述黑色圆球 PNG 的 128×128 LANCZOS 缩小副本，
9,163 bytes，供 ChatGPT Custom MCP 的 Choose icon 上传（上限 10 KB）。
2026-11-06 已验证连接安装后刷新详情页保留此图标。CLI、macOS、Windows
均直接分发同一文件，不在安装时重新压缩。SHA-256：
`94df72b8b3981c3d2a7882f317f660532c9d83bcce00dc5559412f462a4258e8`。
原始品牌图片与大尺寸 App 图标不变。
