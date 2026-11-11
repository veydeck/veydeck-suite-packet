# Changelog

## [Unreleased]

### Fixed

- 修复带尾部填充的抓包发送至数据包构造器时出现 Padding 未映射警告的问题，构造与导出保留填充字节，并避免将其计入业务负载。

### Added

- 支持从文件管理器导入抓包文件后自动选中新文件，解析完成后可直接查看数据包。

## [0.1.0-alpha.1] - 2026-10-13

### Added

- 首次发布 Veydeck 流量解析套件。
- 支持 PCAP 流式上传、协议字段与十六进制检查、流量统计和 TCP 会话追踪。
- 支持 TLS/SSL、SSH、FTP、MQTT、HTTP/2 等协议识别与关键字段解析。
- 提供可视化数据包构造、实时预览、校验、修改及 PCAP 导出能力。
- 提供基于 Veydeck UI、VDL Token 与 Suite Runtime SDK 的 React 界面和语义操作日志。
- 提供 `veydeck/packet:0.1.0-alpha.1` Docker 镜像构建与手动发布流程。
- 支持跟随 Veydeck 主控实时同步主题与液态玻璃开关。
- 流量解析与数据包构造界面支持公共 Liquid Glass 材质，数据包详情、流追踪和统计视图使用标准对话框。
