# Veydeck 流量解析

Veydeck 流量解析套件镜像，用于 PCAP 流量解析、协议字段检查、流量统计和可视化数据包构造。

Veydeck 是一个可扩展的分布式 Linux 主机运维平台，用于统一管理一台或多台 Linux 主机，并支持通过套件按需扩展平台能力。

## 镜像

```text
veydeck/packet:0.1.0-alpha.1
```

## 运行示例

```bash
docker network create veydeck-suite-network
docker run --rm \
  --name veydeck-packet \
  --network veydeck-suite-network \
  -v veydeck-packet-data:/data \
  veydeck/packet:0.1.0-alpha.1
```

## 本地构建

```bash
./build-image.sh 0.1.0-alpha.1
```

本仓库只维护套件源码和 Docker 镜像。`.vsp` 套件交付包由 `veydeck-suites` 仓库统一维护和发布。

在 Veydeck 内运行时，后端通过 Suite Runtime SDK 使用 `operation-logs.write` 能力记录 PCAP 上传、解析终态、删除和构建操作。Agent 实例令牌不会暴露给前端。
