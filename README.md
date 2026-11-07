# Lightweight Custom Protocol (LCP)

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Protocol Spec](https://img.shields.io/badge/Spec-v1.2.1--FINAL-blue.svg)](docs/SPECIFICATION.md)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

**LCP (Lightweight Custom Protocol)** 是一个专为解决复杂网络与恶劣环境下“连接易断、TLS握手脆弱、证书不匹配与大文件传输中断”而设计的工业级、通用型高性能二进制控制与传输协议。

它融合了 **RFC 8200 (IPv6 报头与扩展链哲学)**、**RFC 2675 (IPv6 Jumbograms 巨型帧)** 与 **RFC 9000 (QUIC 底层传输)** 的核心优势，摆脱了传统 HTTP/TCP 的繁重负担与不可控异常。

---

## 核心特性

- **硬件/CPU 友好**：**严格 40 字节定长基础报头**，天然对齐 64 位（8 字节）CPU 内存总线，零拷贝内存直接映射；
- **IPv6 Jumbogram 长度模型**：常规控制包使用 16 位长度（零冗余）；超大分块（512KB ~ 1MB+）使用 `EXT_JUMBO` 扩展头承载 32 位长度（最大支持 4GB 单帧）；
- **链式扩展报头（Next Header Chaining）**：所有扩展报头严格遵守 8 字节整倍数对齐，支持分块控制、压缩、元数据与完整性校验；
- **双特权连续端口架构**：
  - **UDP 856（主通道）**：标准 TLS 1.3 强加密，校验公网权威 CA 证书；
  - **UDP 855（容灾通道）**：挂载专用长期证书，强制执行 **SPKI 公钥指纹固定（SPKI Pinning）**，彻底免疫证书过期与域名不匹配，同时 100% 杜绝中间人劫持；
- **两级断线恢复机制**：
  - **底层（QUIC Connection ID）**：Wi-Fi 切换 5G、宽带重新拨号时连接无缝漫游迁移，传输不停顿；
  - **上层（128 位 UUID 与累计确认）**：长时间休眠或重启后秒级断点恢复，彻底消灭 `ResponseEnded`；
- **IPv6 优先自适应路由**：保留 1000ms 优先竞争窗口，硬性网络错误（如 10051 不可达）10ms 内极速无感回退 IPv4；
- **100% 通用（Business-Agnostic）**：无任何特定业务锁死，开箱即可用于 RPC、微服务通信、海量文件分发与跨端同步。

---

## 基础报头布局（40 字节）

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Magic (8b)  | Ver(4)|Class(4)|       Flow Label (16b)        |  0x00 ~ 0x03
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Payload Length (16b)     |  Next Header  | CustomFlags(8)|  0x04 ~ 0x07
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Source Identifier (128b / 16B)               |  0x08 ~ 0x17
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|               Destination Identifier (128b / 16B)             |  0x18 ~ 0x27
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 目录结构规划

```
LightweightCustomProtocol/
├── docs/
│   └── SPECIFICATION.md        # 完整详细技术规范 (v1.2.1-FINAL)
├── pkg/
│   ├── protocol/               # 物理帧编解码、扩展链解析
│   │   ├── header.go           # 40 字节定长报头 (大端序)
│   │   ├── extensions.go       # 8 字节整倍数扩展链编解码
│   │   └── packet.go           # 统一报文封装
│   ├── transport/              # QUIC 传输层引擎
│   │   ├── client.go           # IPv6 优先探测、双端口 SPKI 客户端
│   │   ├── server.go           # UDP 856 / 855 双端口生产级侦听器
│   │   └── session.go          # 会话管理与连接迁移处理
│   └── chunking/               # 流水线与断点续传引擎
│       ├── pipeline.go         # 流水线并发推送/拉取
│       └── checkpoint.go       # 累计落盘确认游标
└── cmd/
    └── lcp-server/             # 独立运行的轻量服务器程序
        └── main.go
```

---

## 协议详细技术规范

请参阅完整的官方规范文档：**[docs/SPECIFICATION.md](docs/SPECIFICATION.md)**。

---

## License

本项目基于 [Apache License 2.0](LICENSE) 开源发布。
