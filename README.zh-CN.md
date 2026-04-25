# Airgap

> 使用 Rust 和 iced 构建的 NEAR 隔离环境交易签名套件。

[English](./README.md)

Airgap 是一个面向 NEAR 区块链的双设备签名系统。  
它将**在线构造交易（online）**与**离线签名（offline）**分离，通过文件进行显式、可控的数据传递。

**私钥永远不会进入联网环境。**

---

## 架构

Airgap 由两个彼此独立、运行在不同设备上的应用组成：

- **airgap-online（热端设备）**  
  运行在联网设备上。  
  负责获取链上数据（nonce、最新 block hash）、构造未签名交易，以及将已签名交易广播到网络。

- **airgap-offline（冷端设备）**  
  运行在隔离的、物理断网的设备上。  
  负责解析输入交易、以可读方式展示关键信息供用户确认，并使用永不离开本机的私钥完成签名。

两个设备之间通过结构化文件传递数据：

- Online → Offline：未签名交易请求文件
- Offline → Online：已签名交易响应文件

离线设备永不联网，也不会接收任何可执行输入，只接收用于校验和签名的结构化交易数据。

---

## 流程

```text
airgap-online:
获取链状态 → 构造未签名交易 → 导出请求文件

airgap-offline:
导入请求文件 → 校验 → 签名 → 导出响应文件

airgap-online:
导入响应文件 → 广播交易
```

---

## 项目结构

```text
airgap/
├── airgap-core      # 共享逻辑（交易 / 编解码 / 解析）
├── airgap-online    # 热端设备（构造器 + 广播器）
├── airgap-offline   # 冷端设备（签名器）
└── Cargo.toml
```

---

## 模块说明

### `airgap-core`

- 交易模型（NEAR）
- 编码 / 解码（borsh / base64）
- 文件载荷结构定义
- 人类可读的交易解析

---

### `airgap-online`

- RPC 交互
- 获取 nonce 与 block hash
- 构造交易
- 导出请求文件
- 导入响应文件
- 广播已签名交易

---

### `airgap-offline`

- 导入请求文件
- 交易检查与确认（关键安全步骤）
- 签名（ed25519）
- 导出响应文件

---

## 安全模型

通过设备隔离实现密钥隔离。

### 可降低的风险

- 私钥泄露
- 在线设备上的恶意软件
- 剪贴板注入
- 离线设备接收可执行输入

### 前提条件

- 用户需要在离线设备上完成交易确认
- 需要使用新鲜的 block hash（签名窗口较短）

---

## 运行

```bash
cargo run -p airgap-online
cargo run -p airgap-offline
```

本地应用数据保存在 `~/.airgap/` 下：

```text
~/.airgap/airgap-online/db
~/.airgap/airgap-offline/db
~/.airgap/airgap-online/out
~/.airgap/airgap-offline/out
```

---

## 总结

```text
airgap-online 负责构造交易
airgap-offline 负责签名
通过文件传递未签名请求和已签名响应
```
