# Wireshark MCP

Wireshark MCP 是一个基于 Model Context Protocol (MCP) 的服务器，允许 AI 助手通过 tshark 命令行工具与 Wireshark 进行交互。该工具提供了丰富的网络数据分析功能，支持实时抓包和离线分析。

## 功能特性

### 基础功能
- 实时网络抓包分析
- 分析已有的 pcap 文件
- 列出可用网络接口
- 支持 BPF 和 Display 过滤器
- JSON 格式输出便于解析

### 高级分析
- 协议分析与统计
- 错误包检测与分析
- 数据包字段提取
- 流量统计分析
- Top N 分析支持

## 系统要求

- Python 3.7+
- Wireshark/tshark
- MCP SDK

### 操作系统支持
- macOS
- Linux (Ubuntu/Debian)
- Windows (需要额外配置)

## 安装

1. 确保已安装 Wireshark 和 tshark:
```bash
# macOS
brew install wireshark

# Ubuntu/Debian
sudo apt install tshark

# 验证安装
tshark --version
```

2. 安装 Python 依赖:
```bash
pip install -r requirements.txt
```

## 使用方法

1. 启动 MCP 服务器:
```bash
python wireshark_mcp.py 
```

2. 访问状态页面查看服务状态和工具说明:
```
http://127.0.0.1:3000/status
```

3. 配置客户端 MCP 服务器:

![MCP配置示例](docs/images/mcp_config.png)

配置说明：
- 名称：wireshark
- 类型：服务器发送事件 (sse)
- URL：http://127.0.0.1:3000/sse

## 使用效果



### 4. 实时抓包
支持实时网络监控和分析：

```python
# 实时抓包示例
capture_live("en0", duration=60, filter="port 80")
```

## API 参考

### 基础功能
#### list_interfaces()
列出所有可用的网络接口。

#### capture_live(interface: str, duration: int = 10, filter: str = "", max_packets: int = 5000)
实时抓包分析。
- interface: 网络接口名称
- duration: 抓包持续时间(秒)
- filter: BPF 过滤器表达式
- max_packets: 最大数据包数量

#### analyze_pcap(file_path: str, filter: str = "", max_packets: int = 5000)
分析 pcap 文件内容。
- file_path: pcap 文件路径
- filter: 显示过滤器表达式
- max_packets: 最大数据包数量

### 高级分析功能
#### get_protocols()
获取支持的协议列表。

#### get_packet_statistics(file_path: str, filter: str = "")
获取数据包统计信息。
- file_path: pcap 文件路径
- filter: 显示过滤器表达式

#### extract_fields(file_path: str, fields: List[str], filter: str = "", max_packets: int = 5000)
提取特定字段信息并进行统计分析。
- file_path: pcap 文件路径
- fields: 要提取的字段列表
- filter: 显示过滤器表达式
- max_packets: 最大数据包数量

#### analyze_protocols(file_path: str, protocol: str, max_packets: int = 5000)
分析特定协议的数据包。
- file_path: pcap 文件路径
- protocol: 协议名称
- max_packets: 最大数据包数量

#### analyze_errors(file_path: str, error_type: str = "all", max_packets: int = 5000)
分析错误数据包。
- file_path: pcap 文件路径
- error_type: 错误类型 (all/malformed/tcp/retransmission/duplicate_ack/lost_segment)
- max_packets: 最大数据包数量

### 常用过滤器示例

#### 抓包过滤器 (BPF)
- TCP 流量: `tcp`
- 特定端口: `port 80` 或 `port 443`
- 主机过滤: `host 192.168.1.1`
- 协议过滤: `tcp or udp`
- HTTP 流量: `tcp port 80 or tcp port 443`
- DNS 查询: `udp port 53`

#### 显示过滤器
- HTTP 请求: `http.request`
- HTTPS 流量: `ssl or tls`
- DNS 查询: `dns.qry.name contains "example.com"`
- 错误包: `http.response.code >= 400`
- TCP 重传: `tcp.analysis.retransmission`
- 特定 IP: `ip.addr == 192.168.1.1`

## 性能优化

- 数据包数量限制：默认限制为 5000 个数据包
- 自动统计分析：支持 Top 10 分析
- 结果格式化：优化中文显示
- 错误处理：详细的错误信息提示

## 许可证

Apache License 2.0 

## 感谢
https://mp.weixin.qq.com/s/G_6efZFEgGTeOcRtyaNS1g?poc_token=HKpP_2ejJpvhJJ4EJ9J-8b9U5eZ3U0Jvkk_YPKoO
https://github.com/shubham-s-pandey/WiresharkMCP
