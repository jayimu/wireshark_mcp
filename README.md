# Wireshark MCP

Wireshark MCP 是一个基于 Model Context Protocol (MCP) 的服务器，允许 AI 助手通过 tshark 命令行工具与 Wireshark 进行交互。该工具提供了丰富的网络数据分析功能，支持实时抓包和离线分析。

## 功能特性

### 基础功能
- 利用 llm 分析已有的 pcap 文件   -我需要的主要功能,其他功能都是 tshark 带的
- 实时网络抓包分析
- 列出可用网络接口
- 支持 BPF 和 Display 过滤器
- JSON 格式输出便于解析

## 系统要求

- Python 3.9 +
- Wireshark/tshark
- MCP SDK

## 安装

1. 确保已安装 Wireshark 和 tshark:
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

![MCP配置示例](docs/images/286191745081560_.pic.jpg)

配置说明：
- 名称：wireshark
- 类型：服务器发送事件 (sse)
- URL：http://127.0.0.1:3000/sse

## 使用效果
![使用效果](docs/images/286201745081603_.pic.jpg)
![使用效果](docs/images/286211745081627_.pic.jpg)

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
