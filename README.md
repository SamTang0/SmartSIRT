# SmartSIRT v2.0

基于多智能体的安全事件协同响应系统 - 增强版

## v2.0 新增功能

| 功能 | 说明 |
|------|------|
| **威胁情报API** | 对接 VirusTotal、微步在线 |
| **隔离智能体** | 自动执行主机/网络隔离 |
| **工单智能体** | 自动创建处置工单 |
| **告警聚合** | 时间窗口内告警聚合统计 |
| **关联分析** | 识别攻击链模式 |
| **Web仪表板** | 可视化监控面板 |
| **LLM增强** | 大语言模型辅助研判 |

## 快速开始

```bash
# 1. 克隆项目
git clone https://github.com/SamTang0/SmartSIRT-v2.0.git
cd SmartSIRT-v2.0

# 2. 安装依赖
pip install -r requirements_v2.txt

# 3. 配置 API Key（可选）
export VIRUSTOTAL_API_KEY="your_key"
export OPENAI_API_KEY="your_key"

# 4. 运行主程序
python smart_sirt_v2.py

# 5. 启动 Web 仪表板
python web/dashboard.py
```

## 项目结构

```
SmartSIRT-v2.0/
├── smart_sirt_v2.py
├── utils/
│   └── threat_intel_client.py
├── agents/
│   ├── isolation_agent.py
│   └── ticket_agent.py
├── analyzer/
│   └── correlation_engine.py
├── web/
│   └── dashboard.py
├── llm/
│   └── enhanced_analyzer.py
└── config/
    └── settings_v2.py
```

## License

MIT
