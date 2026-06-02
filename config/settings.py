"""
SmartSIRT 配置文件
支持环境变量覆盖
"""

import os
from pathlib import Path
from typing import Dict, Any

# 项目根目录
BASE_DIR = Path(__file__).parent.parent

# ============================================================
# 日志配置
# ============================================================

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = BASE_DIR / "logs" / "smartsirt.log"

# ============================================================
# 智能体配置
# ============================================================

# 分析智能体关键词
MINING_KEYWORDS = ["xmrig", "miner", "cpuminer", "minerd", "stratum", "cryptonight"]
RANSOMWARE_KEYWORDS = ["wannacry", "locky", "cerber", "crypt", "encrypt", "decrypt"]
LATERAL_MOVEMENT_KEYWORDS = ["psexec", "wmic", "schtasks", "at.exe"]

# 置信度阈值
CONFIDENCE_THRESHOLD_HIGH = 0.8
CONFIDENCE_THRESHOLD_MEDIUM = 0.5
CONFIDENCE_THRESHOLD_LOW = 0.3

# ============================================================
# 威胁情报配置
# ============================================================

# 本地情报库路径
INTEL_DB_PATH = BASE_DIR / "mock" / "threat_intel_mock.json"

# 外部情报源配置
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"

ALIYUN_OSPS_API_KEY = os.environ.get("ALIYUN_OSPS_API_KEY", "")
ALIYUN_OSPS_API_URL = "https://alisec.aliyuncs.com"

# 情报缓存配置
INTEL_CACHE_TTL = 3600  # 缓存有效期（秒）
INTEL_CACHE_SIZE = 10000  # 最大缓存条目

# ============================================================
# API 服务配置
# ============================================================

API_HOST = os.environ.get("API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("API_PORT", 8000))
API_WORKERS = int(os.environ.get("API_WORKERS", 1))
API_RELOAD = os.environ.get("API_RELOAD", "false").lower() == "true"

# CORS 配置
CORS_ALLOW_ORIGINS = os.environ.get("CORS_ALLOW_ORIGINS", "*").split(",")
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = ["*"]
CORS_ALLOW_HEADERS = ["*"]

# ============================================================
# 数据源配置
# ============================================================

# Elasticsearch 配置
ELASTICSEARCH_HOST = os.environ.get("ELASTICSEARCH_HOST", "localhost:9200")
ELASTICSEARCH_USERNAME = os.environ.get("ELASTICSEARCH_USERNAME", "")
ELASTICSEARCH_PASSWORD = os.environ.get("ELASTICSEARCH_PASSWORD", "")
ELASTICSEARCH_INDEX = os.environ.get("ELASTICSEARCH_INDEX", "alerts")
ELASTICSEARCH_USE_SSL = os.environ.get("ELASTICSEARCH_USE_SSL", "false").lower() == "true"

# Kafka 配置
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092").split(",")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "alerts")
KAFKA_GROUP_ID = os.environ.get("KAFKA_GROUP_ID", "smartsirt")

# Syslog 配置
SYSLOG_HOST = os.environ.get("SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", 514))

# ============================================================
# 告警处理配置
# ============================================================

# 批量处理大小
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", 100))

# 告警去重窗口（秒）
DEDUP_WINDOW = int(os.environ.get("DEDUP_WINDOW", 300))

# 告警保留天数
ALERT_RETENTION_DAYS = int(os.environ.get("ALERT_RETENTION_DAYS", 30))

# ============================================================
# 处置动作映射
# ============================================================

ACTION_MAP: Dict[str, str] = {
    "critical": "block_and_isolate",
    "high": "block_only",
    "medium": "manual_review",
    "low": "record_only",
    "info": "ignore",
}

# 动作描述
ACTION_DESCRIPTIONS: Dict[str, str] = {
    "block_and_isolate": "阻断网络连接并隔离主机",
    "block_only": "仅阻断网络连接",
    "isolate_only": "仅隔离主机",
    "manual_review": "转人工研判",
    "record_only": "仅记录",
    "ignore": "忽略",
}

# ============================================================
# 提示词文件路径
# ============================================================

PROMPTS_DIR = BASE_DIR / "prompts"
ANALYSIS_AGENT_PROMPT_PATH = PROMPTS_DIR / "分析智能体_prompt.txt"
INTEL_AGENT_PROMPT_PATH = PROMPTS_DIR / "情报智能体_prompt.txt"
WORKFLOW_GUIDELINE_PATH = PROMPTS_DIR / "workflow_guideline.md"

# ============================================================
# 辅助函数
# ============================================================

def get_settings() -> Dict[str, Any]:
    """获取所有配置"""
    return {
        "log_level": LOG_LEVEL,
        "api_host": API_HOST,
        "api_port": API_PORT,
        "batch_size": BATCH_SIZE,
        "dedup_window": DEDUP_WINDOW,
        "action_map": ACTION_MAP,
    }


def load_prompt(filepath: Path) -> str:
    """加载提示词文件"""
    if filepath.exists():
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    return ""


def ensure_directories():
    """确保必要的目录存在"""
    directories = [
        BASE_DIR / "logs",
        BASE_DIR / "data",
        BASE_DIR / "mock",
        PROMPTS_DIR,
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


def is_production() -> bool:
    """判断是否为生产环境"""
    return os.environ.get("ENVIRONMENT", "development").lower() == "production"


# ============================================================
# 初始化
# ============================================================

# 确保必要目录存在
ensure_directories()

# 导出配置
__all__ = [
    "BASE_DIR",
    "LOG_LEVEL",
    "LOG_FORMAT",
    "API_HOST",
    "API_PORT",
    "BATCH_SIZE",
    "ACTION_MAP",
    "ACTION_DESCRIPTIONS",
    "INTEL_DB_PATH",
    "get_settings",
    "load_prompt",
    "is_production",
]