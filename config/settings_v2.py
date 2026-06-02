"""
SmartSIRT v2.0 配置文件
"""

import os

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
API_PORT = int(os.environ.get("API_PORT", 8000))
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", 8050))
