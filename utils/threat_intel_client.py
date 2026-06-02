#!/usr/bin/env python3
"""
威胁情报客户端 - 支持 VirusTotal、微步在线
"""

import requests
from typing import Dict
from datetime import datetime


class ThreatIntelManager:
    def __init__(self, vt_api_key: str = None, weibu_api_key: str = None):
        self.vt_api_key = vt_api_key
        self.weibu_api_key = weibu_api_key

    def query(self, ioc_type: str, ioc_value: str) -> Dict:
        result = {"final_risk": "unknown", "sources": []}

        if self.vt_api_key and ioc_type == "domain":
            try:
                url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
                headers = {"x-apikey": self.vt_api_key}
                resp = requests.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    result["sources"].append({"source": "virustotal", "risk": "high"})
                    result["final_risk"] = "high"
            except Exception as e:
                print(f"VirusTotal error: {e}")

        return result


if __name__ == "__main__":
    print("威胁情报客户端 v2.0")
