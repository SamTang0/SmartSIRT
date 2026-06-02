#!/usr/bin/env python3
"""
告警聚合与关联分析引擎
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple


class AlertAggregator:
    def __init__(self, time_window_seconds: int = 300):
        self.time_window = time_window_seconds
        self.buffer = []

    def add(self, alert: Dict):
        self.buffer.append(alert)
        self._clean()

    def _clean(self):
        now = datetime.now()
        self.buffer = [a for a in self.buffer if self._get_time(a) > now - timedelta(seconds=self.time_window)]

    def _get_time(self, alert: Dict) -> datetime:
        try:
            return datetime.fromisoformat(alert.get("timestamp", "2000-01-01T00:00:00"))
        except:
            return datetime.now()

    def aggregate_by_host(self) -> Dict[str, int]:
        result = defaultdict(int)
        for alert in self.buffer:
            host = alert.get("hostname", "unknown")
            result[host] += 1
        return dict(result)

    def get_stats(self) -> Dict:
        return {"total": len(self.buffer), "by_host": self.aggregate_by_host()}


class CorrelationEngine:
    def __init__(self):
        self.rules = [
            {"name": "挖矿感染链", "sequence": ["扫描", "挖矿程序"], "severity": "high"},
        ]

    def correlate(self, alerts: List[Dict]) -> List[Dict]:
        return []


if __name__ == "__main__":
    agg = AlertAggregator()
    agg.add({"alert": "test", "hostname": "server-01"})
    print(f"统计: {agg.get_stats()}")
