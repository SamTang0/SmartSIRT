#!/usr/bin/env python3
"""
SmartSIRT - 基于多智能体的安全事件协同响应系统
"""

import json
import re
import logging
from datetime import datetime
from typing import Dict, Optional, List
from enum import Enum
from dataclasses import dataclass
from pathlib import Path

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """风险等级枚举"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    def __lt__(self, other):
        order = ["info", "low", "medium", "high", "critical"]
        return order.index(self.value) < order.index(other.value)


class ActionType(Enum):
    """处置动作枚举"""
    BLOCK_AND_ISOLATE = "block_and_isolate"
    BLOCK_ONLY = "block_only"
    ISOLATE_ONLY = "isolate_only"
    MANUAL_REVIEW = "manual_review"
    RECORD_ONLY = "record_only"
    IGNORE = "ignore"


@dataclass
class ThreatIntelEntry:
    """威胁情报条目"""
    risk_level: RiskLevel
    threat_type: str
    confidence: float
    source: str = "local_db"


class ThreatIntelDB:
    """威胁情报数据库"""
    
    def __init__(self, mock_file: str = None):
        self.blacklist: Dict[str, ThreatIntelEntry] = {}
        self.process_db: Dict[str, ThreatIntelEntry] = {}
        self._init_default_data()
        
        if mock_file and Path(mock_file).exists():
            self._load_from_file(mock_file)
    
    def _init_default_data(self):
        """初始化默认数据"""
        # 恶意域名/IP库
        domains = {
            "pool.minexmr.com": ("high", "mining"),
            "xmr.pool.com": ("high", "mining"),
            "mining.pool.org": ("medium", "mining"),
            "c2server.com": ("critical", "c2"),
            "malicious.xyz": ("critical", "c2"),
            "phishing-site.com": ("high", "phishing"),
        }
        
        for domain, (risk, typ) in domains.items():
            self.blacklist[domain] = ThreatIntelEntry(
                risk_level=RiskLevel(risk),
                threat_type=typ,
                confidence=0.95,
                source="local_blacklist"
            )
        
        # 恶意进程特征
        processes = {
            "xmrig": ("high", "miner"),
            "miner": ("high", "miner"),
            "cpuminer": ("high", "miner"),
            "wannacry": ("critical", "ransomware"),
            "locky": ("critical", "ransomware"),
            "mimikatz": ("high", "credential_theft"),
        }
        
        for proc, (risk, typ) in processes.items():
            self.process_db[proc] = ThreatIntelEntry(
                risk_level=RiskLevel(risk),
                threat_type=typ,
                confidence=0.9,
                source="local_process_db"
            )
    
    def _load_from_file(self, filepath: str):
        """从文件加载情报数据"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for domain, info in data.items():
                    self.blacklist[domain] = ThreatIntelEntry(
                        risk_level=RiskLevel(info.get("risk", "low")),
                        threat_type=info.get("type", "unknown"),
                        confidence=info.get("confidence", 0.8),
                        source="external"
                    )
        except Exception as e:
            logger.warning(f"加载情报文件失败: {e}")
    
    def query_domain(self, domain: str) -> Optional[Dict]:
        """查询域名情报"""
        domain_lower = domain.lower()
        if domain_lower in self.blacklist:
            info = self.blacklist[domain_lower]
            return {
                "risk_level": info.risk_level,
                "threat_type": info.threat_type,
                "confidence": info.confidence,
                "source": info.source
            }
        return None
    
    def query_ip(self, ip: str) -> Optional[Dict]:
        """查询IP情报"""
        return self.query_domain(ip)
    
    def query_process(self, process_name: str) -> Optional[Dict]:
        """查询进程情报"""
        process_lower = process_name.lower()
        for key, info in self.process_db.items():
            if key in process_lower:
                return {
                    "risk_level": info.risk_level,
                    "threat_type": info.threat_type,
                    "confidence": info.confidence,
                    "source": info.source
                }
        return None


class AlertNormalizer:
    """告警标准化模块"""
    
    @staticmethod
    def normalize(alert: Dict) -> Dict:
        """将不同格式的告警统一为标准格式"""
        standard = {
            "timestamp": datetime.now().isoformat(),
            "alert_id": alert.get("alert_id", f"alert_{int(datetime.now().timestamp())}"),
            "source": alert.get("source", "unknown"),
            "hostname": alert.get("hostname", alert.get("host", "unknown")),
            "username": alert.get("username", alert.get("user", "unknown")),
            "process_name": "",
            "command_line": "",
            "file_path": "",
            "network_connections": [],
            "raw_message": alert.get("alert", alert.get("message", ""))
        }
        
        raw = standard["raw_message"].lower()
        
        # 提取进程名
        process_patterns = [
            r'进程\s+(\S+)',
            r'process\s+(\S+)',
            r'(\S+\.exe)',
            r'(\S+\.dll)'
        ]
        for pattern in process_patterns:
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                standard["process_name"] = match.group(1)
                break
        
        # 提取IP地址
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        standard["network_connections"] = re.findall(ip_pattern, raw)
        
        # 提取域名
        domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9\-]{1,62}\.[a-zA-Z]{2,}\b'
        standard["domains"] = re.findall(domain_pattern, raw)
        
        return standard


class AnalysisAgent:
    """分析智能体：负责告警研判和特征提取"""
    
    def __init__(self, threat_intel: ThreatIntelDB):
        self.threat_intel = threat_intel
        self.mining_keywords = ["xmrig", "miner", "cpuminer", "minerd", "stratum"]
        self.ransomware_keywords = ["wannacry", "locky", "cerber", "encrypt"]
    
    def analyze(self, alert: Dict) -> Dict:
        """分析告警，返回分析结果"""
        normalized = AlertNormalizer.normalize(alert)
        
        result = {
            "alert_id": normalized["alert_id"],
            "timestamp": normalized["timestamp"],
            "severity": RiskLevel.INFO,
            "threat_type": None,
            "confidence": 0.0,
            "iocs": [],
            "need_intel_query": False,
            "reasoning": []
        }
        
        # 1. 检查进程情报
        if normalized["process_name"]:
            proc_info = self.threat_intel.query_process(normalized["process_name"])
            if proc_info:
                result["severity"] = proc_info["risk_level"]
                result["threat_type"] = proc_info["threat_type"]
                result["confidence"] = proc_info["confidence"]
                result["reasoning"].append(f"进程特征匹配: {normalized['process_name']}")
                result["need_intel_query"] = True
        
        # 2. 检查挖矿特征
        raw_lower = normalized["raw_message"].lower()
        for keyword in self.mining_keywords:
            if keyword in raw_lower:
                if result["severity"].value < RiskLevel.MEDIUM.value:
                    result["severity"] = RiskLevel.MEDIUM
                result["threat_type"] = "mining"
                result["reasoning"].append(f"关键词匹配: {keyword}")
                result["need_intel_query"] = True
                break
        
        # 3. 检查勒索软件特征
        for keyword in self.ransomware_keywords:
            if keyword in raw_lower:
                result["severity"] = RiskLevel.CRITICAL
                result["threat_type"] = "ransomware"
                result["reasoning"].append(f"勒索软件特征: {keyword}")
                result["need_intel_query"] = True
                break
        
        # 4. 提取IoC
        if normalized.get("network_connections"):
            for ip in normalized["network_connections"]:
                result["iocs"].append({"type": "ip", "value": ip})
        
        if normalized.get("domains"):
            for domain in normalized["domains"]:
                result["iocs"].append({"type": "domain", "value": domain})
        
        # 5. 如果没有明确威胁，标记为低风险
        if result["severity"] == RiskLevel.INFO:
            result["severity"] = RiskLevel.LOW
            result["reasoning"].append("未发现明确威胁特征")
        
        return result


class IntelligenceAgent:
    """情报智能体：负责威胁情报查询和风险定级"""
    
    def __init__(self, threat_intel: ThreatIntelDB):
        self.threat_intel = threat_intel
    
    def query(self, iocs: List[Dict]) -> Dict:
        """查询IoC情报"""
        results = {
            "queried_count": 0,
            "malicious_count": 0,
            "details": [],
            "overall_risk": RiskLevel.LOW
        }
        
        for ioc in iocs:
            ioc_type = ioc.get("type")
            ioc_value = ioc.get("value")
            
            if not ioc_type or not ioc_value:
                continue
            
            results["queried_count"] += 1
            
            if ioc_type == "domain":
                info = self.threat_intel.query_domain(ioc_value)
            elif ioc_type == "ip":
                info = self.threat_intel.query_ip(ioc_value)
            else:
                info = None
            
            if info:
                results["malicious_count"] += 1
                results["details"].append({
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                    "risk": info["risk_level"].value,
                    "threat_type": info["threat_type"],
                    "confidence": info["confidence"]
                })
                
                # 更新整体风险等级
                if info["risk_level"] == RiskLevel.CRITICAL:
                    results["overall_risk"] = RiskLevel.CRITICAL
                elif info["risk_level"] == RiskLevel.HIGH and results["overall_risk"] != RiskLevel.CRITICAL:
                    results["overall_risk"] = RiskLevel.HIGH
                elif info["risk_level"] == RiskLevel.MEDIUM and results["overall_risk"] not in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                    results["overall_risk"] = RiskLevel.MEDIUM
        
        return results


class DecisionAgent:
    """决策智能体：综合研判结果，生成处置建议"""
    
    def __init__(self):
        self.action_mapping = {
            RiskLevel.CRITICAL: ActionType.BLOCK_AND_ISOLATE,
            RiskLevel.HIGH: ActionType.BLOCK_ONLY,
            RiskLevel.MEDIUM: ActionType.MANUAL_REVIEW,
            RiskLevel.LOW: ActionType.RECORD_ONLY,
            RiskLevel.INFO: ActionType.IGNORE,
        }
    
    def decide(self, analysis_result: Dict, intel_result: Dict) -> Dict:
        """综合决策，生成最终处置建议"""
        # 确定最终风险等级
        final_risk = analysis_result["severity"]
        
        if intel_result["overall_risk"].value > final_risk.value:
            final_risk = intel_result["overall_risk"]
        
        # 确定处置动作
        action = self.action_mapping.get(final_risk, ActionType.MANUAL_REVIEW)
        
        # 生成详细建议
        suggestions = self._generate_suggestions(final_risk, analysis_result, intel_result)
        
        return {
            "alert_id": analysis_result["alert_id"],
            "timestamp": datetime.now().isoformat(),
            "final_risk": final_risk.value,
            "action": action.value,
            "action_description": self._get_action_description(action),
            "suggestions": suggestions,
            "reasoning": {
                "analysis_reasoning": analysis_result["reasoning"],
                "intel_findings": intel_result["details"]
            }
        }
    
    def _generate_suggestions(self, risk: RiskLevel, analysis: Dict, intel: Dict) -> List[str]:
        """生成具体建议列表"""
        suggestions = []
        
        if risk == RiskLevel.CRITICAL:
            suggestions.append("立即隔离受影响主机，阻断所有网络连接")
            suggestions.append("通知安全团队立即介入处置")
            suggestions.append("收集进程内存和网络连接信息用于取证")
        
        elif risk == RiskLevel.HIGH:
            suggestions.append("阻断恶意网络连接")
            suggestions.append("结束恶意进程")
            if analysis["threat_type"] == "mining":
                suggestions.append("检查主机CPU使用率，排查其他挖矿痕迹")
        
        elif risk == RiskLevel.MEDIUM:
            suggestions.append("添加到待观察列表，持续监控30分钟")
            suggestions.append("如确认威胁，手动升级处置")
        
        elif risk == RiskLevel.LOW:
            suggestions.append("仅记录日志，不进行自动处置")
        
        # 添加情报匹配信息
        for detail in intel.get("details", [])[:2]:
            suggestions.append(f"情报匹配: {detail['ioc_value']} 已被标记为 {detail['risk']}")
        
        return suggestions
    
    def _get_action_description(self, action: ActionType) -> str:
        """获取动作描述"""
        descriptions = {
            ActionType.BLOCK_AND_ISOLATE: "阻断网络连接并隔离主机",
            ActionType.BLOCK_ONLY: "仅阻断网络连接",
            ActionType.ISOLATE_ONLY: "仅隔离主机",
            ActionType.MANUAL_REVIEW: "转人工研判",
            ActionType.RECORD_ONLY: "仅记录",
            ActionType.IGNORE: "忽略"
        }
        return descriptions.get(action, "未知动作")


class SmartSIRT:
    """SmartSIRT 主控制器"""
    
    def __init__(self):
        self.threat_intel = ThreatIntelDB()
        self.analysis_agent = AnalysisAgent(self.threat_intel)
        self.intel_agent = IntelligenceAgent(self.threat_intel)
        self.decision_agent = DecisionAgent()
        self.alert_history = []
    
    def process_alert(self, alert: Dict) -> Dict:
        """处理单条告警的主流程"""
        logger.info(f"开始处理告警: {alert.get('alert_id', alert.get('alert', 'unknown'))[:50]}")
        
        # Step 1: 分析智能体
        analysis_result = self.analysis_agent.analyze(alert)
        logger.info(f"分析完成 - 风险: {analysis_result['severity'].value}, IOCs: {len(analysis_result['iocs'])}")
        
        # Step 2: 情报智能体
        intel_result = {"queried_count": 0, "malicious_count": 0, "details": [], "overall_risk": RiskLevel.LOW}
        if analysis_result["need_intel_query"] and analysis_result["iocs"]:
            intel_result = self.intel_agent.query(analysis_result["iocs"])
            logger.info(f"情报查询完成 - 恶意IoC: {intel_result['malicious_count']}/{intel_result['queried_count']}")
        
        # Step 3: 决策智能体
        final_result = self.decision_agent.decide(analysis_result, intel_result)
        
        self.alert_history.append(final_result)
        logger.info(f"处置决策 - 动作: {final_result['action']}")
        
        return final_result
    
    def process_batch(self, alerts: List[Dict]) -> List[Dict]:
        """批量处理告警"""
        results = []
        for alert in alerts:
            try:
                result = self.process_alert(alert)
                results.append(result)
            except Exception as e:
                logger.error(f"处理告警失败: {e}")
                results.append({"error": str(e), "alert": alert})
        return results
    
    def get_stats(self) -> Dict:
        """获取处理统计信息"""
        if not self.alert_history:
            return {"total": 0}
        
        risk_counts = {}
        action_counts = {}
        
        for result in self.alert_history:
            risk = result.get("final_risk", "unknown")
            action = result.get("action", "unknown")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            action_counts[action] = action_counts.get(action, 0) + 1
        
        return {
            "total": len(self.alert_history),
            "by_risk": risk_counts,
            "by_action": action_counts
        }


def main():
    """演示主函数"""
    print("=" * 60)
    print("SmartSIRT - 多智能体安全事件响应系统")
    print("=" * 60)
    
    sirt = SmartSIRT()
    
    # 测试告警
    test_alerts = [
        {
            "alert_id": "alert_001",
            "source": "EDR",
            "hostname": "server-01",
            "alert": "检测到进程 xmrig.exe 启动，连接至 pool.minexmr.com:4444",
        },
        {
            "alert_id": "alert_002",
            "source": "AV",
            "hostname": "client-05",
            "alert": "发现勒索软件行为: wannacry.exe 正在加密文件",
        },
        {
            "alert_id": "alert_003",
            "source": "NIDS",
            "hostname": "server-03",
            "alert": "可疑DNS请求: c2server.com",
        },
        {
            "alert_id": "alert_004",
            "source": "EDR",
            "hostname": "workstation-12",
            "alert": "进程 notepad.exe 正常启动",
        }
    ]
    
    for alert in test_alerts:
        print("\n" + "-" * 60)
        print(f"处理告警: {alert['alert_id']}")
        print(f"内容: {alert['alert'][:60]}...")
        
        result = sirt.process_alert(alert)
        
        print(f"\n风险等级: {result['final_risk'].upper()}")
        print(f"处置动作: {result['action_description']}")
        print("建议:")
        for suggestion in result['suggestions'][:2]:
            print(f"  - {suggestion}")
    
    print("\n" + "=" * 60)
    print("处理统计:", sirt.get_stats())


if __name__ == "__main__":
    main()