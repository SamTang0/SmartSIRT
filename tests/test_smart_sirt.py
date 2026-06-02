#!/usr/bin/env python3
"""
SmartSIRT 单元测试
运行: pytest tests/ -v
或: python -m unittest tests.test_smart_sirt
"""

import unittest
import sys
import os
import json
import tempfile
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from smart_sirt import (
    SmartSIRT, RiskLevel, ActionType, ThreatIntelDB,
    AnalysisAgent, IntelligenceAgent, DecisionAgent, AlertNormalizer
)


class TestRiskLevel(unittest.TestCase):
    """风险等级枚举测试"""
    
    def test_risk_values(self):
        self.assertEqual(RiskLevel.CRITICAL.value, "critical")
        self.assertEqual(RiskLevel.HIGH.value, "high")
        self.assertEqual(RiskLevel.MEDIUM.value, "medium")
        self.assertEqual(RiskLevel.LOW.value, "low")
    
    def test_risk_comparison(self):
        self.assertTrue(RiskLevel.CRITICAL > RiskLevel.HIGH)
        self.assertTrue(RiskLevel.HIGH > RiskLevel.MEDIUM)
        self.assertTrue(RiskLevel.MEDIUM > RiskLevel.LOW)
        self.assertTrue(RiskLevel.LOW > RiskLevel.INFO)


class TestActionType(unittest.TestCase):
    """处置动作枚举测试"""
    
    def test_action_values(self):
        self.assertEqual(ActionType.BLOCK_AND_ISOLATE.value, "block_and_isolate")
        self.assertEqual(ActionType.BLOCK_ONLY.value, "block_only")
        self.assertEqual(ActionType.MANUAL_REVIEW.value, "manual_review")
        self.assertEqual(ActionType.RECORD_ONLY.value, "record_only")


class TestThreatIntelDB(unittest.TestCase):
    """威胁情报数据库测试"""
    
    def setUp(self):
        self.db = ThreatIntelDB()
    
    def test_query_known_domain(self):
        result = self.db.query_domain("pool.minexmr.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["risk_level"], RiskLevel.HIGH)
        self.assertEqual(result["threat_type"], "mining")
    
    def test_query_unknown_domain(self):
        result = self.db.query_domain("safe.example.com")
        self.assertIsNone(result)
    
    def test_query_known_process(self):
        result = self.db.query_process("xmrig.exe")
        self.assertIsNotNone(result)
        self.assertEqual(result["risk_level"], RiskLevel.HIGH)
    
    def test_query_unknown_process(self):
        result = self.db.query_process("notepad.exe")
        self.assertIsNone(result)
    
    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"test.com": {"risk": "critical", "type": "c2"}}, f)
            f.close()
            
            db = ThreatIntelDB(mock_file=f.name)
            result = db.query_domain("test.com")
            self.assertIsNotNone(result)
            self.assertEqual(result["risk_level"], RiskLevel.CRITICAL)
            
            os.unlink(f.name)


class TestAlertNormalizer(unittest.TestCase):
    """告警标准化测试"""
    
    def test_normalize_with_process(self):
        alert = {"alert": "进程 xmrig.exe 启动", "hostname": "server-01"}
        result = AlertNormalizer.normalize(alert)
        self.assertEqual(result["process_name"], "xmrig.exe")
        self.assertEqual(result["hostname"], "server-01")
    
    def test_normalize_with_ip(self):
        alert = {"alert": "连接至 192.168.1.100", "host": "pc-01"}
        result = AlertNormalizer.normalize(alert)
        self.assertIn("192.168.1.100", result["network_connections"])
    
    def test_normalize_with_domain(self):
        alert = {"alert": "访问 pool.minexmr.com"}
        result = AlertNormalizer.normalize(alert)
        self.assertIn("pool.minexmr.com", result.get("domains", []))
    
    def test_normalize_without_hostname(self):
        alert = {"alert": "test"}
        result = AlertNormalizer.normalize(alert)
        self.assertEqual(result["hostname"], "unknown")


class TestAnalysisAgent(unittest.TestCase):
    """分析智能体测试"""
    
    def setUp(self):
        self.db = ThreatIntelDB()
        self.agent = AnalysisAgent(self.db)
    
    def test_analyze_mining_alert(self):
        alert = {"alert": "检测到 xmrig.exe 启动", "hostname": "server-01"}
        result = self.agent.analyze(alert)
        self.assertTrue(result["need_intel_query"])
        self.assertEqual(result["threat_type"], "mining")
    
    def test_analyze_ransomware_alert(self):
        alert = {"alert": "wannacry.exe 正在加密文件", "hostname": "client-01"}
        result = self.agent.analyze(alert)
        self.assertEqual(result["severity"], RiskLevel.CRITICAL)
        self.assertEqual(result["threat_type"], "ransomware")
    
    def test_analyze_normal_alert(self):
        alert = {"alert": "notepad.exe 正常启动", "hostname": "workstation"}
        result = self.agent.analyze(alert)
        self.assertEqual(result["severity"], RiskLevel.LOW)
        self.assertFalse(result["need_intel_query"])
    
    def test_analyze_extracts_iocs(self):
        alert = {"alert": "连接至 pool.minexmr.com 和 1.2.3.4", "hostname": "server"}
        result = self.agent.analyze(alert)
        ioc_values = [ioc["value"] for ioc in result["iocs"]]
        self.assertIn("pool.minexmr.com", ioc_values)
        self.assertIn("1.2.3.4", ioc_values)


class TestIntelligenceAgent(unittest.TestCase):
    """情报智能体测试"""
    
    def setUp(self):
        self.db = ThreatIntelDB()
        self.agent = IntelligenceAgent(self.db)
    
    def test_query_malicious_domain(self):
        iocs = [{"type": "domain", "value": "pool.minexmr.com"}]
        result = self.agent.query(iocs)
        self.assertEqual(result["malicious_count"], 1)
        self.assertEqual(result["overall_risk"], RiskLevel.HIGH)
    
    def test_query_clean_domain(self):
        iocs = [{"type": "domain", "value": "safe.com"}]
        result = self.agent.query(iocs)
        self.assertEqual(result["malicious_count"], 0)
        self.assertEqual(result["overall_risk"], RiskLevel.LOW)
    
    def test_query_multiple_iocs(self):
        iocs = [
            {"type": "domain", "value": "pool.minexmr.com"},
            {"type": "domain", "value": "c2server.com"},
            {"type": "domain", "value": "safe.com"}
        ]
        result = self.agent.query(iocs)
        self.assertEqual(result["queried_count"], 3)
        self.assertEqual(result["malicious_count"], 2)
        self.assertEqual(result["overall_risk"], RiskLevel.CRITICAL)
    
    def test_query_empty_iocs(self):
        result = self.agent.query([])
        self.assertEqual(result["queried_count"], 0)
        self.assertEqual(result["malicious_count"], 0)


class TestDecisionAgent(unittest.TestCase):
    """决策智能体测试"""
    
    def setUp(self):
        self.agent = DecisionAgent()
    
    def test_decide_critical(self):
        analysis = {
            "severity": RiskLevel.CRITICAL,
            "alert_id": "001",
            "reasoning": [],
            "threat_type": "ransomware"
        }
        intel = {"overall_risk": RiskLevel.LOW, "details": []}
        result = self.agent.decide(analysis, intel)
        self.assertEqual(result["action"], ActionType.BLOCK_AND_ISOLATE.value)
        self.assertIn("立即隔离", result["suggestions"][0])
    
    def test_decide_high(self):
        analysis = {
            "severity": RiskLevel.HIGH,
            "alert_id": "002",
            "reasoning": [],
            "threat_type": "mining"
        }
        intel = {"overall_risk": RiskLevel.LOW, "details": []}
        result = self.agent.decide(analysis, intel)
        self.assertEqual(result["action"], ActionType.BLOCK_ONLY.value)
    
    def test_decide_medium(self):
        analysis = {
            "severity": RiskLevel.MEDIUM,
            "alert_id": "003",
            "reasoning": [],
            "threat_type": None
        }
        intel = {"overall_risk": RiskLevel.MEDIUM, "details": []}
        result = self.agent.decide(analysis, intel)
        self.assertEqual(result["action"], ActionType.MANUAL_REVIEW.value)
    
    def test_decide_low(self):
        analysis = {
            "severity": RiskLevel.LOW,
            "alert_id": "004",
            "reasoning": [],
            "threat_type": None
        }
        intel = {"overall_risk": RiskLevel.LOW, "details": []}
        result = self.agent.decide(analysis, intel)
        self.assertEqual(result["action"], ActionType.RECORD_ONLY.value)
    
    def test_intel_upgrades_risk(self):
        analysis = {
            "severity": RiskLevel.MEDIUM,
            "alert_id": "005",
            "reasoning": [],
            "threat_type": None
        }
        intel = {"overall_risk": RiskLevel.CRITICAL, "details": [{"ioc_value": "bad.com", "risk": "critical"}]}
        result = self.agent.decide(analysis, intel)
        self.assertEqual(result["final_risk"], "critical")
        self.assertEqual(result["action"], ActionType.BLOCK_AND_ISOLATE.value)


class TestSmartSIRTIntegration(unittest.TestCase):
    """集成测试"""
    
    def setUp(self):
        self.sirt = SmartSIRT()
    
    def test_process_single_alert(self):
        alert = {"alert_id": "test_001", "alert": "xmrig.exe detected"}
        result = self.sirt.process_alert(alert)
        self.assertIn("final_risk", result)
        self.assertIn("action", result)
        self.assertIn("suggestions", result)
    
    def test_process_batch_alerts(self):
        alerts = [
            {"alert_id": "batch_001", "alert": "xmrig.exe"},
            {"alert_id": "batch_002", "alert": "notepad.exe"},
            {"alert_id": "batch_003", "alert": "wannacry.exe"}
        ]
        results = self.sirt.process_batch(alerts)
        self.assertEqual(len(results), 3)
    
    def test_get_stats(self):
        self.sirt.process_alert({"alert_id": "001", "alert": "xmrig.exe"})
        self.sirt.process_alert({"alert_id": "002", "alert": "notepad.exe"})
        stats = self.sirt.get_stats()
        self.assertEqual(stats["total"], 2)
        self.assertIn("by_risk", stats)
    
    def test_alert_history(self):
        self.sirt.process_alert({"alert_id": "001", "alert": "test"})
        self.assertEqual(len(self.sirt.alert_history), 1)


class TestEdgeCases(unittest.TestCase):
    """边界情况测试"""
    
    def setUp(self):
        self.sirt = SmartSIRT()
    
    def test_empty_alert(self):
        result = self.sirt.process_alert({})
        self.assertIsNotNone(result)
    
    def test_malformed_alert(self):
        result = self.sirt.process_alert({"alert": None})
        self.assertIsNotNone(result)
    
    def test_unicode_alert(self):
        result = self.sirt.process_alert({"alert": "检测到中文告警 xmrig.exe"})
        self.assertIsNotNone(result)
    
    def test_very_long_alert(self):
        long_alert = "x" * 10000
        result = self.sirt.process_alert({"alert": long_alert})
        self.assertIsNotNone(result)


def run_tests():
    """运行所有测试"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # 添加所有测试类
    suite.addTests(loader.loadTestsFromTestCase(TestRiskLevel))
    suite.addTests(loader.loadTestsFromTestCase(TestActionType))
    suite.addTests(loader.loadTestsFromTestCase(TestThreatIntelDB))
    suite.addTests(loader.loadTestsFromTestCase(TestAlertNormalizer))
    suite.addTests(loader.loadTestsFromTestCase(TestAnalysisAgent))
    suite.addTests(loader.loadTestsFromTestCase(TestIntelligenceAgent))
    suite.addTests(loader.loadTestsFromTestCase(TestDecisionAgent))
    suite.addTests(loader.loadTestsFromTestCase(TestSmartSIRTIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)