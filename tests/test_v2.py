#!/usr/bin/env python3
"""
SmartSIRT v2.0 单元测试
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smart_sirt_v2 import SmartSIRT
from analyzer.correlation_engine import AlertAggregator


class TestAggregator(unittest.TestCase):
    def test_add_alert(self):
        agg = AlertAggregator()
        agg.add({"alert": "test", "hostname": "host1"})
        self.assertEqual(len(agg.buffer), 1)


class TestSmartSIRT(unittest.TestCase):
    def test_process_alert(self):
        sirt = SmartSIRT()
        result = sirt.process_alert({"alert": "test"})
        self.assertIn("final_risk", result)


if __name__ == "__main__":
    unittest.main()
