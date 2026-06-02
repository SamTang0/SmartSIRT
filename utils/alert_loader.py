#!/usr/bin/env python3
"""
告警加载工具
支持从多种数据源加载告警: JSON, CSV, 文本文件, Elasticsearch, Kafka
"""

import json
import csv
import os
from typing import List, Dict, Optional, Iterator
from pathlib import Path
from datetime import datetime
import re


class AlertLoader:
    """告警加载器基类"""
    
    @staticmethod
    def from_json(filepath: str, encoding: str = 'utf-8') -> List[Dict]:
        """
        从 JSON 文件加载告警
        
        支持格式:
            1. 单个告警对象: {"alert": "...", "hostname": "..."}
            2. 告警数组: [{"alert": "..."}, ...]
        
        Args:
            filepath: JSON 文件路径
            encoding: 文件编码
            
        Returns:
            告警列表
        """
        with open(filepath, 'r', encoding=encoding) as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return [data]
    
    @staticmethod
    def from_csv(filepath: str, encoding: str = 'utf-8') -> List[Dict]:
        """
        从 CSV 文件加载告警
        
        CSV 列名建议: alert_id, source, hostname, username, alert, message
        
        Args:
            filepath: CSV 文件路径
            encoding: 文件编码
            
        Returns:
            告警列表
        """
        alerts = []
        with open(filepath, 'r', encoding=encoding) as f:
            reader = csv.DictReader(f)
            for row in reader:
                alerts.append(row)
        return alerts
    
    @staticmethod
    def from_text(filepath: str, encoding: str = 'utf-8') -> List[Dict]:
        """
        从纯文本文件加载告警
        每行一条告警内容
        
        Args:
            filepath: 文本文件路径
            encoding: 文件编码
            
        Returns:
            告警列表
        """
        alerts = []
        with open(filepath, 'r', encoding=encoding) as f:
            for i, line in enumerate(f):
                line = line.strip()
                if line:
                    alerts.append({
                        "alert_id": f"alert_{i+1}",
                        "alert": line,
                        "source": "text_import"
                    })
        return alerts
    
    @staticmethod
    def from_directory(directory: str, extensions: List[str] = None) -> List[Dict]:
        """
        从目录递归加载所有告警文件
        
        Args:
            directory: 目录路径
            extensions: 文件扩展名列表，默认 ['.json', '.csv', '.txt']
            
        Returns:
            所有告警的合并列表
        """
        if extensions is None:
            extensions = ['.json', '.csv', '.txt']
        
        all_alerts = []
        directory = Path(directory)
        
        for ext in extensions:
            for filepath in directory.rglob(f"*{ext}"):
                try:
                    if ext == '.json':
                        alerts = AlertLoader.from_json(str(filepath))
                    elif ext == '.csv':
                        alerts = AlertLoader.from_csv(str(filepath))
                    else:
                        alerts = AlertLoader.from_text(str(filepath))
                    
                    for alert in alerts:
                        if 'source_file' not in alert:
                            alert['source_file'] = str(filepath)
                    
                    all_alerts.extend(alerts)
                except Exception as e:
                    print(f"加载失败 {filepath}: {e}")
        
        return all_alerts


class ElasticsearchLoader:
    """
    Elasticsearch 告警加载器
    
    需要安装: pip install elasticsearch
    """
    
    def __init__(self, host: str = "localhost:9200", index: str = "alerts", 
                 username: str = None, password: str = None, 
                 use_ssl: bool = False):
        """
        初始化 Elasticsearch 连接
        
        Args:
            host: ES 主机地址
            index: 索引名称
            username: 用户名（可选）
            password: 密码（可选）
            use_ssl: 是否使用 SSL
        """
        self.host = host
        self.index = index
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self._client = None
    
    def _get_client(self):
        """延迟初始化 ES 客户端"""
        if self._client is None:
            try:
                from elasticsearch import Elasticsearch
                
                scheme = "https" if self.use_ssl else "http"
                url = f"{scheme}://{self.host}"
                
                if self.username and self.password:
                    self._client = Elasticsearch(
                        [url],
                        basic_auth=(self.username, self.password)
                    )
                else:
                    self._client = Elasticsearch([url])
                
                # 测试连接
                if not self._client.ping():
                    raise ConnectionError("无法连接到 Elasticsearch")
                    
            except ImportError:
                raise ImportError("请安装 elasticsearch: pip install elasticsearch")
        
        return self._client
    
    def query(self, 
              size: int = 100, 
              query_body: Dict = None,
              time_field: str = "@timestamp",
              time_range: Dict = None) -> List[Dict]:
        """
        查询告警
        
        Args:
            size: 返回数量
            query_body: 自定义查询体
            time_field: 时间字段名
            time_range: 时间范围 {"gte": "now-1h", "lte": "now"}
            
        Returns:
            告警列表
        """
        client = self._get_client()
        
        if query_body is None:
            query_body = {"match_all": {}}
        
        body = {
            "query": query_body,
            "size": size,
            "sort": [{time_field: {"order": "desc"}}]
        }
        
        # 添加时间范围过滤
        if time_range:
            body["query"] = {
                "bool": {
                    "must": [query_body],
                    "filter": [{"range": {time_field: time_range}}]
                }
            }
        
        response = client.search(index=self.index, body=body)
        
        alerts = []
        for hit in response["hits"]["hits"]:
            alert = hit["_source"]
            alert["_id"] = hit["_id"]
            alert["_index"] = hit["_index"]
            alerts.append(alert)
        
        return alerts
    
    def scroll_query(self, query_body: Dict = None, scroll_time: str = "2m") -> Iterator[Dict]:
        """
        使用 scroll API 遍历大量数据
        
        Args:
            query_body: 查询体
            scroll_time: scroll 保持时间
            
        Yields:
            逐条告警
        """
        client = self._get_client()
        
        if query_body is None:
            query_body = {"match_all": {}}
        
        response = client.search(
            index=self.index,
            body={"query": query_body},
            scroll=scroll_time,
            size=100
        )
        
        scroll_id = response["_scroll_id"]
        
        try:
            for hit in response["hits"]["hits"]:
                alert = hit["_source"]
                alert["_id"] = hit["_id"]
                yield alert
            
            while len(response["hits"]["hits"]):
                response = client.scroll(scroll_id=scroll_id, scroll=scroll_time)
                scroll_id = response["_scroll_id"]
                for hit in response["hits"]["hits"]:
                    alert = hit["_source"]
                    alert["_id"] = hit["_id"]
                    yield alert
        finally:
            client.clear_scroll(scroll_id=scroll_id)


class KafkaLoader:
    """
    Kafka 告警加载器（消费者）
    
    需要安装: pip install kafka-python
    """
    
    def __init__(self, 
                 bootstrap_servers: List[str],
                 topic: str,
                 group_id: str = "smartsirt",
                 auto_offset_reset: str = "latest"):
        """
        初始化 Kafka 消费者
        
        Args:
            bootstrap_servers: Kafka 服务器列表
            topic: 主题名称
            group_id: 消费组 ID
            auto_offset_reset: 偏移重置策略
        """
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.auto_offset_reset = auto_offset_reset
        self._consumer = None
    
    def _get_consumer(self):
        """延迟初始化 Kafka 消费者"""
        if self._consumer is None:
            try:
                from kafka import KafkaConsumer
                import json
                
                self._consumer = KafkaConsumer(
                    self.topic,
                    bootstrap_servers=self.bootstrap_servers,
                    group_id=self.group_id,
                    auto_offset_reset=self.auto_offset_reset,
                    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
                )
            except ImportError:
                raise ImportError("请安装 kafka-python: pip install kafka-python")
        
        return self._consumer
    
    def consume(self, max_messages: int = None, timeout_ms: int = 1000) -> List[Dict]:
        """
        消费消息
        
        Args:
            max_messages: 最大消息数
            timeout_ms: 超时时间
            
        Returns:
            消息列表
        """
        consumer = self._get_consumer()
        messages = []
        
        for msg in consumer:
            messages.append(msg.value)
            if max_messages and len(messages) >= max_messages:
                break
        
        return messages
    
    def consume_stream(self) -> Iterator[Dict]:
        """流式消费消息"""
        consumer = self._get_consumer()
        for msg in consumer:
            yield msg.value
    
    def close(self):
        """关闭消费者"""
        if self._consumer:
            self._consumer.close()
            self._consumer = None


class SyslogLoader:
    """
    Syslog 告警加载器
    
    需要安装: pip install syslog-udp-handler
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 514, facility: int = 1):
        """
        初始化 Syslog 接收器
        
        Args:
            host: 监听地址
            port: 监听端口
            facility: syslog facility
        """
        self.host = host
        self.port = port
        self.facility = facility
        self._server = None
    
    def start_server(self, callback):
        """
        启动 Syslog 服务器
        
        Args:
            callback: 接收告警的回调函数
        """
        import socketserver
        from socketserver import DatagramRequestHandler
        
        class SyslogHandler(DatagramRequestHandler):
            def handle(self):
                data = self.request[0].strip().decode('utf-8')
                alert = {
                    "source": "syslog",
                    "alert": data,
                    "timestamp": datetime.now().isoformat(),
                    "remote_addr": self.client_address[0]
                }
                callback(alert)
        
        self._server = socketserver.UDPServer((self.host, self.port), SyslogHandler)
        print(f"Syslog 监听已启动: {self.host}:{self.port}")
        self._server.serve_forever()
    
    def stop_server(self):
        """停止服务器"""
        if self._server:
            self._server.shutdown()
            self._server = None


def merge_alerts(alerts_list: List[List[Dict]]) -> List[Dict]:
    """
    合并多个告警源的数据
    
    Args:
        alerts_list: 多个告警列表
        
    Returns:
        合并后的告警列表
    """
    merged = []
    for alerts in alerts_list:
        merged.extend(alerts)
    return merged


def deduplicate_alerts(alerts: List[Dict], key_fields: List[str] = None) -> List[Dict]:
    """
    去重告警
    
    Args:
        alerts: 告警列表
        key_fields: 用于去重的字段，默认 ['alert', 'hostname']
        
    Returns:
        去重后的告警列表
    """
    if key_fields is None:
        key_fields = ['alert', 'hostname']
    
    seen = set()
    unique = []
    
    for alert in alerts:
        key = tuple(alert.get(field, '') for field in key_fields)
        if key not in seen:
            seen.add(key)
            unique.append(alert)
    
    return unique


def enrich_alerts(alerts: List[Dict]) -> List[Dict]:
    """
    丰富告警信息（添加默认字段）
    
    Args:
        alerts: 告警列表
        
    Returns:
        丰富后的告警列表
    """
    for alert in alerts:
        if 'alert_id' not in alert:
            alert['alert_id'] = f"alert_{int(datetime.now().timestamp())}_{hash(str(alert)) % 10000}"
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().isoformat()
        if 'source' not in alert:
            alert['source'] = 'unknown'
    return alerts


def main():
    """命令行入口示例"""
    import argparse
    
    parser = argparse.ArgumentParser(description='告警加载工具')
    parser.add_argument('--file', '-f', type=str, help='文件路径')
    parser.add_argument('--type', '-t', choices=['json', 'csv', 'txt'], default='json', help='文件类型')
    parser.add_argument('--directory', '-d', type=str, help='目录路径')
    parser.add_argument('--limit', '-l', type=int, default=10, help='显示数量限制')
    
    args = parser.parse_args()
    
    if args.file:
        if args.type == 'json':
            alerts = AlertLoader.from_json(args.file)
        elif args.type == 'csv':
            alerts = AlertLoader.from_csv(args.file)
        else:
            alerts = AlertLoader.from_text(args.file)
        
        print(f"加载了 {len(alerts)} 条告警")
        for alert in alerts[:args.limit]:
            print(f"  - {alert.get('alert', alert.get('message', 'N/A'))[:50]}...")
    
    elif args.directory:
        alerts = AlertLoader.from_directory(args.directory)
        print(f"从目录加载了 {len(alerts)} 条告警")
    
    else:
        print("请指定 --file 或 --directory")
        print("\n示例:")
        print("  python utils/alert_loader.py --file mock/demo_input.json")
        print("  python utils/alert_loader.py --directory mock/")
        print("  python utils/alert_loader.py --file alerts.csv --type csv")


if __name__ == "__main__":
    main()