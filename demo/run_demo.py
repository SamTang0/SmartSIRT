#!/usr/bin/env python3
"""
SmartSIRT 完整演示脚本
支持命令行参数：--alert "告警内容" --file 文件路径 --batch 批量演示
"""

import json
import sys
import os
import argparse
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from smart_sirt import SmartSIRT


def print_colored(text, color="green"):
    """彩色输出（仅支持终端）"""
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "reset": "\033[0m"
    }
    if sys.stdout.isatty():
        print(f"{colors.get(color, '')}{text}{colors['reset']}")
    else:
        print(text)


def demo_single_alert(sirt, alert_text=None):
    """演示单条告警处理"""
    if alert_text is None:
        alert_text = "检测到进程 xmrig.exe 启动，连接至 pool.minexmr.com:4444"
    
    alert = {
        "alert_id": "demo_001",
        "source": "EDR",
        "hostname": "server-01",
        "username": "admin",
        "alert": alert_text
    }
    
    print_colored("\n" + "=" * 70, "blue")
    print_colored("📋 单条告警演示", "green")
    print_colored("=" * 70, "blue")
    
    print(f"\n📥 输入告警:")
    print(json.dumps(alert, indent=2, ensure_ascii=False))
    
    print_colored("\n⚙️  处理中...", "yellow")
    result = sirt.process_alert(alert)
    
    print_colored("\n📊 处置结果:", "green")
    print(f"  风险等级: {result['final_risk'].upper()}")
    print(f"  处置动作: {result['action_description']}")
    print(f"\n  建议:")
    for suggestion in result['suggestions']:
        print(f"    • {suggestion}")
    
    return result


def demo_batch_alerts(sirt):
    """批量告警演示"""
    test_alerts = [
        {
            "alert_id": "batch_001",
            "source": "EDR",
            "hostname": "server-01",
            "alert": "检测到进程 xmrig.exe 启动，连接至 pool.minexmr.com:4444",
        },
        {
            "alert_id": "batch_002",
            "source": "AV",
            "hostname": "client-05",
            "alert": "发现勒索软件行为: wannacry.exe 正在加密文件",
        },
        {
            "alert_id": "batch_003",
            "source": "NIDS",
            "hostname": "server-03",
            "alert": "可疑DNS请求: c2server.com",
        },
        {
            "alert_id": "batch_004",
            "source": "EDR",
            "hostname": "workstation-12",
            "alert": "进程 notepad.exe 正常启动",
        },
        {
            "alert_id": "batch_005",
            "source": "防火墙",
            "hostname": "gateway-01",
            "alert": "检测到与恶意IP 1.2.3.4 的通信",
        }
    ]
    
    print_colored("\n" + "=" * 70, "blue")
    print_colored("📦 批量告警演示 (5条)", "green")
    print_colored("=" * 70, "blue")
    
    results = sirt.process_batch(test_alerts)
    
    print(f"\n{'序号':<6} {'告警ID':<12} {'风险等级':<10} {'处置动作':<20}")
    print("-" * 60)
    
    for i, result in enumerate(results, 1):
        risk = result.get('final_risk', 'error').upper()
        action = result.get('action_description', '失败')[:18]
        alert_id = result.get('alert_id', 'unknown')
        print(f"{i:<6} {alert_id:<12} {risk:<10} {action:<20}")
    
    stats = sirt.get_stats()
    print_colored(f"\n📈 统计: 共处理 {stats['total']} 条告警", "green")
    print(f"  风险分布: {stats.get('by_risk', {})}")
    print(f"  动作分布: {stats.get('by_action', {})}")
    
    return results


def demo_from_file(sirt, filepath):
    """从文件加载告警并处理"""
    print_colored("\n" + "=" * 70, "blue")
    print_colored(f"📁 从文件加载告警: {filepath}", "green")
    print_colored("=" * 70, "blue")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if isinstance(data, list):
            alerts = data
        else:
            alerts = [data]
        
        print(f"加载了 {len(alerts)} 条告警")
        
        for alert in alerts:
            print(f"\n处理: {alert.get('alert_id', 'unknown')}")
            result = sirt.process_alert(alert)
            print(f"  风险: {result['final_risk']} → 动作: {result['action']}")
        
        return sirt.get_stats()
        
    except Exception as e:
        print_colored(f"错误: {e}", "red")
        return None


def demo_interactive(sirt):
    """交互式演示"""
    print_colored("\n" + "=" * 70, "blue")
    print_colored("💬 交互式演示模式", "green")
    print_colored("=" * 70, "blue")
    print("输入告警内容（输入 'quit' 退出，输入 'demo' 使用示例）\n")
    
    while True:
        try:
            user_input = input("告警内容 > ").strip()
            
            if user_input.lower() == 'quit':
                print("再见！")
                break
            elif user_input.lower() == 'demo':
                user_input = "检测到进程 xmrig.exe 启动"
            elif not user_input:
                continue
            
            alert = {
                "alert_id": "interactive",
                "hostname": "unknown",
                "alert": user_input
            }
            
            result = sirt.process_alert(alert)
            print(f"\n结果: [{result['final_risk'].upper()}] {result['action_description']}")
            print(f"建议: {result['suggestions'][0] if result['suggestions'] else '无'}\n")
            
        except KeyboardInterrupt:
            print("\n再见！")
            break
        except Exception as e:
            print_colored(f"错误: {e}", "red")


def main():
    parser = argparse.ArgumentParser(description='SmartSIRT 演示脚本')
    parser.add_argument('--alert', '-a', type=str, help='单条告警内容')
    parser.add_argument('--file', '-f', type=str, help='JSON文件路径')
    parser.add_argument('--batch', '-b', action='store_true', help='运行批量演示')
    parser.add_argument('--interactive', '-i', action='store_true', help='交互式模式')
    
    args = parser.parse_args()
    
    print_colored("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    SmartSIRT 演示系统                        ║
    ║           基于多智能体的安全事件协同响应系统                   ║
    ╚══════════════════════════════════════════════════════════════╝
    """, "blue")
    
    sirt = SmartSIRT()
    
    if args.interactive:
        demo_interactive(sirt)
    elif args.batch:
        demo_batch_alerts(sirt)
    elif args.file:
        demo_from_file(sirt, args.file)
    elif args.alert:
        demo_single_alert(sirt, args.alert)
    else:
        # 默认运行单条演示
        demo_single_alert(sirt)
        print_colored("\n💡 提示: 使用 -h 查看更多选项", "yellow")
        print("  python demo/run_demo.py --batch    # 批量演示")
        print("  python demo/run_demo.py --interactive  # 交互模式")
        print("  python demo/run_demo.py --file mock/demo_input.json")


if __name__ == "__main__":
    main()