#!/usr/bin/env python3
"""
工单智能体
"""

from typing import Dict, List
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class TicketPriority(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Ticket:
    ticket_id: str
    title: str
    priority: TicketPriority
    status: str
    created_at: str


class TicketAgent:
    def __init__(self):
        self.tickets = {}
        self._counter = 0

    def _gen_id(self) -> str:
        self._counter += 1
        return f"SIRT-{datetime.now().strftime("%Y%m%d")}-{self._counter:04d}"

    def create_ticket(self, alert_id: str, hostname: str, risk_level: str) -> Ticket:
        priority = TicketPriority.HIGH if risk_level in ["critical", "high"] else TicketPriority.MEDIUM
        ticket = Ticket(
            ticket_id=self._gen_id(),
            title=f"[{risk_level.upper()}] {hostname} 安全事件",
            priority=priority,
            status="open",
            created_at=datetime.now().isoformat()
        )
        self.tickets[ticket.ticket_id] = ticket
        return ticket


if __name__ == "__main__":
    agent = TicketAgent()
    ticket = agent.create_ticket("alert_001", "server-01", "high")
    print(f"工单已创建: {ticket.ticket_id}")
