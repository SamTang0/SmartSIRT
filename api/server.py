#!/usr/bin/env python3
"""
SmartSIRT Web API 服务
基于 FastAPI 提供 RESTful API

安装依赖:
    pip install fastapi uvicorn

运行:
    python api/server.py
    或
    uvicorn api.server:app --reload --port 8000

测试:
    curl http://localhost:8000/
    curl -X POST http://localhost:8000/analyze -H "Content-Type: application/json" -d '{"alert":"xmrig.exe detected"}'
"""

import sys
import os
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
from contextlib import asynccontextmanager

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from smart_sirt import SmartSIRT

# 全局 SmartSIRT 实例
sirt = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    global sirt
    sirt = SmartSIRT()
    print("SmartSIRT 引擎已初始化")
    yield
    print("SmartSIRT 引擎已关闭")


# 创建 FastAPI 应用
app = FastAPI(
    title="SmartSIRT API",
    description="基于多智能体的安全事件协同响应系统",
    version="1.0.0",
    lifespan=lifespan
)

# 配置 CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# 请求/响应模型
# ============================================================

class AlertRequest(BaseModel):
    """告警请求模型"""
    alert_id: Optional[str] = Field(None, description="告警ID")
    source: Optional[str] = Field(None, description="告警源 (EDR/AV/NIDS)")
    hostname: Optional[str] = Field(None, description="主机名")
    username: Optional[str] = Field(None, description="用户名")
    alert: str = Field(..., description="告警内容")
    message: Optional[str] = Field(None, description="附加消息")
    timestamp: Optional[str] = Field(None, description="告警时间")
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "alert_001",
                "source": "EDR",
                "hostname": "server-01",
                "username": "admin",
                "alert": "检测到进程 xmrig.exe 启动，连接至 pool.minexmr.com:4444"
            }
        }


class AlertResponse(BaseModel):
    """告警响应模型"""
    alert_id: str
    timestamp: str
    final_risk: str
    action: str
    action_description: str
    suggestions: List[str]
    reasoning: Dict[str, Any]
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "alert_001",
                "timestamp": "2026-06-02T22:00:00",
                "final_risk": "high",
                "action": "block_only",
                "action_description": "仅阻断网络连接",
                "suggestions": ["阻断恶意网络连接", "结束恶意进程"],
                "reasoning": {"analysis_reasoning": ["进程特征匹配: xmrig"], "intel_findings": []}
            }
        }


class BatchRequest(BaseModel):
    """批量请求模型"""
    alerts: List[AlertRequest]


class BatchResponse(BaseModel):
    """批量响应模型"""
    total: int
    results: List[AlertResponse]


class StatsResponse(BaseModel):
    """统计响应模型"""
    total: int
    by_risk: Dict[str, int]
    by_action: Dict[str, int]


class HealthResponse(BaseModel):
    """健康检查响应"""
    status: str
    version: str
    timestamp: str


# ============================================================
# API 端点
# ============================================================

@app.get("/", response_model=HealthResponse)
async def root():
    """根路径 - 健康检查"""
    return HealthResponse(
        status="running",
        version="1.0.0",
        timestamp=datetime.now().isoformat()
    )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """健康检查端点"""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.now().isoformat()
    )


@app.post("/analyze", response_model=AlertResponse)
async def analyze_alert(alert: AlertRequest):
    """
    分析单条告警
    
    - 输入: 告警信息
    - 输出: 风险等级、处置动作、建议列表
    """
    global sirt
    
    if sirt is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SmartSIRT 引擎未初始化"
        )
    
    try:
        alert_dict = alert.model_dump(exclude_none=True)
        result = sirt.process_alert(alert_dict)
        return AlertResponse(**result)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"处理告警失败: {str(e)}"
        )


@app.post("/batch", response_model=BatchResponse)
async def analyze_batch(request: BatchRequest):
    """
    批量分析告警
    
    - 输入: 多条告警
    - 输出: 所有告警的处理结果
    """
    global sirt
    
    if sirt is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SmartSIRT 引擎未初始化"
        )
    
    try:
        alerts = [alert.model_dump(exclude_none=True) for alert in request.alerts]
        results = sirt.process_batch(alerts)
        return BatchResponse(total=len(results), results=[AlertResponse(**r) for r in results])
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"批量处理失败: {str(e)}"
        )


@app.get("/stats", response_model=StatsResponse)
async def get_stats():
    """获取处理统计信息"""
    global sirt
    
    if sirt is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SmartSIRT 引擎未初始化"
        )
    
    stats = sirt.get_stats()
    return StatsResponse(**stats)


@app.post("/reset")
async def reset_stats():
    """重置统计信息"""
    global sirt
    
    if sirt is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SmartSIRT 引擎未初始化"
        )
    
    sirt.alert_history = []
    return {"status": "success", "message": "统计信息已重置"}


# ============================================================
# 命令行入口
# ============================================================

def main():
    """启动 API 服务"""
    port = int(os.environ.get("API_PORT", 8000))
    host = os.environ.get("API_HOST", "0.0.0.0")
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    SmartSIRT API 服务                        ║
    ║           基于多智能体的安全事件协同响应系统                   ║
    ╚══════════════════════════════════════════════════════════════╝
    
    服务地址: http://{host}:{port}
    API 文档: http://{host}:{port}/docs
    健康检查: http://{host}:{port}/health
    
    测试命令:
        curl http://localhost:{port}/
        curl -X POST http://localhost:{port}/analyze \\
             -H "Content-Type: application/json" \\
             -d '{{"alert":"xmrig.exe detected"}}'
    """)
    
    uvicorn.run(
        "api.server:app",
        host=host,
        port=port,
        reload=True
    )


if __name__ == "__main__":
    main()