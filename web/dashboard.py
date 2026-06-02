#!/usr/bin/env python3
"""
SmartSIRT v2.0 Web 可视化仪表板
运行: python web/dashboard.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import dash
    from dash import dcc, html
    import plotly.graph_objs as go
except ImportError:
    print("请安装依赖: pip install dash plotly")
    sys.exit(1)

from smart_sirt_v2 import SmartSIRT

sirt = SmartSIRT()
sirt.process_alert({"alert": "xmrig.exe detected", "hostname": "server-01"})

app = dash.Dash(__name__, title="SmartSIRT v2.0")

app.layout = html.Div([
    html.H1("SmartSIRT v2.0 安全仪表板", style={"textAlign": "center"}),
    html.Div([
        html.Div([
            html.H3("告警统计"),
            dcc.Graph(id="stats-chart")
        ], className="six columns"),
    ], className="row")
])

@app.callback(
    dash.dependencies.Output("stats-chart", "figure"),
    dash.dependencies.Input("stats-chart", "id")
)
def update_chart(_):
    stats = sirt.get_stats()
    fig = go.Figure(data=[go.Bar(x=["总数"], y=[stats["total"]])])
    fig.update_layout(height=300)
    return fig

def run_dashboard(port=8050):
    print(f"仪表板启动: http://localhost:{port}")
    app.run(debug=True, host="0.0.0.0", port=port)

if __name__ == "__main__":
    run_dashboard()
