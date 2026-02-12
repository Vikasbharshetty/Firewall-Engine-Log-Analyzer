from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from firewall_core import FirewallSimulator, LogAnalyzer
import uvicorn
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Sentinel Firewall API")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

firewall = FirewallSimulator()
analyzer = LogAnalyzer()

class Rule(BaseModel):
    id: Optional[int] = None
    action: str
    src_ip: str
    dst_port: int
    protocol: str

class Packet(BaseModel):
    src_ip: str
    dst_port: int
    protocol: str

class Threat(BaseModel):
    type: str
    src_ip: str
    count: int
    details: str

@app.get("/rules", response_model=List[Rule])
def get_rules():
    return firewall.rules

@app.post("/rules", response_model=Rule)
def add_rule(rule: Rule):
    return firewall.add_rule(rule.action, rule.src_ip, rule.dst_port, rule.protocol)

@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: int):
    firewall.remove_rule(rule_id)
    return {"message": "Rule deleted"}

@app.post("/simulate")
def simulate_packet(packet: Packet):
    action = firewall.check_packet(packet.src_ip, packet.dst_port, packet.protocol)
    analyzer.log_event(packet.src_ip, packet.dst_port, packet.protocol, action)
    return {"action": action}

@app.get("/threats", response_model=List[Threat])
def get_threats():
    return analyzer.analyze_logs()

@app.get("/logs")
def get_logs():
    if not os.path.exists(analyzer.log_file):
        return []
    logs = []
    with open(analyzer.log_file, "r") as f:
        for line in f.readlines()[-50:]:  # Return last 50 logs
            parts = line.strip().split(" | ")
            if len(parts) == 5:
                logs.append({
                    "timestamp": parts[0],
                    "src_ip": parts[1],
                    "dst_port": parts[2],
                    "protocol": parts[3],
                    "action": parts[4]
                })
    return logs

@app.get("/report")
def generate_report():
    threats = analyzer.analyze_logs()
    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_threats": len(threats),
        "threats": threats,
        "active_rules_count": len(firewall.rules),
        "summary": f"Security scan completed. Found {len(threats)} potential threats."
    }
    return report

if __name__ == "__main__":
    import os
    uvicorn.run(app, host="0.0.0.0", port=8000)
