import json
import os
from datetime import datetime
import ipaddress

class FirewallSimulator:
    def __init__(self, rules_file="rules.json"):
        self.rules_file = rules_file
        self.rules = self.load_rules()

    def load_rules(self):
        if os.path.exists(self.rules_file):
            with open(self.rules_file, "r") as f:
                return json.load(f)
        return [
            {"id": 1, "action": "DENY", "src_ip": "192.168.1.100", "dst_port": 23, "protocol": "TCP"},
            {"id": 2, "action": "ALLOW", "src_ip": "any", "dst_port": 443, "protocol": "TCP"},
            {"id": 3, "action": "DENY", "src_ip": "any", "dst_port": 22, "protocol": "TCP"},
            {"id": 4, "action": "ALLOW", "src_ip": "10.0.0.0/8", "dst_port": 80, "protocol": "TCP"},
        ]

    def save_rules(self):
        with open(self.rules_file, "w") as f:
            json.dump(self.rules, f, indent=4)

    def add_rule(self, action, src_ip, dst_port, protocol):
        rule_id = max([r["id"] for r in self.rules], default=0) + 1
        new_rule = {
            "id": rule_id,
            "action": action,
            "src_ip": src_ip,
            "dst_port": dst_port,
            "protocol": protocol
        }
        self.rules.append(new_rule)
        self.save_rules()
        return new_rule

    def remove_rule(self, rule_id):
        self.rules = [r for r in self.rules if r["id"] != rule_id]
        self.save_rules()

    def check_packet(self, src_ip, dst_port, protocol):
        for rule in self.rules:
            if self._ip_matches(src_ip, rule["src_ip"]):
                if rule["dst_port"] == dst_port and rule["protocol"].upper() == protocol.upper():
                    return rule["action"]
        return "ALLOW"  # Default allow policy

    def _ip_matches(self, packet_ip, rule_ip):
        if rule_ip == "any":
            return True
        try:
            if "/" in rule_ip:
                return ipaddress.ip_address(packet_ip) in ipaddress.ip_network(rule_ip)
            return packet_ip == rule_ip
        except ValueError:
            return False

class LogAnalyzer:
    def __init__(self, log_file="firewall.log"):
        self.log_file = log_file

    def log_event(self, src_ip, dst_port, protocol, action):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} | {src_ip} | {dst_port} | {protocol} | {action}\n"
        with open(self.log_file, "a") as f:
            f.write(log_entry)

    def analyze_logs(self):
        threats = []
        ip_denies = {}
        
        if not os.path.exists(self.log_file):
            return []

        with open(self.log_file, "r") as f:
            for line in f:
                parts = line.strip().split(" | ")
                if len(parts) == 5:
                    ts, src, port, proto, action = parts
                    if action == "DENY":
                        ip_denies[src] = ip_denies.get(src, 0) + 1
                        if ip_denies[src] > 5:  # Brute force threshold
                            threats.append({
                                "type": "Brute Force Attempt",
                                "src_ip": src,
                                "count": ip_denies[src],
                                "details": f"Multiple access attempts blocked from {src}"
                            })
        
        # Deduplicate threats for the same IP
        unique_threats = {t["src_ip"]: t for t in threats}.values()
        return list(unique_threats)
