import ipaddress
import time
from typing import Dict, List, Any

class FirewallService:
    def __init__(self):
        self.enabled = True
        self.rules: List[Dict[str, Any]] = [
            {"id": "rule_1", "ip": "192.168.1.100", "action": "BLOCK", "reason": "Repeated failed authentication attempts", "timestamp": time.time() - 3600},
            {"id": "rule_2", "ip": "10.0.0.45", "action": "ALLOW", "reason": "Whitelisted internal admin workstation", "timestamp": time.time() - 1800}
        ]
        self.audit_logs: List[Dict[str, Any]] = [
            {"action": "Rule Created", "ip": "192.168.1.100", "status": "BLOCK", "reason": "Repeated failed authentication attempts", "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")},
            {"action": "Rule Created", "ip": "10.0.0.45", "status": "ALLOW", "reason": "Whitelisted internal admin workstation", "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
        ]

    def validate_ip(self, ip_str: str) -> bool:
        try:
            ipaddress.ip_network(ip_str, strict=False)
            return True
        except ValueError:
            return False

    def get_status(self) -> Dict[str, Any]:
        return {
            "status": "Active" if self.enabled else "Inactive",
            "active_rules_count": len(self.rules),
            "threats_blocked_today": sum(1 for r in self.rules if r["action"] == "BLOCK"),
            "audit_logs_count": len(self.audit_logs)
        }

    def toggle(self, enable: bool) -> bool:
        self.enabled = enable
        self.log_audit("Firewall Toggle", "SYSTEM", f"Firewall status updated to {'Active' if enable else 'Inactive'}")
        return self.enabled

    def get_rules(self) -> List[Dict[str, Any]]:
        return self.rules

    def add_rule(self, ip: str, action: str, reason: str) -> Dict[str, Any]:
        action_clean = action.upper().strip()
        if action_clean not in ("ALLOW", "BLOCK"):
            raise ValueError("Invalid action. Must be 'ALLOW' or 'BLOCK'.")

        if not self.validate_ip(ip):
            raise ValueError(f"Invalid IP address or CIDR format: '{ip}'")

        if not reason or len(reason.strip()) < 3:
            raise ValueError("Reason must be at least 3 characters long.")

        # Check if rule already exists for IP
        for rule in self.rules:
            if rule["ip"] == ip:
                rule["action"] = action_clean
                rule["reason"] = reason
                rule["timestamp"] = time.time()
                self.log_audit("Rule Updated", ip, action_clean, reason)
                return {"status": "success", "message": f"Rule updated for IP {ip}", "rule": rule}

        new_rule = {
            "id": f"rule_{len(self.rules) + 1}",
            "ip": ip,
            "action": action_clean,
            "reason": reason,
            "timestamp": time.time()
        }
        self.rules.append(new_rule)
        self.log_audit("Rule Created", ip, action_clean, reason)
        return {"status": "success", "message": f"Firewall rule added for IP {ip}", "rule": new_rule}

    def delete_rule(self, rule_id: str) -> bool:
        initial_len = len(self.rules)
        self.rules = [r for r in self.rules if r["id"] != rule_id and r["ip"] != rule_id]
        deleted = len(self.rules) < initial_len
        if deleted:
            self.log_audit("Rule Deleted", rule_id, "REMOVED", "Manual deletion from firewall dashboard")
        return deleted

    def log_audit(self, action_name: str, ip: str, status: str, reason: str):
        self.audit_logs.insert(0, {
            "action": action_name,
            "ip": ip,
            "status": status,
            "reason": reason,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })
        if len(self.audit_logs) > 200:
            self.audit_logs.pop()

    def get_audit_logs(self) -> List[Dict[str, Any]]:
        return self.audit_logs

firewall_service = FirewallService()
