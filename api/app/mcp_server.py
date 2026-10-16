from mcp.server.fastmcp import FastMCP
from typing import Dict, Any
from app.services.firewall_service import firewall_service
from app.services.rag_service import rag_service

mcp = FastMCP("SecureVault-SecOps")

@mcp.tool()
async def apply_firewall_rule(ip: str, action: str, reason: str) -> Dict[str, Any]:
    """Adds or updates a real-time network access rule (ALLOW or BLOCK) in the Enterprise Firewall."""
    try:
        result = firewall_service.add_rule(ip=ip, action=action, reason=reason)
        return result
    except Exception as e:
        return {"status": "error", "message": str(e)}

@mcp.tool()
async def query_incident_database(threat_type: str = "all", limit: int = 5) -> Dict[str, Any]:
    """Fetches historical cyber security incidents and MITRE ATT&CK classifications from the RAG pipeline."""
    try:
        cases = rag_service.query_incidents(threat_type=threat_type, limit=limit)
        return {
            "status": "success",
            "threat_type": threat_type,
            "total_matches": len(cases),
            "cases": cases
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    mcp.run(transport="stdio")
