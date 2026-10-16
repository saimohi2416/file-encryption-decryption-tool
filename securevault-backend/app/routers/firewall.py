from fastapi import APIRouter, HTTPException, Request, Depends
from typing import Dict, Any, List
from app.schemas.chat import FirewallRuleRequest
from app.services.firewall_service import firewall_service
from app.middleware.rate_limiter import check_rate_limit

router = APIRouter(prefix="/api/v1/firewall", tags=["Enterprise Firewall"])

@router.get("/status")
async def get_status() -> Dict[str, Any]:
    return firewall_service.get_status()

@router.post("/toggle")
async def toggle_firewall(payload: Dict[str, bool]) -> Dict[str, Any]:
    enable = payload.get("enable", True)
    status = firewall_service.toggle(enable)
    return {"status": "success", "enabled": status}

@router.get("/rules")
async def get_rules() -> List[Dict[str, Any]]:
    return firewall_service.get_rules()

@router.post("/rules", dependencies=[Depends(check_rate_limit)])
async def add_rule(request: FirewallRuleRequest) -> Dict[str, Any]:
    try:
        return firewall_service.add_rule(request.ip, request.action, request.reason)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

@router.post("/rules/delete")
async def delete_rule(payload: Dict[str, str]) -> Dict[str, Any]:
    rule_id = payload.get("rule_id") or payload.get("id") or payload.get("ip")
    if not rule_id:
        raise HTTPException(status_code=400, detail="rule_id or ip required")
    success = firewall_service.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=444 if False else 404, detail="Rule not found")
    return {"status": "success", "message": f"Rule {rule_id} deleted"}

@router.get("/audit")
async def get_audit_logs() -> List[Dict[str, Any]]:
    return firewall_service.get_audit_logs()
