import asyncio
import json
import os
import sys
import time
import httpx
import uvicorn
from multiprocessing import Process

from app.main import app

def run_server():
    uvicorn.run(app, host="127.0.0.1", port=8005, log_level="warning")

async def test_all_endpoints():
    base_url = "http://127.0.0.1:8005"
    print("\n========================================================")
    print("      SECUREVAULT AI BACKEND COMPREHENSIVE TEST SUITE")
    print("========================================================")

    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
        # 1. Health Endpoint Test
        print("\n[1] Testing Health Endpoint (/health)...")
        res = await client.get("/health")
        assert res.status_code == 200, f"Health check failed: {res.status_code}"
        data = res.json()
        print(f"    SUCCESS: {data}")

        # 2. Enterprise Firewall Status & Rules Test
        print("\n[2] Testing Enterprise Firewall Endpoints...")
        res = await client.get("/api/v1/firewall/status")
        assert res.status_code == 200
        print(f"    Firewall Status: {res.json()}")

        rule_payload = {"ip": "198.51.100.44", "action": "BLOCK", "reason": "Suspicious automated port scanning"}
        res = await client.post("/api/v1/firewall/rules", json=rule_payload)
        assert res.status_code == 200
        print(f"    Add Rule Result: {res.json()}")

        res = await client.get("/api/v1/firewall/rules")
        assert res.status_code == 200
        print(f"    Active Firewall Rules Count: {len(res.json())}")

        # 3. Zero-Knowledge Entropy Scanner Test
        print("\n[3] Testing Entropy & Metadata Scanner (/api/v1/scanner/entropy)...")
        scan_payload = {
            "file_name": "suspicious_payload.bin",
            "file_size": 1048576,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "entropy_score": 7.95,
            "header_hex": "4d5a900003000000",
            "mime_type": "application/pdf"
        }
        res = await client.post("/api/v1/scanner/entropy", json=scan_payload)
        assert res.status_code == 200
        scan_res = res.json()
        print(f"    Entropy Verdict: {scan_res['verdict']} | Risk: {scan_res['risk_level']} | Zero-Knowledge Compliant: {scan_res['zero_knowledge_compliant']}")

        # 4. Cyber Incident Cases & pgvector RAG Search Test
        print("\n[4] Testing Cyber Incident Database & pgvector RAG Search...")
        res = await client.get("/api/v1/incidents?threat_type=Brute Force")
        assert res.status_code == 200
        print(f"    Incident Filter Count: {res.json()['count']}")

        res = await client.get("/api/v1/incidents/search?query=entropy ransomware")
        assert res.status_code == 200
        rag_res = res.json()
        print(f"    Vector Matches: {rag_res['matches_found']} | Top Match: {rag_res['results'][0]['title']}")

        # 5. WebAuthn Passkeys Endpoints Test
        print("\n[5] Testing WebAuthn FIDO2 Passkey Options...")
        res = await client.post("/api/v1/webauthn/register/options", json={"username": "AliceDev"})
        assert res.status_code == 200
        reg_opts = res.json()
        print(f"    WebAuthn Registration Challenge Generated: {reg_opts['success']}")

        res = await client.post("/api/v1/webauthn/authenticate/options", json={"username": "AliceDev"})
        assert res.status_code == 200
        auth_opts = res.json()
        print(f"    WebAuthn Authentication Challenge Generated: {auth_opts['success']}")

        # 6. Copilot SSE Token Streaming Test
        print("\n[6] Testing Gemini Security Copilot SSE Token Streaming (/api/v1/copilot/chat/stream)...")
        copilot_payload = {
            "prompt": "Explain AES-256-GCM and PBKDF2 600,000 iterations in SecureVault zero-knowledge architecture.",
            "history": []
        }
        async with client.stream("POST", "/api/v1/copilot/chat/stream", json=copilot_payload) as stream_res:
            assert stream_res.status_code == 200
            print("    Connected to SSE stream. Receiving tokens:")
            tokens_received = []
            async for chunk in stream_res.aiter_text():
                tokens_received.append(chunk)
            print(f"    Total SSE Chunks Received: {len(tokens_received)}")
            print(f"    Sample Token Chunk: {tokens_received[0][:80] if tokens_received else 'None'}")

        # 7. Redis Rate Limiter (Denial of Wallet Protection) Test
        print("\n[7] Testing Sliding-Window Rate Limiter Quota Protection (20 req / 60s)...")
        rate_limit_triggered = False
        for i in range(25):
            res = await client.post("/api/v1/copilot/chat/stream", json={"prompt": f"Ping request {i}", "history": []})
            if res.status_code == 429:
                rate_limit_triggered = True
                print(f"    SUCCESS: Request {i+1} rejected with HTTP 429 Rate Limit Error: {res.json()['detail']}")
                break
        
        assert rate_limit_triggered, "Rate limiter did not trigger HTTP 429 after 20 requests"

    print("\n========================================================")
    print(" [ALL VERIFICATION TESTS PASSED SUCCESSFULLY!]")
    print("========================================================\n")

if __name__ == "__main__":
    proc = Process(target=run_server, daemon=True)
    proc.start()
    time.sleep(2) # Give uvicorn server 2s to initialize
    try:
        asyncio.run(test_all_endpoints())
    finally:
        proc.terminate()
