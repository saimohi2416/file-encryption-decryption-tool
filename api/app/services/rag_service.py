import math
from typing import List, Dict, Any, Optional

# Seed dataset of cyber incident cases and MITRE ATT&CK tactics
INCIDENT_DATABASE: List[Dict[str, Any]] = [
    {
        "id": "CASE-2024-001",
        "title": "Credential Stuffing & Brute Force Attempt on Auth Portal",
        "threat_type": "Brute Force",
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "tactic": "Credential Access",
        "severity": "HIGH",
        "description": "Distributed IP network attempting rapid credential guessing against login endpoints.",
        "remediation": "Enforce MFA/WebAuthn hardware tokens, apply IP rate limiting (20 req/min), and block offending subnet.",
        "keywords": ["password", "brute force", "login", "auth", "credential", "stuffing", "mfa"]
    },
    {
        "id": "CASE-2024-002",
        "title": "Ransomware Data Encryption & Obfuscated File Payload",
        "threat_type": "Ransomware",
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "severity": "CRITICAL",
        "description": "High Shannon entropy (H > 7.9) detected in uploaded binary with mismatched file header magic bytes.",
        "remediation": "Isolate host, enforce zero-knowledge local key isolation, inspect entropy scores before execution.",
        "keywords": ["entropy", "ransomware", "encrypt", "obfuscated", "magic bytes", "shannon", "payload"]
    },
    {
        "id": "CASE-2024-003",
        "title": "Unauthorized Data Exfiltration via HTTP Outbound Channel",
        "threat_type": "Exfiltration",
        "mitre_id": "T1567",
        "mitre_name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "severity": "HIGH",
        "description": "Unencrypted file metadata and payloads sent to external rogue domain.",
        "remediation": "Enforce Zero-Knowledge client architecture where raw file contents are never transmitted across the network.",
        "keywords": ["exfiltration", "upload", "leak", "unencrypted", "zero-knowledge", "privacy", "plain text"]
    },
    {
        "id": "CASE-2024-004",
        "title": "Web Crypto API Key Hijacking / Insecure Key Storage",
        "threat_type": "Key Compromise",
        "mitre_id": "T1552",
        "mitre_name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "severity": "MEDIUM",
        "description": "Attempted extraction of symmetric key bytes from local browser state.",
        "remediation": "Derive keys using PBKDF2 with SHA-256 (600,000 iterations), store non-extractable CryptoKey objects in memory.",
        "keywords": ["key", "pbkdf2", "web crypto", "aes-gcm", "secret", "iterations", "salt"]
    },
    {
        "id": "CASE-2024-005",
        "title": "Denial of Wallet Rate Limit Flooding",
        "threat_type": "DoS",
        "mitre_id": "T1499",
        "mitre_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "severity": "MEDIUM",
        "description": "High-frequency API queries targeting AI Copilot endpoints to exhaust API quotas.",
        "remediation": "Deploy Redis sliding-window log rate limiter with client IP tracking and HTTP 429 response enforcement.",
        "keywords": ["rate limit", "redis", "denial of wallet", "copilot", "quota", "sliding window", "429"]
    }
]

class RagService:
    def query_incidents(self, threat_type: str = "all", limit: int = 5, query_text: Optional[str] = None) -> List[Dict[str, Any]]:
        results = INCIDENT_DATABASE
        
        if threat_type and threat_type.lower() != "all":
            results = [inc for inc in results if threat_type.lower() in inc["threat_type"].lower() or threat_type.lower() in inc["mitre_id"].lower()]

        if query_text:
            query_terms = query_text.lower().split()
            scored_results = []
            for inc in results:
                score = 0
                searchable_blob = f"{inc['title']} {inc['description']} {inc['remediation']} {' '.join(inc['keywords'])}".lower()
                for term in query_terms:
                    if term in searchable_blob:
                        score += 1
                scored_results.append((score, inc))
            
            scored_results.sort(key=lambda x: x[0], reverse=True)
            results = [item[1] for item in scored_results if item[0] > 0]
            if not results:
                results = INCIDENT_DATABASE

        return results[:limit]

    def perform_vector_search(self, query: str, limit: int = 3) -> Dict[str, Any]:
        """Simulates pgvector semantic cosine-similarity retrieval over MITRE & Threat Cases."""
        incidents = self.query_incidents(query_text=query, limit=limit)
        return {
            "query": query,
            "vector_search_status": "active_pgvector_emulated",
            "matches_found": len(incidents),
            "results": [
                {
                    "case_id": inc["id"],
                    "title": inc["title"],
                    "mitre_classification": f"{inc['mitre_id']} ({inc['mitre_name']})",
                    "tactic": inc["tactic"],
                    "similarity_score": round(0.85 + (0.1 * (1.0 / (i + 1))), 4),
                    "description": inc["description"],
                    "remediation": inc["remediation"]
                }
                for i, inc in enumerate(incidents)
            ]
        }

rag_service = RagService()
