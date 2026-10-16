import math
import binascii
from typing import Dict, Any

class EntropyService:
    @staticmethod
    def calculate_shannon_entropy_from_hex(header_hex: str) -> float:
        if not header_hex:
            return 0.0
        try:
            data_bytes = bytes.fromhex(header_hex)
        except Exception:
            return 0.0
        
        if not data_bytes:
            return 0.0
            
        byte_counts = [0] * 256
        for b in data_bytes:
            byte_counts[b] += 1

        entropy = 0.0
        total_bytes = len(data_bytes)
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    def scan_heuristics(
        self,
        file_name: str,
        file_size: int,
        sha256: str,
        entropy_score: float,
        header_hex: str = "",
        mime_type: str = "application/octet-stream"
    ) -> Dict[str, Any]:
        """Scans metadata and header magic bytes without consuming raw file body."""
        calculated_header_entropy = self.calculate_shannon_entropy_from_hex(header_hex) if header_hex else entropy_score
        final_entropy = max(entropy_score, calculated_header_entropy)

        # Header Magic Byte Analysis
        known_magics = {
            "89504e47": "PNG Image",
            "ffd8ff": "JPEG Image",
            "25504446": "PDF Document",
            "504b0304": "ZIP Archive / DOCX",
            "53564352": "SecureVault Encrypted File (SVCR)",
            "4d5a": "Windows Executable (EXE/DLL)",
            "7f454c46": "Linux Executable (ELF)"
        }

        detected_magic = "Unknown Binary Format"
        clean_hex = header_hex.lower().replace(" ", "")
        for magic, fmt in known_magics.items():
            if clean_hex.startswith(magic):
                detected_magic = fmt
                break

        # Risk Classification
        risk_level = "LOW"
        anomalies = []

        if final_entropy > 7.5:
            risk_level = "MEDIUM"
            anomalies.append("High Shannon entropy (H > 7.5) indicates compressed or encrypted payload.")
        
        if final_entropy > 7.9:
            risk_level = "HIGH"
            anomalies.append("Extreme entropy (H > 7.9) consistent with ransomware or encrypted obfuscation.")

        if clean_hex.startswith("4d5a") and mime_type != "application/x-msdownload":
            risk_level = "HIGH"
            anomalies.append("MIME type spoofing detected: File headers match Windows Executable (MZ).")

        if not anomalies:
            anomalies.append("No security anomalies or header spoofing detected.")

        return {
            "file_name": file_name,
            "file_size_bytes": file_size,
            "sha256": sha256,
            "shannon_entropy": final_entropy,
            "magic_format": detected_magic,
            "declared_mime": mime_type,
            "risk_level": risk_level,
            "anomalies": anomalies,
            "zero_knowledge_compliant": True,
            "verdict": "SAFE" if risk_level == "LOW" else ("SUSPICIOUS" if risk_level == "MEDIUM" else "QUARANTINE_RECOMMENDED")
        }

entropy_service = EntropyService()
