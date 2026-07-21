import os
import sys
import argparse
import struct
import hashlib
from http.server import HTTPServer, SimpleHTTPRequestHandler
import subprocess

# Auto-install missing dependencies so the script runs flawlessly on any PC
try:
    import cryptography # type: ignore
except ImportError:
    print(" 'cryptography' library not found. Auto-installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    print(" Installation complete! Restarting...")
    os.execv(sys.executable, ['python'] + sys.argv)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM # type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # type: ignore
from cryptography.hazmat.primitives import hashes # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore

MAGIC = b"SVCR"
VERSION = b"\x01"
SALT_LEN = 16
IV_LEN = 12
PBKDF2_ITERS = 600_000

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive AES-256 key using PBKDF2 exactly as the Web Crypto API does."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_data(file_data: bytes, password: str) -> bytes:
    """Encrypt raw bytes using AES-256-GCM (outputs Version 2 by default now)"""
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    iv = os.urandom(IV_LEN)
    
    # Calculate SHA-256 integrity hash
    original_hash = hashlib.sha256(file_data).digest()
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, file_data, None)
    
    # Format V2: MAGIC (4) | VERSION (1: 0x02) | SALT (16) | IV (12) | HASH (32) | CIPHERTEXT
    return MAGIC + b"\x02" + salt + iv + original_hash + ciphertext

def decrypt_file(input_path, output_path, password):
    """Decrypt SecureVault files supporting Version 1, 2, and 3 (streaming)"""
    try:
        with open(input_path, 'rb') as f:
            header = f.read(77) # Read enough for V3 header
    except FileNotFoundError:
        print(f" Error: Input file '{input_path}' not found.")
        sys.exit(1)

    if len(header) < 33:
        print(" Error: File too small to be a valid SecureVault file.")
        sys.exit(1)

    if header[:4] != MAGIC:
        print(" Error: Invalid magic number. Not a SecureVault file.")
        sys.exit(1)

    version = header[4]
    if version not in (1, 2, 3):
        print(f" Error: Unsupported SecureVault version: v{version}.")
        sys.exit(1)

    salt = header[5:21]
    iv = header[21:33]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    if version == 1:
        # V1: MAGIC(4) | VERSION(1) | SALT(16) | IV(12) | CIPHERTEXT
        with open(input_path, 'rb') as f:
            f.seek(33)
            ciphertext = f.read()
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
        except Exception:
            print(" Error: Decryption failed! Wrong password or corrupted file.")
            sys.exit(1)
        
        try:
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            print(f" Decrypted successfully: {output_path}")
        except IOError as e:
            print(f" Error writing output file: {e}")
            sys.exit(1)

    elif version == 2:
        # V2: MAGIC(4) | VERSION(1) | SALT(16) | IV(12) | HASH(32) | CIPHERTEXT
        expected_hash = header[33:65]
        with open(input_path, 'rb') as f:
            f.seek(65)
            ciphertext = f.read()
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
        except Exception:
            print(" Error: Decryption failed! Wrong password or corrupted file.")
            sys.exit(1)

        # Verify Hash
        computed_hash = hashlib.sha256(plaintext).digest()
        if computed_hash != expected_hash:
            print(" Warning: Integrity check failed! File may have been tampered with.")
        else:
            print(" Integrity verified successfully (SHA-256 matches).")

        try:
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            print(f" Decrypted successfully: {output_path}")
        except IOError as e:
            print(f" Error writing output: {e}")
            sys.exit(1)

    elif version == 3:
        # V3: MAGIC(4) | VERSION(1) | SALT(16) | IV(12) | HASH(32) | SIZE(8) | CHUNK_SIZE(4) | ENCRYPTED CHUNKS
        expected_hash = header[33:65]
        file_size = struct.unpack('>Q', header[65:73])[0]
        chunk_size = struct.unpack('>I', header[73:77])[0]

        enc_chunk_size = chunk_size + 16
        num_chunks = (file_size + chunk_size - 1) // chunk_size

        sha256 = hashlib.sha256()

        try:
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                infile.seek(77) # Move past header
                for i in range(num_chunks):
                    is_last = (i == num_chunks - 1)
                    
                    # Read encrypted chunk
                    enc_chunk = infile.read(enc_chunk_size if not is_last else -1)
                    if not enc_chunk:
                        break

                    # Derive chunk IV (replace last 4 bytes of base IV with chunk index)
                    chunk_iv = bytearray(iv)
                    chunk_iv[8:12] = struct.pack('>I', i)
                    
                    # AAD: chunk index (4B) + is_last (1B)
                    aad = bytearray(5)
                    aad[0:4] = struct.pack('>I', i)
                    aad[4] = 1 if is_last else 0

                    # Decrypt chunk
                    dec_chunk = aesgcm.decrypt(bytes(chunk_iv), enc_chunk, bytes(aad))
                    
                    outfile.write(dec_chunk)
                    sha256.update(dec_chunk)

            # Verify Hash
            if sha256.digest() != expected_hash:
                print(" Warning: Integrity check failed! Decrypted stream hash mismatch.")
            else:
                print(" Integrity verified successfully (SHA-256 matches).")
            print(f" Decrypted successfully: {output_path}")
        except Exception as e:
            print(f" Error: Decryption failed! {e}")
            if os.path.exists(output_path):
                os.remove(output_path)
            sys.exit(1)

# ==========================================
# Local Web Server
# ==========================================
import json
from datetime import datetime

# Global firewall state
firewall_rules = {}             # ip -> "ALLOW" | "BLOCK"
block_all_third_parties = True  # True by default to protect from third parties
connections_log = []            # list of dicts
incidents_log = []              # list of dicts
incident_counter = 5000

class SecureVaultAPIHandler(SimpleHTTPRequestHandler):
    extensions_map = SimpleHTTPRequestHandler.extensions_map.copy()
    extensions_map.update({
        '.js': 'application/javascript',
        '.css': 'text/css',
        '.html': 'text/html',
        '.svg': 'image/svg+xml'
    })

    def is_ip_allowed(self, ip):
        # Normalize local IPs
        normalized_ip = ip.strip()
        if normalized_ip.startswith("::ffff:"):
            normalized_ip = normalized_ip[7:]
            
        if normalized_ip in ('127.0.0.1', '::1', 'localhost'):
            return True
            
        # Check custom rules
        if normalized_ip in firewall_rules:
            return firewall_rules[normalized_ip] == "ALLOW"
            
        # If block_all_third_parties is active, reject
        if block_all_third_parties:
            return False
            
        return True

    def log_connection(self, ip, action):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        normalized_ip = ip.strip()
        if normalized_ip.startswith("::ffff:"):
            normalized_ip = normalized_ip[7:]

        connections_log.append({
            "proto": "TCP",
            "local": f"{get_local_ip()}:{self.server.server_port}",
            "foreign": f"{normalized_ip}:{self.client_address[1]}",
            "state": "ESTABLISHED" if action == "ALLOW" else "BLOCKED",
            "action": action
        })
        if len(connections_log) > 100:
            connections_log.pop(0)
            
        if action == "BLOCK":
            global incident_counter
            incident_id = f"#SEC-{incident_counter}"
            incident_counter += 1
            incidents_log.append({
                "id": incident_id,
                "time": now_str,
                "type": "Unauthorized Access Attempt (Firewall Blocked)",
                "severity": "High",
                "status": "Blocked"
            })
            if len(incidents_log) > 100:
                incidents_log.pop(0)

    def check_firewall(self):
        ip = self.client_address[0]
        if not self.is_ip_allowed(ip):
            self.log_connection(ip, "BLOCK")
            
            # If requesting an API endpoint, return JSON
            if self.path.startswith('/api/'):
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Forbidden: Blocked by SecureVault Enterprise Firewall"}).encode('utf-8'))
            else:
                # Return custom access denied HTML
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                local_ip = get_local_ip()
                normalized_ip = ip.strip()
                if normalized_ip.startswith("::ffff:"):
                    normalized_ip = normalized_ip[7:]

                html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied - SecureVault Firewall</title>
  <style>
    body {{
      background-color: #050505;
      color: #f3f4f6;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
      box-sizing: border-box;
    }}
    .card {{
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(239, 68, 68, 0.2);
      border-radius: 12px;
      padding: 40px;
      max-width: 500px;
      width: 100%;
      text-align: center;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
      backdrop-filter: blur(10px);
    }}
    .icon {{
      color: #ef4444;
      font-size: 64px;
      margin-bottom: 20px;
    }}
    h1 {{
      font-size: 24px;
      font-weight: 700;
      margin: 0 0 10px 0;
      letter-spacing: -0.5px;
    }}
    p {{
      color: #9ca3af;
      font-size: 15px;
      line-height: 1.6;
      margin: 0 0 24px 0;
    }}
    .details {{
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 16px;
      text-align: left;
      font-family: monospace;
      font-size: 13px;
      margin-bottom: 24px;
    }}
    .details-row {{
      display: flex;
      justify-content: space-between;
      margin-bottom: 8px;
    }}
    .details-row:last-child {{
      margin-bottom: 0;
    }}
    .label {{
      color: #6b7280;
    }}
    .value {{
      color: #f3f4f6;
    }}
    .footer {{
      color: #4b5563;
      font-size: 12px;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">⚠️</div>
    <h1>Access Blocked by Firewall</h1>
    <p>Your IP address is not authorized to access this SecureVault Enterprise server. The connection attempt has been logged for security review.</p>
    <div class="details">
      <div class="details-row"><span class="label">IP Address:</span><span class="value">{normalized_ip}</span></div>
      <div class="details-row"><span class="label">Timestamp:</span><span class="value">{now_str}</span></div>
      <div class="details-row"><span class="label">Node Host:</span><span class="value">{local_ip}:{self.server.server_port}</span></div>
      <div class="details-row"><span class="label">Policy:</span><span class="value" style="color: #ef4444; font-weight: bold;">BLOCK_ALL_THIRD_PARTY</span></div>
    </div>
    <div class="footer">SecureVault Intrusion Prevention System (IPS)</div>
  </div>
</body>
</html>"""
                self.wfile.write(html_content.encode('utf-8'))
            return False
        return True

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        if not self.check_firewall():
            return
            
        if self.path == '/api/firewall/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({
                "block_third_parties": block_all_third_parties,
                "rules": firewall_rules,
                "connections": connections_log,
                "incidents": incidents_log
            }).encode('utf-8'))
            return
            
        # Log successful connection (only for non-API calls to avoid cluttering)
        if not self.path.startswith('/api/'):
            self.log_connection(self.client_address[0], "ALLOW")
            
        super().do_GET()

    def do_POST(self):
        if not self.check_firewall():
            return
            
        if self.path.startswith('/api/firewall/'):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(post_data)
            except Exception:
                data = {}
                
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            global block_all_third_parties
            if self.path == '/api/firewall/toggle':
                block_all_third_parties = data.get('block', True)
                self.wfile.write(json.dumps({"success": True, "block_third_parties": block_all_third_parties}).encode('utf-8'))
                
            elif self.path == '/api/firewall/rules':
                ip = data.get('ip')
                action = data.get('action', 'BLOCK')
                if ip:
                    # Normalize IP
                    ip = ip.strip()
                    firewall_rules[ip] = action
                    self.wfile.write(json.dumps({"success": True, "rules": firewall_rules}).encode('utf-8'))
                else:
                    self.wfile.write(json.dumps({"success": False, "error": "Invalid IP"}).encode('utf-8'))
                    
            elif self.path == '/api/firewall/rules/delete':
                ip = data.get('ip')
                if ip:
                    ip = ip.strip()
                if ip in firewall_rules:
                    del firewall_rules[ip]
                    self.wfile.write(json.dumps({"success": True, "rules": firewall_rules}).encode('utf-8'))
                else:
                    self.wfile.write(json.dumps({"success": False, "error": "IP not found in rules"}).encode('utf-8'))
            else:
                self.wfile.write(json.dumps({"success": False, "error": "Not Found"}).encode('utf-8'))
            return
            
        self.send_response(404)
        self.end_headers()


def get_local_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def run_server(port=8000):
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, SecureVaultAPIHandler)
    local_ip = get_local_ip()
    
    print("\n" + "="*75)
    print("  [SECURED] SECUREVAULT ENTERPRISE PORTABLE WEB SERVER RUNNING")
    print("="*75)
    print(f"  Local Access:   http://localhost:{port}")
    if local_ip != "127.0.0.1":
        print(f"  Network Access: http://{local_ip}:{port}  <-- Share this link on your Wi-Fi/LAN!")
    print("="*75)
    print("\n  [WARNING] IMPORTANT - SHARING INFORMATION & BROWSER SECURITY RULES:")
    print("  Modern browsers block Web Crypto features on insecure HTTP sites.")
    print("  Deploy to HTTPS or use local flags to bypass.")
    print("="*75 + "\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SecureVault Advanced CLI Engine")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Serve Command
    parser_serve = subparsers.add_parser("serve", help="Run local web server for the UI")
    parser_serve.add_argument("--port", type=int, default=8000)

    # Encrypt Command
    parser_enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    parser_enc.add_argument("input", help="Input file path")
    parser_enc.add_argument("output", help="Output file path")
    parser_enc.add_argument("--password", required=True, help="Encryption password")

    # Decrypt Command
    parser_dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    parser_dec.add_argument("input", help="Input file path")
    parser_dec.add_argument("output", help="Output file path")
    parser_dec.add_argument("--password", required=True, help="Decryption password")

    args = parser.parse_args()

    if args.command == "serve":
        run_server(args.port)
    elif args.command == "encrypt":
        try:
            with open(args.input, 'rb') as f:
                data = f.read()
            encrypted = encrypt_data(data, args.password)
            with open(args.output, 'wb') as f:
                f.write(encrypted)
            print(f" Encrypted successfully: {args.output}")
        except Exception as e:
            print(f" Error: {e}")
            sys.exit(1)
    elif args.command == "decrypt":
        decrypt_file(args.input, args.output, args.password)
    else:
        parser.print_help()
