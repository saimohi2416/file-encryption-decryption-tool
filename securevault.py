import os
import sys
import argparse
from http.server import HTTPServer, SimpleHTTPRequestHandler

import subprocess

# Auto-install missing dependencies so the script runs flawlessly on any PC
try:
    import cryptography # type: ignore
except ImportError:
    print("⚙️ 'cryptography' library not found. Auto-installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    print("✅ Installation complete! Restarting...")
    os.execv(sys.executable, ['python'] + sys.argv)

# type: ignore is added to hide the 4 "missing import" problems in VS Code 
# when the library isn't installed yet.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # type: ignore
from cryptography.hazmat.primitives import hashes # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore

MAGIC = b"SVCR"
VERSION = b"\x01"
SALT_LEN = 16
IV_LEN = 12
PBKDF2_ITERS = 310_000

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
    """Encrypt raw bytes using AES-256-GCM exactly like the SecureVault Web UI"""
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    iv = os.urandom(IV_LEN)
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, file_data, None)
    
    # Format: MAGIC (4) | VERSION (1) | SALT (16) | IV (12) | CIPHERTEXT
    return MAGIC + VERSION + salt + iv + ciphertext

def decrypt_data(file_data: bytes, password: str) -> bytes:
    """Decrypt SecureVault format bytes"""
    if len(file_data) < 33:
        raise ValueError("File too small to be a valid SecureVault file.")
    if file_data[:4] != MAGIC:
        raise ValueError("Invalid magic number. Not a SecureVault file.")
    if file_data[4:5] != VERSION:
        raise ValueError("Unsupported SecureVault version.")
    
    salt = file_data[5:21]
    iv = file_data[21:33]
    ciphertext = file_data[33:]
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    try:
        return aesgcm.decrypt(iv, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed! Wrong password or corrupted file.")

def encrypt_file(input_path, output_path, password):
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"❌ Error: Input file '{input_path}' not found.")
        sys.exit(1)
        
    encrypted = encrypt_data(data, password)
    
    try:
        with open(output_path, 'wb') as f:
            f.write(encrypted)
        print(f"✅ Encrypted successfully: {output_path}")
    except IOError as e:
        print(f"❌ Error writing output file: {e}")
        sys.exit(1)

def decrypt_file(input_path, output_path, password):
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"❌ Error: Input file '{input_path}' not found.")
        sys.exit(1)
        
    decrypted = decrypt_data(data, password)
    
    try:
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        print(f"✅ Decrypted successfully: {output_path}")
    except IOError as e:
        print(f"❌ Error writing output file: {e}")
        sys.exit(1)

# ==========================================
# Local Web Server
# ==========================================
class SecureVaultAPIHandler(SimpleHTTPRequestHandler):
    # This serves the files in the directory so index.html works smoothly
    # Explicitly set MIME types to fix Windows registry MIME mapping issues
    extensions_map = SimpleHTTPRequestHandler.extensions_map.copy()
    extensions_map.update({
        '.js': 'application/javascript',
        '.css': 'text/css',
        '.html': 'text/html',
        '.svg': 'image/svg+xml'
    })

def run_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, SecureVaultAPIHandler)
    print(f"🚀 SecureVault Local Server running on http://localhost:{port}")
    print("Use this URL in your browser to avoid 'file://' security errors!")
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
        encrypt_file(args.input, args.output, args.password)
    elif args.command == "decrypt":
        try:
            decrypt_file(args.input, args.output, args.password)
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
    else:
        parser.print_help()
