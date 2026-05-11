import os
import sys
import subprocess
import threading
from http.server import HTTPServer

# ==========================================
# Phase 1: Native Desktop App Implementation
# ==========================================

print("Initializing SecureVault Enterprise Environment...")

def install_and_import(package, import_name=None):
    if import_name is None:
        import_name = package
    try:
        __import__(import_name)
    except ImportError:
        print(f"Installing missing dependency: {package}...")
        try:
            # Try python -m pip first
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        except Exception:
            # Fallback
            subprocess.check_call(["pip", "install", package])
        finally:
            __import__(import_name)

# Ensure required packages for a Native Desktop App
install_and_import("cryptography")
install_and_import("pywebview", "webview")

import webview  # type: ignore
from securevault import SecureVaultAPIHandler

def start_background_server():
    # Bind to 127.0.0.1 on port 0 to let the OS assign a random, available ephemeral port.
    # This prevents "Address already in use" errors and avoids relying on a fixed port like 8000/8080.
    server_address = ('127.0.0.1', 0)
    httpd = HTTPServer(server_address, SecureVaultAPIHandler)
    assigned_port = httpd.server_port
    
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    
    return assigned_port

if __name__ == '__main__':
    # 1. Start the Secure Local Server dynamically
    dynamic_port = start_background_server()
    print(f"Server securely bound to ephemeral port: {dynamic_port}")
    
    # 2. Launch the Native Window via pywebview
    # This turns the web application into a standalone desktop application.
    print("Launching SecureVault Desktop Client...")
    window = webview.create_window(
        'SecureVault Enterprise', 
        f'http://127.0.0.1:{dynamic_port}/splash.html',
        width=1200, 
        height=800, 
        min_size=(900, 650),
        background_color='#050505',
        text_select=False
    )
    
    # Start the application loop
    webview.start(private_mode=False)
