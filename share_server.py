import os
import sys
import subprocess
import time
import re
import webbrowser

def main():
    print("\n=====================================================================")
    print("      SECUREVAULT ENTERPRISE - SHAREABLE HTTPS ENVIRONMENT")
    print("=====================================================================")
    print("Preparing local server and creating secure tunnel...")

    # 1. Start the local server on port 8000
    try:
        server_proc = subprocess.Popen(
            [sys.executable, "securevault.py", "serve", "--port", "8000"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        print(f"Error starting local server: {e}")
        return

    # 2. Start the SSH tunnel
    # We use -o StrictHostKeyChecking=no to avoid blocking prompts on Windows
    try:
        tunnel_proc = subprocess.Popen(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-R", "80:localhost:8000", "nokey@localhost.run"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
    except Exception as e:
        print(f"Error starting SSH tunnel: {e}")
        server_proc.terminate()
        return

    # 3. Read output line by line to extract the HTTPS URL
    public_url = None
    print("Generating public HTTPS URL. Please wait 3-5 seconds...")
    
    # Wait for the URL to appear in the stdout stream
    for line in iter(tunnel_proc.stdout.readline, ''):
        # Print lines to console for transparency
        if "lhr.life" in line or "https://" in line:
            # Match the HTTPS URL
            match = re.search(r'(https://[a-zA-Z0-9\-\.]+)', line)
            if match:
                public_url = match.group(1)
                break
        
        # Stop checking if process terminated early
        if tunnel_proc.poll() is not None:
            break

    if public_url:
        print("\n" + "="*70)
        print(" [SUCCESS] SECURE SHARING LINK GENERATED SUCCESSFULLY")
        print("="*70)
        print(f" SHARE THIS LINK WITH YOUR TEAM:")
        print(f" {public_url}")
        print("="*70)
        print(" (Web Crypto API works perfectly on this secure HTTPS link.)")
        print(" Press Ctrl+C at any time in this window to stop sharing.")
        print("="*70 + "\n")

        # Open in default system browser
        webbrowser.open(public_url)
    else:
        print("\n[ERROR] Failed to retrieve secure tunnel URL.")
        print("Please check your internet connection and verify that SSH is allowed.")

    # 4. Wait for user termination (Ctrl+C)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping secure tunnel and local server...")
    finally:
        tunnel_proc.terminate()
        server_proc.terminate()
        print("Stopped! SecureVault is no longer shared.")

if __name__ == '__main__':
    main()
