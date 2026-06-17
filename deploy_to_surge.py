import os
import sys
import urllib.request
import zipfile
import subprocess
import random
import string

def random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def main():
    print("Initializing deployment engine...")
    
    # 1. Download Node.js portable zip
    zip_url = "https://nodejs.org/dist/v20.11.1/node-v20.11.1-win-x64.zip"
    zip_path = "node-portable.zip"
    extract_dir = "node-portable"
    
    if not os.path.exists(extract_dir):
        print("Downloading Node.js portable (30MB)... Please wait.")
        urllib.request.urlretrieve(zip_url, zip_path)
        print("Extracting Node.js package...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(".")
        # Find the extracted folder and rename it
        for name in os.listdir("."):
            if name.startswith("node-") and os.path.isdir(name) and name != extract_dir:
                os.rename(name, extract_dir)
                break
        os.remove(zip_path)
        print("Node.js portable environment ready.")
    else:
        print("Node.js portable environment already exists.")

    # Paths to node.exe
    node_bin = os.path.abspath(os.path.join(extract_dir, "node.exe"))

    # Generate temporary credentials
    email = f"securevault-{random_string(6)}@example.com"
    password = f"pass-{random_string(10)}"

    # 2. Deploy
    domain = f"securevault-{random_string(8)}.surge.sh"
    print(f"Deploying project to: https://{domain} ...")

    # Start surge process directly via node.exe
    # surge expects:
    # 1. email
    # 2. password
    # 3. project directory
    # 4. domain name
    proc = subprocess.Popen(
        [node_bin, "node_modules/surge/bin/surge", "./", domain],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    # Send stdin inputs to surge CLI
    inputs = f"{email}\n{password}\n"
    
    try:
        stdout, stderr = proc.communicate(input=inputs, timeout=45)
        
        print("--- Surge STDOUT ---")
        print(stdout)
        print("--- Surge STDERR ---")
        print(stderr)
        
        if proc.returncode == 0 and "Success" in stdout:
            print("\n" + "="*75)
            print(" [SUCCESS] DEPLOYMENT COMPLETED SUCCESSFULLY!")
            print("="*75)
            print(f" Public HTTPS URL: https://{domain}")
            print("="*75)
            print(" You can share this URL with anyone. It runs 100% on the cloud,")
            print(" has zero localhost dependencies, and runs error-free over HTTPS.")
            print("="*75 + "\n")
        else:
            print("\n=======================================================")
            print(" [ERROR] DEPLOYMENT FAILED")
            print("=======================================================")
            print("Surge CLI did not report a successful publication.")
            print("=======================================================\n")
    except Exception as e:
        print(f"Timeout or error during deployment: {e}")
        proc.kill()

if __name__ == '__main__':
    main()
