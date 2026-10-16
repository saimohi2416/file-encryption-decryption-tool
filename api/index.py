import sys
import os

api_dir = os.path.abspath(os.path.dirname(__file__))
if api_dir not in sys.path:
    sys.path.insert(0, api_dir)

from app.main import app

@app.api_route("/api", methods=["GET", "POST"])
@app.api_route("/api/index", methods=["GET", "POST"])
@app.api_route("/api/index.py", methods=["GET", "POST"])
async def vercel_root_entry(request):
    return {
        "status": "healthy",
        "service": "SecureVault AI Backend on Vercel",
        "version": "2.5.0",
        "path": str(request.url)
    }
