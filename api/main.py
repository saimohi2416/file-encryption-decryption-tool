import sys
import os

api_dir = os.path.abspath(os.path.dirname(__file__))
if api_dir not in sys.path:
    sys.path.insert(0, api_dir)

from app.main import app
