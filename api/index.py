# Vercel entrypoint redirecting to our FastAPI application
import sys
import os

# Append the project root to path so Python can find app_web.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app_web import app
