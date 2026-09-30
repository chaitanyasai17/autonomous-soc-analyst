"""
ASOC — FastAPI application root proxy entrypoint.
Exposes 'app' from app.main for standard entrypoint resolution.
"""

import sys
import traceback
from pathlib import Path

# Ensure backend root and parent directories are in sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
if str(backend_dir.parent) not in sys.path:
    sys.path.insert(0, str(backend_dir.parent))

try:
    from app.main import app
except Exception as startup_exc:
    err_tb = traceback.format_exc()
    print("CRITICAL: Failed to import app.main:", err_tb, file=sys.stderr)
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    app = FastAPI(title="ASOC Emergency Fallback")

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
    async def emergency_catch_all(full_path: str):
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": "startup_failed",
                "message": f"Application initialization error: {startup_exc}",
                "traceback": err_tb.splitlines()[-15:],
            },
        )

__all__ = ["app"]
