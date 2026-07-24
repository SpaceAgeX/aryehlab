from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles


BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"

app = FastAPI(title="Aryeh Lab")
app.mount("/public", StaticFiles(directory=PUBLIC_DIR), name="public")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(PUBLIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "online"}
