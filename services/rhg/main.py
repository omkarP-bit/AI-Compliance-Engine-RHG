from fastapi import FastAPI

from rhg.api.routes import router

app = FastAPI(title="RHG — Release Hardening Gate", version="0.1.0")
app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "rhg"}
