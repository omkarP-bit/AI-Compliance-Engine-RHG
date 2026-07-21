from fastapi import FastAPI
from ace.api.routes import router

app = FastAPI(title="ACE — AI Compliance Engine", version="0.1.0")
app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "ace"}
