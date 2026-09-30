from fastapi import FastAPI
from pydantic import BaseModel

from sandbox import analyze_url


app = FastAPI(
    title="Phishing Sandbox",
    version="1.0"
)


class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():

    return {
        "service": "Phishing Sandbox",
        "status": "running"
    }


@app.post("/analyze")
async def analyze(request: URLRequest):

    return await analyze_url(request.url)