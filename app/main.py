from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from headers import scan_headers
from sqli import scan_sqli
from xss import scan_xss
from risk import calculate_risk
from report import generate_report

app = FastAPI(title="Web Security Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: HttpUrl

@app.post("/scan")
async def scan_website(data: ScanRequest):
    try:
        url = str(data.url)

        xss = await scan_xss(url)
        sqli = await scan_sqli(url)
        headers = await scan_headers(url)
        risk = calculate_risk(xss, sqli, headers)

        return generate_report(url, xss, sqli, headers, risk)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
