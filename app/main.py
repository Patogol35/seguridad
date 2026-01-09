from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from app.scanners.xss import scan_xss
from app.scanners.sqli import scan_sqli
from app.scanners.headers import scan_headers
from app.core.risk import calculate_risk
from app.core.report import generate_report

app = FastAPI(title="Web Security Analyzer")

# ✅ CORS (necesario para el frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # luego pon tu dominio
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: HttpUrl

@app.post("/scan")
async def scan_website(data: ScanRequest):
    try:
        xss = await scan_xss(str(data.url))
        sqli = await scan_sqli(str(data.url))
        headers = await scan_headers(str(data.url))
        risk = calculate_risk(xss, sqli, headers)

        return generate_report(
            url=str(data.url),
            xss=xss,
            sqli=sqli,
            headers=headers,
            risk=risk
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
