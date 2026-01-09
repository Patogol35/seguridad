from fastapi import FastAPI
from app.schemas.scan import ScanRequest
from app.scanners.xss import scan_xss
from app.scanners.sqli import scan_sqli
from app.scanners.headers import scan_headers
from app.services.risk import calculate_risk
from app.services.report import generate_report
import asyncio

app = FastAPI(title="Web Security Analyzer")

@app.post("/scan")
async def scan_website(data: ScanRequest):
    xss, sqli, headers = await asyncio.gather(
        scan_xss(data.url),
        scan_sqli(data.url),
        scan_headers(data.url)
    )

    risk = calculate_risk(xss, sqli, headers)
    return generate_report(data.url, xss, sqli, headers, risk)
