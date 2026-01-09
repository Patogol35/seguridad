from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import httpx

app = FastAPI(title="Web Security Analyzer")

# ✅ CORS (permite conexión desde el frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # luego puedes poner tu dominio
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: HttpUrl


@app.post("/scan")
async def scan_website(data: ScanRequest):
    try:
        async with httpx.AsyncClient(
            timeout=8.0,
            follow_redirects=True
        ) as client:
            response = await client.get(str(data.url))

        headers = response.headers
        issues = []

        if "x-frame-options" not in headers:
            issues.append("Missing X-Frame-Options header")

        if "content-security-policy" not in headers:
            issues.append("Missing Content-Security-Policy header")

        if "strict-transport-security" not in headers:
            issues.append("Missing HSTS header")

        return {
            "url": data.url,
            "status_code": response.status_code,
            "issues_found": len(issues),
            "issues": issues
        }

    except httpx.ConnectTimeout:
        raise HTTPException(status_code=408, detail="Connection timeout")

    except httpx.RequestError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Request error: {str(e)}"
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
