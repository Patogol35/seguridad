from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import httpx

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

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            # =====================
            # REQUEST BASE
            # =====================
            response = await client.get(url)
            headers = response.headers

            issues = []
            recommendations = []

            # =====================
            # 🔐 HEADERS
            # =====================
            if "x-frame-options" not in headers:
                issues.append("Missing X-Frame-Options header")
                recommendations.append(
                    "Agregar X-Frame-Options para prevenir clickjacking"
                )

            if "content-security-policy" not in headers:
                issues.append("Missing Content-Security-Policy header")
                recommendations.append(
                    "Implementar Content-Security-Policy para mitigar XSS"
                )

            if "strict-transport-security" not in headers:
                issues.append("Missing HSTS header")
                recommendations.append(
                    "Habilitar HSTS para forzar HTTPS"
                )

            # =====================
            # 🧪 XSS (reflejado básico)
            # =====================
            XSS_PAYLOAD = "<script>alert(1)</script>"
            xss_vulnerable = False

            xss_resp = await client.get(url, params={"q": XSS_PAYLOAD})
            if XSS_PAYLOAD in xss_resp.text:
                xss_vulnerable = True
                issues.append("Possible reflected XSS")
                recommendations.append(
                    "Escapar y sanitizar entradas de usuario"
                )

            # =====================
            # 🧪 SQLi (error-based básico)
            # =====================
            SQL_PAYLOAD = "' OR '1'='1"
            sqli_vulnerable = False

            sqli_resp = await client.get(url, params={"id": SQL_PAYLOAD})
            errors = ["sql", "syntax", "mysql", "postgres"]

            if any(e in sqli_resp.text.lower() for e in errors):
                sqli_vulnerable = True
                issues.append("Possible SQL Injection")
                recommendations.append(
                    "Usar queries parametrizadas u ORM"
                )

            # =====================
            # 📊 RIESGO
            # =====================
            score = 0
            score += len(issues) * 10
            if xss_vulnerable:
                score += 20
            if sqli_vulnerable:
                score += 30

            level = "BAJO"
            if score >= 70:
                level = "ALTO"
            elif score >= 40:
                level = "MEDIO"

            return {
                "url": url,
                "status_code": response.status_code,
                "issues_found": len(issues),
                "issues": issues,
                "risk": {
                    "score": score,
                    "level": level
                },
                "recommendations": recommendations,
                "tests": {
                    "xss": xss_vulnerable,
                    "sqli": sqli_vulnerable
                }
            }

    except httpx.RequestError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
