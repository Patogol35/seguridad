import httpx
from app.core.config import DEFAULT_TIMEOUT, HEADERS

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options"
]

async def scan_headers(url: str):
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=HEADERS) as client:
            response = await client.get(url)
            missing = [h for h in SECURITY_HEADERS if h not in response.headers]
            return {"missing_headers": missing}
    except httpx.RequestError:
        return {"missing_headers": SECURITY_HEADERS}
