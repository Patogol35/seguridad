import httpx
from app.core.config import DEFAULT_TIMEOUT, HEADERS

XSS_PAYLOAD = "<script>alert(1)</script>"


async def scan_xss(url: str):
    try:
        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            headers=HEADERS
        ) as client:
            response = await client.get(
                url,
                params={"q": XSS_PAYLOAD}
            )

        vulnerable = XSS_PAYLOAD in response.text

        return {
            "vulnerable": vulnerable,
            "payload": XSS_PAYLOAD
        }

    except httpx.RequestError:
        return {"vulnerable": False}
