import httpx
from app.core.config import DEFAULT_TIMEOUT, HEADERS

SQL_PAYLOAD = "' OR '1'='1"


async def scan_sqli(url: str):
    try:
        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            headers=HEADERS
        ) as client:
            response = await client.get(
                url,
                params={"id": SQL_PAYLOAD}
            )

        errors = ["sql", "syntax", "mysql", "postgres"]
        vulnerable = any(
            e in response.text.lower()
            for e in errors
        )

        return {
            "vulnerable": vulnerable,
            "payload": SQL_PAYLOAD
        }

    except httpx.RequestError:
        return {"vulnerable": False}
