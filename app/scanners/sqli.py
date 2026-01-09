import httpx

SQL_PAYLOAD = "' OR '1'='1"

async def scan_sqli(url: str):
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(url, params={"id": SQL_PAYLOAD})
            errors = ["sql", "syntax", "mysql", "postgres"]
            vulnerable = any(e in response.text.lower() for e in errors)
            return {
                "vulnerable": vulnerable,
                "payload": SQL_PAYLOAD
            }
    except httpx.RequestError:
        return {"vulnerable": False}
