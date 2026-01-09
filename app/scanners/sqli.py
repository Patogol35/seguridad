import requests

SQL_PAYLOAD = "' OR '1'='1"

def scan_sqli(url):
    try:
        response = requests.get(url, params={"id": SQL_PAYLOAD}, timeout=5)
        errors = ["sql", "syntax", "mysql", "postgres"]
        vulnerable = any(err in response.text.lower() for err in errors)
        return {
            "vulnerable": vulnerable,
            "payload": SQL_PAYLOAD
        }
    except requests.RequestException:
        return {"vulnerable": False}
