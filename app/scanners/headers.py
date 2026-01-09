import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options"
]

def scan_headers(url):
    try:
        response = requests.get(url, timeout=5)
        missing = [h for h in SECURITY_HEADERS if h not in response.headers]
        return {"missing_headers": missing}
    except requests.RequestException:
        return {"missing_headers": SECURITY_HEADERS}
