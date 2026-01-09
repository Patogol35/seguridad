import requests
XSS_PAYLOAD = "<script>alert(1)</script>"
def scan_xss(url):
    try:
        response = requests.get(url, params={"q": XSS_PAYLOAD}, timeout=5)
        vulnerable = XSS_PAYLOAD in response.text
        return {
            "vulnerable": vulnerable,
            "payload": XSS_PAYLOAD
        }
    except:
        return {"vulnerable": False}