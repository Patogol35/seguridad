def generate_report(url, xss, sqli, headers, risk):
    return {
        "url": url,
        "xss": xss,
        "sqli": sqli,
        "headers": headers,
        "risk": risk
    }