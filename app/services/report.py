def generate_report(url, xss, sqli, headers, risk):
    return {
        "url": url,
        "results": {
            "xss": xss,
            "sqli": sqli,
            "headers": headers
        },
        "risk": risk
    }
