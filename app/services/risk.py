def calculate_risk(xss, sqli, headers):
    score = 0

    if sqli.get("vulnerable"):
        score += 50

    if xss.get("vulnerable"):
        score += 30

    score += len(headers.get("missing_headers", [])) * 5

    level = "BAJO"
    if score >= 70:
        level = "ALTO"
    elif score >= 40:
        level = "MEDIO"

    return {
        "score": score,
        "level": level
    }
