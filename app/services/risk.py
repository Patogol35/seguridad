def calculate_risk(xss, sqli, headers):
    score = 0

    if sqli.get("vulnerable"):
        score += 50
    if xss.get("vulnerable"):
        score += 30

    score += len(headers.get("missing_headers", [])) * 5

    if score >= 70:
        level = "ALTO"
    elif score >= 40:
        level = "MEDIO"
    else:
        level = "BAJO"

    return {
        "score": score,
        "level": level
    }
