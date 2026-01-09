def calculate_risk(xss, sqli, headers):
    score = 0
    if sqli["vulnerable"]:
        score += 50
    if xss["vulnerable"]:
        score += 30
    score += len(headers["missing_headers"]) * 5
    if score >= 70:
        level = "ALTO"
    elif score >= 40:
        level = "MEDIO"
    else:
        level = "BAJO"
    return {"score": score, "level": level}