WEIGHTS = {"identity": 20, "device": 20, "location": 15, "time": 10, "behavior": 15, "resource_sensitivity": 20}
DEVICE = {"trusted": 0, "unknown": 12, "warning": 20, "compromised": 40}
LOCATION = {"normal": 0, "new": 8, "suspicious": 20}
SENSITIVITY = {"low": 2, "medium": 7, "high": 13, "critical": 20}

def evaluate(*, user_status: str, device_state: str, location: str, time_context: str, failed_attempts: int, sensitivity: str):
    factors = {
        "identity": 20 if user_status != "active" else 0,
        "device": DEVICE.get(device_state, 12),
        "location": LOCATION.get(location, 8),
        "time": 10 if time_context == "unusual" else 0,
        "behavior": min(15, max(0, failed_attempts) * 4),
        "resource_sensitivity": SENSITIVITY.get(sensitivity, 7),
    }
    score = min(100, sum(factors.values()))
    reasons = [f"{name.replace('_', ' ').title()} contributed {value} risk points" for name, value in factors.items() if value]
    if not reasons: reasons = ["All evaluated context signals are within the low-risk baseline"]
    level = "low" if score < 30 else "medium" if score < 70 else "high"
    if device_state == "compromised" or user_status != "active" or score >= 70: decision = "DENY"
    elif score >= 30: decision = "RESTRICT"
    else: decision = "ALLOW"
    return {"score": score, "level": level, "decision": decision, "factors": factors, "reasons": reasons}
