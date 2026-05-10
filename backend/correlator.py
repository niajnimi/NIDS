def clamp(value: float, lower: int = 0, upper: int = 100) -> int:
    return max(lower, min(upper, int(value)))


def compute_risk_score(port_diversity: int, auth_failures: int, packet_volume: int, window_seconds: int) -> int:
    speed_factor = 60 / max(window_seconds, 1)
    score = (
        min(port_diversity * 1.5, 35)
        + min(auth_failures * 6, 30)
        + min(packet_volume / 20, 25)
        + min(speed_factor * 10, 10)
    )
    return clamp(score)


def elevate_if_composite(port_diversity: int, auth_failures: int) -> bool:
    return port_diversity >= 10 and auth_failures >= 3