# risk.py — расчёт итогового риск-скора уязвимости

def calculate_risk(
    cvss: float,
    epss: float,
    asset_criticality: float,
    exploit_factor: float,
    exposure_factor: float
) -> float:
    """
    Вычисляет итоговый риск-скор на основе взвешенной формулы.

    Формула:
        risk = 0.3 * (cvss/10) + 0.25 * epss + 0.2 * asset_criticality
               + 0.15 * exploit_factor + 0.1 * exposure_factor

    Все веса в сумме дают 1.0, результат в диапазоне [0, 1].

    Параметры:
        cvss              — базовая оценка CVSS (0–10)
        epss              — вероятность эксплуатации (0–1)
        asset_criticality — критичность актива (0–1)
        exploit_factor    — наличие эксплойта (0–1)
        exposure_factor   — степень экспозиции (0–1)

    Возвращает:
        float — итоговый риск в диапазоне [0, 1]
    """
    risk = (
        0.30 * (cvss / 10) +
        0.25 * epss +
        0.20 * asset_criticality +
        0.15 * exploit_factor +
        0.10 * exposure_factor
    )
    # Ограничиваем результат в пределах [0, 1]
    return round(min(max(risk, 0.0), 1.0), 4)


def get_risk_level(risk_score: float) -> str:
    """
    Классифицирует риск по уровням.
    
    High   >= 0.7
    Medium >= 0.4
    Low    <  0.4
    """
    if risk_score >= 0.7:
        return "High"
    elif risk_score >= 0.4:
        return "Medium"
    else:
        return "Low"
