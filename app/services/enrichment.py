# enrichment.py — обогащение уязвимостей дополнительными метриками

import json
from urllib import error, parse, request


EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_TIMEOUT_SECONDS = 5
_EPSS_CACHE: dict[str, float] = {}

CISA_KEV_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_TIMEOUT_SECONDS = 10
_CISA_KEV_CACHE: set[str] | None = None


def _fetch_epss_from_api(cve: str) -> float | None:
    """
    Возвращает EPSS для CVE из FIRST API.
    Если значение не удалось получить, возвращает None.
    При успешном получении кеширует результат для повторных обращений.
    """
    normalized = cve.strip().upper() if isinstance(cve, str) else ""
    if not normalized:
        return None

    if normalized in _EPSS_CACHE:
        return _EPSS_CACHE[normalized]

    query = parse.urlencode({"cve": normalized})
    url = f"{EPSS_API_URL}?{query}"
    req = request.Request(url, headers={"User-Agent": "VulnGuard/1.0"})

    try:
        with request.urlopen(req, timeout=EPSS_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (error.URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError):
        return None

    data = payload.get("data") if isinstance(payload, dict) else None
    if not data:
        return None

    raw_epss = data[0].get("epss")
    try:
        epss_value = round(float(raw_epss), 4)
    except (TypeError, ValueError):
        return None

    _EPSS_CACHE[normalized] = epss_value
    return epss_value


def _fetch_cisa_kev_from_api() -> set[str] | None:
    """
    Возвращает множество CVE из CISA KEV (Known Exploited Vulnerabilities).
    Если не удалось получить, возвращает None.
    Кеширует результат для повторных обращений.
    """
    global _CISA_KEV_CACHE
    if _CISA_KEV_CACHE is not None:
        return _CISA_KEV_CACHE

    req = request.Request(CISA_KEV_API_URL, headers={"User-Agent": "VulnGuard/1.0"})

    try:
        with request.urlopen(req, timeout=CISA_KEV_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (error.URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError):
        return None

    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not vulnerabilities or not isinstance(vulnerabilities, list):
        return None

    kev_cves = {item.get("cveID", "").strip().upper() for item in vulnerabilities if isinstance(item, dict)}
    kev_cves.discard("")  # Удалить пустые строки

    _CISA_KEV_CACHE = kev_cves
    return kev_cves


def is_cve_in_kev(cve: str) -> bool:
    """
    Проверяет, находится ли CVE в списке CISA KEV.
    """
    normalized = cve.strip().upper() if isinstance(cve, str) else ""
    if not normalized:
        return False

    kev_set = _fetch_cisa_kev_from_api()
    if kev_set is None:
        return False

    return normalized in kev_set


def enrich_vulnerability(cve: str, cvss: float) -> dict:
    """
    Обогащает уязвимость дополнительными метриками для оценки риска.
    
    В текущей версии:
    - epss запрашивается из API FIRST.org (https://api.first.org/data/v1/epss)
    - exploit_factor устанавливается на основе CISA KEV: 1.0 если в KEV, иначе 0.7
    - exposure_factor пока остаётся MVP mock-значением
    """

    # EPSS — вероятность эксплуатации в течение 30 дней (0.0–1.0)
    # Берём реальное значение через FIRST API, при ошибке используем безопасный fallback.
    epss = _fetch_epss_from_api(cve)
    if epss is None:
        epss = 0.0

    # exploit_factor — есть ли публичный рабочий эксплойт (0.0 или 0.7 или 1.0)
    # На основе CISA KEV: если CVE в списке известных эксплуатируемых, то 1.0, иначе 0.7
    exploit_factor = 1.0 if is_cve_in_kev(cve) else 0.7

    # exposure_factor — насколько хост открыт (0.0–1.0)
    # Mock: максимальная экспозиция
    exposure_factor = 1.0

    return {
        "epss": epss,
        "exploit_factor": exploit_factor,
        "exposure_factor": exposure_factor,
    }
