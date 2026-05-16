# parser.py — парсинг JSON файла скана

import json
from typing import Any

from app.schemas import ScanInput


def _parse_simple_format(raw: dict[str, Any]) -> list[ScanInput]:
    # Формат MVP:
    # { "host": "...", "vulnerabilities": [ {"cve": "...", "cvss": 9.8, "description": "..."} ] }
    return [ScanInput(**raw)]


def _parse_custom_vms_generator_format(raw: dict[str, Any]) -> list[ScanInput]:
    # Пример формата:
    # {
    #   "scan_info": {"target": "192.168.1.105", ...},
    #   "vulnerabilities": [
    #     {"cve_id":"CVE-2026-4756","cvss_score":6.1,"title":"...","description":"..."}
    #   ]
    # }
    scan_info = raw.get("scan_info")
    if not isinstance(scan_info, dict):
        return []

    host = scan_info.get("target") or scan_info.get("host") or scan_info.get("ip")
    if not host:
        return []

    vulns_raw = raw.get("vulnerabilities", [])
    if not isinstance(vulns_raw, list):
        return []

    vulns: list[dict[str, Any]] = []
    for v in vulns_raw:
        if not isinstance(v, dict):
            continue

        cve = v.get("cve") or v.get("cve_id") or v.get("cveId")
        cvss = (
            v.get("cvss")
            if "cvss" in v
            else (v.get("cvss_score") if "cvss_score" in v else v.get("cvssScore"))
        )
        description = v.get("description") or v.get("title") or ""

        if not cve or cvss is None:
            continue

        try:
            cvss_f = float(cvss)
        except (TypeError, ValueError):
            continue

        vulns.append({"cve": str(cve), "cvss": cvss_f, "description": str(description)})

    if not vulns:
        return []

    return [ScanInput(host=str(host), vulnerabilities=vulns)]


def _parse_nessus_like_format(raw: dict[str, Any]) -> list[ScanInput]:
    # Пример формата:
    # { "hosts": [ { "ip": "...", "vulnerabilities": [ { "cve": "...", "cvss_base_score": 9.3, ... } ] } ] }
    hosts = raw.get("hosts")
    if not isinstance(hosts, list):
        return []

    scans: list[ScanInput] = []
    for h in hosts:
        if not isinstance(h, dict):
            continue
        host_ip = h.get("ip") or h.get("hostname")
        if not host_ip:
            continue

        vulns_raw = h.get("vulnerabilities", [])
        if not isinstance(vulns_raw, list):
            vulns_raw = []

        vulns: list[dict[str, Any]] = []
        for v in vulns_raw:
            if not isinstance(v, dict):
                continue
            cve = v.get("cve")
            cvss = v.get("cvss") if "cvss" in v else v.get("cvss_base_score")
            description = v.get("description") or v.get("plugin_name") or ""

            if not cve or cvss is None:
                continue

            try:
                cvss_f = float(cvss)
            except (TypeError, ValueError):
                continue

            vulns.append({"cve": str(cve), "cvss": cvss_f, "description": str(description)})

        scans.append(ScanInput(host=str(host_ip), vulnerabilities=vulns))

    return scans


def _parse_payload(raw: Any) -> list[ScanInput]:
    if isinstance(raw, dict):
        # Формат MVP
        if "host" in raw and "vulnerabilities" in raw:
            return _parse_simple_format(raw)

        # Custom-VMS-Generator
        if "scan_info" in raw and "vulnerabilities" in raw:
            scans = _parse_custom_vms_generator_format(raw)
            if scans:
                return scans

        # Nessus-like
        if "hosts" in raw:
            scans = _parse_nessus_like_format(raw)
            if scans:
                return scans

        return []

    if isinstance(raw, list):
        scans: list[ScanInput] = []
        for item in raw:
            scans.extend(_parse_payload(item))
        return scans

    return []


def _decode_multiple_json_values(text: str) -> list[Any]:
    decoder = json.JSONDecoder()
    values: list[Any] = []
    idx = 0
    length = len(text)

    while idx < length:
        while idx < length and text[idx].isspace():
            idx += 1
        if idx >= length:
            break

        value, end = decoder.raw_decode(text, idx)
        values.append(value)
        idx = end

    return values


def _decode_json_lines(text: str) -> list[Any]:
    values: list[Any] = []
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        # Пропускаем строки, которые явно не похожи на JSON.
        if candidate[0] not in "{[":
            continue
        try:
            values.append(json.loads(candidate))
        except json.JSONDecodeError:
            continue
    return values


def parse_scan_file(filepath: str) -> list[ScanInput]:
    """
    Читает JSON файл со скана и возвращает список ScanInput (по хостам).
    
    Поддерживаемые форматы:
    1) MVP:
    {
        "host": "192.168.1.10",
        "vulnerabilities": [
            {"cve": "CVE-XXXX", "cvss": 9.8, "description": "..."}
        ]
    }
    2) Nessus-like (упрощённый экспорт):
    { "hosts": [ { "ip": "...", "vulnerabilities": [ { "cve": "...", "cvss_base_score": 9.3, ... } ] } ] }
    """
    with open(filepath, "r", encoding="utf-8") as f:
        text = f.read()

    if not text.strip():
        raise ValueError("Файл скана пустой.")

    payloads: list[Any]
    try:
        payloads = [json.loads(text)]
    except json.JSONDecodeError:
        # Поддержка JSONL/NDJSON и файлов, где JSON-объекты идут подряд.
        try:
            payloads = _decode_multiple_json_values(text)
        except json.JSONDecodeError as exc:
            # Доп. fallback: построчный режим для "грязного" JSONL.
            payloads = _decode_json_lines(text)
            if not payloads:
                raise ValueError(f"Некорректный JSON: {exc.msg} (строка {exc.lineno}, колонка {exc.colno}).") from exc

    scans: list[ScanInput] = []
    for payload in payloads:
        scans.extend(_parse_payload(payload))
    if scans:
        return scans

    raise ValueError(
        "Неподдерживаемый формат JSON. Ожидается {host, vulnerabilities}, "
        "{hosts:[...]} (Nessus-like), массив таких объектов или JSONL/NDJSON."
    )
