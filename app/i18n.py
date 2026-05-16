# Локализация интерфейса: қазақша (kk), русский (ru), English (en)

from __future__ import annotations

from typing import Any

LOCALE_COOKIE = "vp_lang"
DEFAULT_LOCALE = "ru"
SUPPORTED_LOCALES = frozenset({"kk", "ru", "en"})


def normalize_locale(lang: str | None) -> str:
    if not lang:
        return DEFAULT_LOCALE
    low = lang.lower().strip()
    if low.startswith("kk"):
        return "kk"
    if low.startswith("ru"):
        return "ru"
    if low.startswith("en"):
        return "en"
    return DEFAULT_LOCALE


def get_locale_from_cookie(cookie_val: str | None) -> str:
    return normalize_locale(cookie_val)


# Плоские ключи для шаблонов: t.key
_UI: dict[str, dict[str, str]] = {
    # _base / общее
    "nav_group_overview": {"kk": "Шолу", "ru": "Обзор", "en": "Overview"},
    "nav_dashboard": {"kk": "Бақылау тақтасы", "ru": "Дашборд", "en": "Dashboard"},
    "nav_assets": {"kk": "Активтер шолуы", "ru": "Обзор активов", "en": "Asset Overview"},
    "nav_group_vm": {"kk": "Осалдық әкімшілеу", "ru": "Управление уязвимостями", "en": "Vulnerability Management"},
    "nav_vulns": {"kk": "Осалдық кестесі", "ru": "Таблица уязвимостей", "en": "Vulnerability Table"},
    "nav_remediation": {"kk": "Жою тақтасы", "ru": "Доска устранения", "en": "Remediation Board"},
    "nav_group_ops": {"kk": "Операциялар", "ru": "Операции", "en": "Operations"},
    "nav_scans": {"kk": "Сканерлеуді басқару", "ru": "Управление сканами", "en": "Scan Management"},
    "nav_upload": {"kk": "Скан жүктеу", "ru": "Загрузка скана", "en": "Scan Upload"},
    "search_placeholder": {
        "kk": "CVE, сипаттама бойынша іздеу…",
        "ru": "Поиск CVE, описание…",
        "en": "Search CVE, description…",
    },
    "chip_critical": {"kk": "Критикалық", "ru": "Критических", "en": "Critical"},
    "lang_switch": {"kk": "Тіл", "ru": "Язык", "en": "Language"},
    # index
    "title_upload": {"kk": "VulnPriority — Жүктеу", "ru": "VulnPriority — Загрузка", "en": "VulnPriority — Upload"},
    "page_upload_title": {"kk": "Скан жүктеу", "ru": "Загрузка скана", "en": "Scan Upload"},
    "page_upload_sub": {
        "kk": "JSON нәтижелерін жұмыс орнына импорттау",
        "ru": "Импорт результатов JSON в рабочую область",
        "en": "Import JSON scan results into the workspace",
    },
    "card_upload_title": {"kk": "Скан жүктеу", "ru": "Загрузить скан", "en": "Upload scan"},
    "card_upload_sub": {
        "kk": "Қолдау: қарапайым MVP JSON немесе Nessus экспорты",
        "ru": "Поддержка: простой MVP JSON или экспорт Nessus",
        "en": "Supported: simple MVP JSON or Nessus-like export",
    },
    "choose_file": {"kk": "Файл таңдау", "ru": "Выбрать файл", "en": "Choose file"},
    "upload_analyze": {"kk": "Жүктеу және талдау", "ru": "Загрузить и проанализировать", "en": "Upload & analyze"},
    "uploading": {"kk": "Жүктелуде…", "ru": "Загрузка…", "en": "Uploading…"},
    "upload_send": {"kk": "Файл жіберілуде", "ru": "Передача файла", "en": "Sending file"},
    "upload_processing": {
        "kk": "Серверде талдау…",
        "ru": "Обработка на сервере…",
        "en": "Analyzing on server…",
    },
    "upload_failed": {"kk": "Жүктеу сәтсіз", "ru": "Ошибка загрузки", "en": "Upload failed"},
    "card_formats_title": {"kk": "Күтілетін форматтар", "ru": "Ожидаемые форматы", "en": "Expected formats"},
    "card_formats_sub": {"kk": "Мысалдарды көшіруге болады", "ru": "Можно скопировать примеры", "en": "Examples you can copy"},
    "format_mvp": {"kk": "MVP", "ru": "MVP", "en": "MVP"},
    # dashboard
    "title_dashboard": {"kk": "VulnPriority — Бақылау", "ru": "VulnPriority — Дашборд", "en": "VulnPriority — Dashboard"},
    "dashboard_page_title": {"kk": "Басқару бақылау тақтасы", "ru": "Сводный дашборд", "en": "Executive Dashboard"},
    "dashboard_page_sub": {
        "kk": "Нақты уақыттағы осалдық пен тәуекел шолуы",
        "ru": "Обзор уязвимостей и рисков в реальном времени",
        "en": "Real-time vulnerability & risk overview",
    },
    "kpi_total_vulns": {"kk": "Барлық осалдықтар", "ru": "Всего уязвимостей", "en": "Total vulnerabilities"},
    "kpi_critical_cvss": {"kk": "Критикалық (CVSS ≥ 9.0)", "ru": "Критические (CVSS ≥ 9.0)", "en": "Critical (CVSS ≥ 9.0)"},
    "kpi_in_progress": {"kk": "Орындалуда", "ru": "В работе", "en": "In progress"},
    "kpi_fixed": {"kk": "Түзетілген", "ru": "Исправлено", "en": "Fixed"},
    "risk_trend_title": {"kk": "Тәуекел динамикасы", "ru": "Тренд риска", "en": "Risk Trend"},
    "risk_trend_sub": {
        "kk": "Скан бойынша орташа тәуекел (0–100)",
        "ru": "Средний риск по скану (0–100)",
        "en": "Average risk score per scan (0–100)",
    },
    "scans_count": {"kk": "скан", "ru": "сканов", "en": "scans"},
    "severity_dist_title": {"kk": "Қатаңдық бөлінісі", "ru": "Распределение по CVSS", "en": "Severity Distribution"},
    "severity_dist_sub": {"kk": "CVSS санаттары бойынша", "ru": "По корзинам CVSS", "en": "Based on CVSS buckets"},
    "total_suffix": {"kk": "барлығы", "ru": "всего", "en": "total"},
    "top_assets_title": {"kk": "Ең осал активтер", "ru": "Топ уязвимых активов", "en": "Top vulnerable assets"},
    "top_assets_sub": {"kk": "Ең жоғары тәуекел", "ru": "Наибольший риск", "en": "Highest risk items"},
    "unknown_asset": {"kk": "Белгісіз актив", "ru": "Неизвестный актив", "en": "Unknown asset"},
    "dash_empty": {
        "kk": "Тақтаны толтыру үшін скан жүктеңіз.",
        "ru": "Загрузите скан, чтобы заполнить дашборд.",
        "en": "Upload a scan to populate dashboard.",
    },
    "upload_scan_btn": {"kk": "Скан жүктеу", "ru": "Загрузить скан", "en": "Upload scan"},
    "sla_title": {"kk": "SLA сәйкестігі", "ru": "Соблюдение SLA", "en": "SLA compliance"},
    "sla_sub": {"kk": "Мерзім ішінде жою (макет)", "ru": "Устранение в срок (макет)", "en": "Remediation within deadline (mock)"},
    "compliant": {"kk": "сәйкес", "ru": "соблюдено", "en": "compliant"},
    "within_sla": {"kk": "SLA ішінде", "ru": "В пределах SLA", "en": "Within SLA"},
    "at_risk": {"kk": "Тәуекелде", "ru": "Под риском", "en": "At risk"},
    "admin_title": {"kk": "Әкімшілеу", "ru": "Администрирование", "en": "Admin"},
    "admin_sub": {"kk": "Қызмет көрсету әрекеттері", "ru": "Служебные действия", "en": "Maintenance actions"},
    "admin_warn": {
        "kk": "Бұл барлық активтер мен осалдықтарды мәңгі жояды.",
        "ru": "Это безвозвратно удалит все активы и уязвимости.",
        "en": "This will permanently delete all assets and vulnerabilities.",
    },
    "reset_db_btn": {"kk": "Қайта түсіру / дерекқорды тазалау", "ru": "Сброс / очистить БД", "en": "Reset / Clear database"},
    "confirm_reset": {
        "kk": "Дерекқорды тазалау керек пе? Барлық деректер жойылады.",
        "ru": "Очистить базу данных? Все данные будут удалены.",
        "en": "Clear the database? All data will be removed.",
    },
    "scan_label": {"kk": "Скан", "ru": "Скан", "en": "Scan"},
    "chart_avg_risk": {"kk": "Орташа тәуекел (0–100)", "ru": "Средний риск (0–100)", "en": "Avg risk (0–100)"},
    "chart_sev_critical": {"kk": "Критикалық", "ru": "Критический", "en": "Critical"},
    "chart_sev_high": {"kk": "Жоғары", "ru": "Высокий", "en": "High"},
    "chart_sev_medium": {"kk": "Орташа", "ru": "Средний", "en": "Medium"},
    "chart_sev_low": {"kk": "Төмен", "ru": "Низкий", "en": "Low"},
    # badge risk mapping (CVSS bucket shown as label)
    "bdg_critical": {"kk": "Критикалық", "ru": "Критический", "en": "Critical"},
    "bdg_high": {"kk": "Жоғары", "ru": "Высокий", "en": "High"},
    "bdg_medium": {"kk": "Орташа", "ru": "Средний", "en": "Medium"},
    "bdg_low": {"kk": "Төмен", "ru": "Низкий", "en": "Low"},
    # assets
    "title_assets": {"kk": "VulnPriority — Активтер", "ru": "VulnPriority — Активы", "en": "VulnPriority — Assets"},
    "assets_page_title": {"kk": "Активтер шолуы", "ru": "Обзор активов", "en": "Asset Overview"},
    "assets_page_sub": {
        "kk": "Бизнес маңыздылығы мен экспозиция контексті",
        "ru": "Критичность и контекст экспозиции",
        "en": "Business criticality and exposure context",
    },
    "assets_card_title": {"kk": "Активтер", "ru": "Активы", "en": "Assets"},
    "assets_card_sub": {
        "kk": "Тәуекелді қайта есептеу үшін критикалықты өзгертіңіз",
        "ru": "Измените критичность для пересчёта риска",
        "en": "Adjust criticality to recalculate risk",
    },
    "th_id": {"kk": "ID", "ru": "ID", "en": "ID"},
    "th_asset": {"kk": "Актив", "ru": "Актив", "en": "Asset"},
    "th_criticality": {"kk": "Критикалықтық", "ru": "Критичность", "en": "Criticality"},
    "th_vulns": {"kk": "Осалдық", "ru": "Уязвимости", "en": "Vulns"},
    "th_update": {"kk": "Жаңарту", "ru": "Обновить", "en": "Update"},
    "crit_level_crit": {"kk": "Критикалық", "ru": "Критический", "en": "Critical"},
    "crit_level_high": {"kk": "Жоғары", "ru": "Высокий", "en": "High"},
    "crit_level_med": {"kk": "Орташа", "ru": "Средний", "en": "Medium"},
    "apply": {"kk": "Қолдану", "ru": "Применить", "en": "Apply"},
    "no_assets_title": {"kk": "Активтер жоқ", "ru": "Активы не найдены", "en": "No assets found"},
    "no_assets_sub": {
        "kk": "Активтерді автоматты түрде жасау үшін скан жүктеңіз.",
        "ru": "Загрузите скан для автоматического создания активов.",
        "en": "Upload a scan to create assets automatically.",
    },
    # vulnerabilities
    "title_vulns": {"kk": "VulnPriority — Осалдықтар", "ru": "VulnPriority — Уязвимости", "en": "VulnPriority — Vulnerabilities"},
    "vulns_page_title": {"kk": "Осалдық әкімшілеу", "ru": "Управление уязвимостями", "en": "Vulnerability Management"},
    "vulns_page_sub": {"kk": "Скан → Бағалау → Жою", "ru": "Скан → Оценка → Устранение", "en": "Scan → Assess → Remediate"},
    "kpi_total": {"kk": "Барлығы", "ru": "Всего", "en": "Total"},
    "kpi_high_risk": {"kk": "Жоғары тәуекел", "ru": "Высокий риск", "en": "High risk"},
    "vuln_table_title": {"kk": "Осалдық кестесі", "ru": "Таблица уязвимостей", "en": "Vulnerability table"},
    "vuln_table_sub": {"kk": "Тәуекел көрсеткіші бойынша (азайған)", "ru": "Сортировка по risk score (убыв.)", "en": "Sorted by risk score (desc)"},
    "ph_search_cve": {"kk": "CVE / сипаттама…", "ru": "CVE / описание…", "en": "Search CVE/description…"},
    "ph_asset_ip": {"kk": "Актив IP…", "ru": "IP актива…", "en": "Asset IP…"},
    "filter_severity_all": {"kk": "Қатаңдық: барлығы", "ru": "Критичность: все", "en": "Severity: All"},
    "filter_status_all": {"kk": "Күй: барлығы", "ru": "Статус: все", "en": "Status: All"},
    "rescan": {"kk": "Қайта скан", "ru": "Повторный скан", "en": "Rescan"},
    "th_cve": {"kk": "CVE ID", "ru": "CVE ID", "en": "CVE ID"},
    "th_cvss": {"kk": "CVSS", "ru": "CVSS", "en": "CVSS"},
    "th_epss": {"kk": "EPSS", "ru": "EPSS", "en": "EPSS"},
    "th_risk": {"kk": "Тәуекел", "ru": "Риск", "en": "Risk"},
    "th_severity": {"kk": "Қатаңдық", "ru": "Критичность", "en": "Severity"},
    "th_status": {"kk": "Күй", "ru": "Статус", "en": "Status"},
    "th_sla_due": {"kk": "SLA мерзімі", "ru": "Срок SLA", "en": "SLA due"},
    "th_update_col": {"kk": "Жаңарту", "ru": "Обновить", "en": "Update"},
    "overdue": {"kk": "Мерзімі өткен", "ru": "Просрочено", "en": "Overdue"},
    "save": {"kk": "Сақтау", "ru": "Сохранить", "en": "Save"},
    "pager_showing": {"kk": "Көрсетілуде", "ru": "Показано", "en": "Showing"},
    "pager_of": {"kk": "ішінен", "ru": "из", "en": "of"},
    "pager_per_column": {"kk": "баған бойынша", "ru": "на колонку", "en": "per column"},
    "pager_total_label": {"kk": "Барлығы", "ru": "Всего", "en": "Total"},
    "per_page": {"kk": "Бетіне", "ru": "На странице", "en": "Per page"},
    "no_data_title": {"kk": "Дерек жоқ", "ru": "Нет данных", "en": "No data yet"},
    "no_data_sub": {
        "kk": "Кестені толтыру үшін скан JSON жүктеңіз.",
        "ru": "Загрузите JSON скана, чтобы заполнить таблицу.",
        "en": "Upload a scan JSON to populate the table.",
    },
    # remediation
    "title_remediation": {"kk": "VulnPriority — Жою тақтасы", "ru": "VulnPriority — Доска", "en": "VulnPriority — Remediation Board"},
    "rem_page_title": {"kk": "Жою тақтасы", "ru": "Доска устранения", "en": "Remediation Board"},
    "rem_page_sub": {
        "kk": "Скан → Бағалау → Жою бойынша ілгерлеу",
        "ru": "Прогресс по цепочке Скан → Оценка → Устранение",
        "en": "Track progress across Scan → Assess → Remediate",
    },
    "rem_card_title": {"kk": "Жою тақтасы", "ru": "Доска устранения", "en": "Remediation board"},
    "rem_card_sub": {
        "kk": "Карталарды сүйреп күйді өзгертіңіз · тәуекел бойынша сұрыпталған",
        "ru": "Перетащите карточки для смены статуса · сортировка по риску",
        "en": "Drag cards to update status · Sorted by risk",
    },
    "open_table": {"kk": "Кестені ашу", "ru": "Открыть таблицу", "en": "Open table"},
    "kanban_empty_title": {"kk": "Карталар жоқ", "ru": "Нет карточек", "en": "No cards"},
    "kanban_empty_sub": {
        "kk": "Осалдықты осы жерге сүйреңіз",
        "ru": "Перетащите уязвимость сюда",
        "en": "Drag a vulnerability here",
    },
    "pager_rem_footer": {"kk": "баған бойынша · барлығы", "ru": "на колонку · всего", "en": "per column · Total"},
    # scans
    "title_scans": {"kk": "VulnPriority — Скан тарихы", "ru": "VulnPriority — История сканов", "en": "VulnPriority — Scan history"},
    "scans_page_title": {"kk": "Скан тарихы", "ru": "История сканов", "en": "Scan History"},
    "scans_page_sub": {
        "kk": "Скан арасындағы өзгерістерді бақылау",
        "ru": "Отслеживание изменений между сканами",
        "en": "Track changes between scans (Scan → Assess → Remediate)",
    },
    "kpi_total_scans": {"kk": "Барлық скан", "ru": "Всего сканов", "en": "Total scans"},
    "kpi_last_upload": {"kk": "Соңғы жүктеу", "ru": "Последняя загрузка", "en": "Last upload"},
    "scans_card_title": {"kk": "Сканерлеуді басқару", "ru": "Управление сканами", "en": "Scan Management"},
    "scans_card_sub": {
        "kk": "Әр жүктеу дельта талдауы үшін сүрінті жасайды",
        "ru": "Каждая загрузка создаёт снимок для дельта-анализа",
        "en": "Each upload creates a snapshot for delta analysis",
    },
    "th_time": {"kk": "Уақыт", "ru": "Время", "en": "Time"},
    "th_source": {"kk": "Файл көзі", "ru": "Исходный файл", "en": "Source file"},
    "th_hosts": {"kk": "Хосттар", "ru": "Хосты", "en": "Hosts"},
    "th_open": {"kk": "Ашу", "ru": "Открыть", "en": "Open"},
    "view": {"kk": "Қарау", "ru": "Просмотр", "en": "View"},
    "no_scans_title": {"kk": "Скан жоқ", "ru": "Сканов пока нет", "en": "No scans yet"},
    "no_scans_sub": {
        "kk": "Алғашқы сүрінті үшін JSON скан жүктеңіз.",
        "ru": "Загрузите JSON скана, чтобы создать первый снимок.",
        "en": "Upload a scan JSON to create the first snapshot.",
    },
    # asset detail
    "title_asset_detail": {"kk": "VulnPriority — Актив", "ru": "VulnPriority — Актив", "en": "VulnPriority — Asset"},
    "asset_page_title": {"kk": "Активтер шолуы", "ru": "Обзор активов", "en": "Asset Overview"},
    "asset_page_sub_suffix": {"kk": "тәуекел және жою контексті", "ru": "риск и контекст устранения", "en": "risk & remediation context"},
    "back_assets": {"kk": "← Активтерге", "ru": "← К активам", "en": "← Back to assets"},
    "open_vulns_link": {"kk": "Осалдықтарды ашу", "ru": "Открыть уязвимости", "en": "Open vulnerabilities"},
    "kpi_asset": {"kk": "Актив", "ru": "Актив", "en": "Asset"},
    "kpi_criticality": {"kk": "Критикалықтық", "ru": "Критичность", "en": "Criticality"},
    "kpi_open_vulns": {"kk": "Ашық осалдық", "ru": "Открытые уязвимости", "en": "Open vulns"},
    "hist_trend_title": {"kk": "Тарихи осалдық динамикасы", "ru": "Исторический тренд уязвимостей", "en": "Historical Vulnerability Trend"},
    "patch_title": {"kk": "Жамау сәйкестігі", "ru": "Соответствие патчам", "en": "Patch Compliance"},
    "patch_sub": {"kk": "Mock KPI (кейінірек)", "ru": "Mock KPI (позже)", "en": "Mock KPI (upgrade later)"},
    "within_sla_ring": {"kk": "SLA ішінде", "ru": "в пределах SLA", "en": "within SLA"},
    "compliant_bar": {"kk": "Сәйкес", "ru": "Соответствует", "en": "Compliant"},
    "open_vulns_section": {"kk": "Ашық осалдықтар", "ru": "Открытые уязвимости", "en": "Open Vulnerabilities"},
    "open_vulns_sub": {"kk": "Тәуекел көрсеткіші бойынша", "ru": "Сортировка по risk score", "en": "Sorted by risk score"},
    "th_open_col": {"kk": "Ашу", "ru": "Открыть", "en": "Open"},
    "details": {"kk": "Толығырақ", "ru": "Детали", "en": "Details"},
    "no_asset_records": {"kk": "Бұл актив үшін жазбалар жоқ.", "ru": "Нет записей по этому активу.", "en": "No records for this asset."},
    # scan detail
    "title_scan_detail": {"kk": "VulnPriority — Скан", "ru": "VulnPriority — Скан", "en": "VulnPriority — Scan"},
    "scan_snapshot_sub": {"kk": "Сүрінті және алдыңғы сканға дельта", "ru": "Снимок и дельта к предыдущему скану", "en": "Snapshot & delta vs previous scan"},
    "back_scans": {"kk": "← Скан тарихына", "ru": "← К истории сканов", "en": "← Back to scan history"},
    "open_vuln_table": {"kk": "Осалдық кестесін ашу", "ru": "Открыть таблицу уязвимостей", "en": "Open vulnerability table"},
    "kpi_scan_time": {"kk": "Скан уақыты", "ru": "Время скана", "en": "Scan time"},
    "kpi_vulnerabilities": {"kk": "Осалдықтар", "ru": "Уязвимости", "en": "Vulnerabilities"},
    "delta_title": {"kk": "Дельта (Скан → Бағалау)", "ru": "Дельта (Скан → Оценка)", "en": "Delta (Scan → Assess)"},
    "delta_vs": {
        "kk": "Алдыңғы сканмен салыстырғанда",
        "ru": "По сравнению со сканом",
        "en": "Compared to scan",
    },
    "no_prev_scan": {"kk": "Алдыңғы скан әлі жоқ", "ru": "Предыдущий скан не найден", "en": "No previous scan found yet"},
    "badge_new": {"kk": "Жаңа", "ru": "Новые", "en": "New"},
    "badge_resolved": {"kk": "Шешілген", "ru": "Устранено", "en": "Resolved"},
    "th_current": {"kk": "Ағымдағы", "ru": "Текущее", "en": "Current"},
    "th_previous": {"kk": "Алдыңғы", "ru": "Предыдущее", "en": "Previous"},
    "th_new_cve": {"kk": "Жаңа CVE", "ru": "Новые CVE", "en": "New CVE"},
    "th_resolved_cve": {"kk": "Шешілген CVE", "ru": "Устранённые CVE", "en": "Resolved CVE"},
    "more_count": {"kk": "тағы", "ru": "ещё", "en": "more"},
    "delta_need_two": {
        "kk": "Дельтаны көру үшін кемінде екі скан жүктеңіз.",
        "ru": "Загрузите минимум два скана, чтобы увидеть дельту.",
        "en": "Upload at least two scans to see delta.",
    },
    "snapshot_title": {"kk": "Сүрінті мазмұны (Скан)", "ru": "Содержимое снимка (Скан)", "en": "Snapshot contents (Scan)"},
    "snapshot_sub": {"kk": "Осы сканға қабылданған осалдықтар", "ru": "Уязвимости, загруженные в этом скане", "en": "Vulnerabilities ingested in this scan"},
    "no_vuln_scan": {
        "kk": "Бұл сканға осалдық тіркелмеген.",
        "ru": "К этому скану уязвимости не привязаны.",
        "en": "No vulnerabilities attached to this scan.",
    },
    # vulnerability detail
    "title_vuln_detail": {"kk": "VulnPriority — Осалдық", "ru": "VulnPriority — Уязвимость", "en": "VulnPriority — Vulnerability"},
    "vuln_detail_sub": {
        "kk": "Толық осалдық ақпараты",
        "ru": "Развёрнутые сведения об уязвимости",
        "en": "Expanded vulnerability details",
    },
    "back_table": {"kk": "← Кестеге", "ru": "← К таблице", "en": "← Back to table"},
    "summary_title": {"kk": "Қорытынды", "ru": "Сводка", "en": "Summary"},
    "summary_sub": {
        "kk": "Басымды таңдау үшін негізгі метрикалар",
        "ru": "Ключевые метрики приоритизации",
        "en": "Core metrics used by prioritization",
    },
    "kpi_risk_score": {"kk": "Тәуекел көрсеткіші", "ru": "Risk score", "en": "Risk score"},
    "kpi_exploit": {"kk": "Эксплуатация факторы", "ru": "Фактор эксплуатации", "en": "Exploit factor"},
    "kpi_exposure": {"kk": "Экспозиция факторы", "ru": "Фактор экспозиции", "en": "Exposure factor"},
    "kpi_asset_crit": {"kk": "Актив критикалықтығы", "ru": "Критичность актива", "en": "Asset criticality"},
    "desc_title": {"kk": "Сипаттама", "ru": "Описание", "en": "Description"},
    "desc_sub": {"kk": "Не және не үшін маңызды", "ru": "Что это и почему важно", "en": "What it is and why it matters"},
    "mini_update_status": {"kk": "Күйді жаңарту", "ru": "Обновить статус", "en": "Update status"},
    # Экспорт отчётов (CSV / PDF)
    "export_menu_aria": {"kk": "Есепті жүктеу", "ru": "Экспорт отчёта", "en": "Export report"},
    "export_reports": {"kk": "Есеп", "ru": "Отчёт", "en": "Report"},
    "export_csv": {"kk": "CSV", "ru": "CSV", "en": "CSV"},
    "export_pdf": {"kk": "PDF", "ru": "PDF", "en": "PDF"},
    "export_pdf_kk": {"kk": "PDF KK", "ru": "PDF KK", "en": "PDF KK"},
    "export_pdf_ru": {"kk": "PDF RU", "ru": "PDF RU", "en": "PDF RU"},
    "export_pdf_en": {"kk": "PDF EN", "ru": "PDF EN", "en": "PDF EN"},
    "report_pdf_tab_title": {"kk": "Есеп", "ru": "Отчёт", "en": "Report"},
    "report_doc_title": {
        "kk": "VulnPriority — осалдықтар есебі",
        "ru": "VulnPriority — отчёт по уязвимостям",
        "en": "VulnPriority — vulnerability report",
    },
    "report_no_trend": {
        "kk": "Тренд үшін скан деректері жоқ.",
        "ru": "Нет данных сканов для построения тренда.",
        "en": "No scan data to plot risk trend.",
    },
    "report_no_severity": {
        "kk": "Қатаңдық бөлінісі үшін дерек жоқ.",
        "ru": "Нет данных для распределения по CVSS.",
        "en": "No data for CVSS distribution.",
    },
    "report_generated": {"kk": "Құрылды", "ru": "Сформирован", "en": "Generated"},
    "report_summary_vulns": {"kk": "Жазбалар", "ru": "Записей", "en": "Records"},
    "report_summary_assets": {"kk": "Активтер", "ru": "Активов", "en": "Assets"},
    "report_summary_critical": {"kk": "CVSS критикалық", "ru": "Критичных по CVSS", "en": "Critical (CVSS)"},
    "report_col_id": {"kk": "ID", "ru": "ID", "en": "ID"},
    "report_col_cve": {"kk": "CVE", "ru": "CVE", "en": "CVE"},
    "report_col_asset": {"kk": "Актив (IP)", "ru": "Актив (IP)", "en": "Asset (IP)"},
    "report_col_cvss": {"kk": "CVSS", "ru": "CVSS", "en": "CVSS"},
    "report_col_epss": {"kk": "EPSS", "ru": "EPSS", "en": "EPSS"},
    "report_col_risk": {"kk": "Тәуекел", "ru": "Риск", "en": "Risk"},
    "report_col_risk_level": {
        "kk": "Тәуекел деңгейі",
        "ru": "Уровень риска",
        "en": "Risk level",
    },
    "report_col_asset_crit": {
        "kk": "Актив крит.",
        "ru": "Крит. актива",
        "en": "Asset crit.",
    },
    "report_col_exploit": {"kk": "Эксплуатация", "ru": "Эксплойт", "en": "Exploit"},
    "report_col_exposure": {"kk": "Экспозиция", "ru": "Экспозиция", "en": "Exposure"},
    "report_col_severity": {"kk": "Қатаңдық", "ru": "Критичность", "en": "Severity"},
    "report_col_status": {"kk": "Күй", "ru": "Статус", "en": "Status"},
    "report_col_description": {"kk": "Сипаттама", "ru": "Описание", "en": "Description"},
    "report_exec_title": {"kk": "Қорытынды", "ru": "Сводка", "en": "Executive summary"},
    "report_exec_risk": {
        "kk": "Тәуекел деңгейі бойынша",
        "ru": "По уровню риска (формула)",
        "en": "By risk level (formula)",
    },
    "report_exec_status": {"kk": "Күйлер", "ru": "Статусы", "en": "Statuses"},
    "report_exec_sla": {"kk": "SLA сәйкестігі", "ru": "Соблюдение SLA", "en": "SLA compliance"},
    "report_exec_top5": {
        "kk": "Топ-5 — жедел назар",
        "ru": "Топ-5 — срочно",
        "en": "Top 5 — urgent",
    },
}

STATUS_LABELS: dict[str, dict[str, str]] = {
    "Open": {"kk": "Ашық", "ru": "Открыто", "en": "Open"},
    "In Progress": {"kk": "Орындалуда", "ru": "В работе", "en": "In Progress"},
    "Pending Verification": {"kk": "Растау күтілуде", "ru": "Ожидает проверки", "en": "Pending Verification"},
    "Resolved": {"kk": "Шешілді", "ru": "Устранено", "en": "Resolved"},
    "Verified": {"kk": "Расталды", "ru": "Проверено", "en": "Verified"},
    "New": {"kk": "Жаңа", "ru": "Новая", "en": "New"},
    "Fixed": {"kk": "Түзетілді", "ru": "Исправлено", "en": "Fixed"},
}

SEVERITY_LABELS: dict[str, dict[str, str]] = {
    "Critical": {"kk": "Критикалық", "ru": "Критический", "en": "Critical"},
    "High": {"kk": "Жоғары", "ru": "Высокий", "en": "High"},
    "Medium": {"kk": "Орташа", "ru": "Средний", "en": "Medium"},
    "Low": {"kk": "Төмен", "ru": "Низкий", "en": "Low"},
}


def tr(locale: str, key: str) -> str:
    loc = normalize_locale(locale)
    row = _UI.get(key)
    if not row:
        return key
    return row.get(loc) or row.get("en") or key


def t_bundle(locale: str) -> dict[str, str]:
    loc = normalize_locale(locale)
    return {k: v.get(loc) or v.get("en") or k for k, v in _UI.items()}


def status_label(locale: str, status: str) -> str:
    loc = normalize_locale(locale)
    row = STATUS_LABELS.get(status)
    if not row:
        return status
    return row.get(loc) or row.get("en") or status


def severity_label(locale: str, sev: str) -> str:
    loc = normalize_locale(locale)
    row = SEVERITY_LABELS.get(sev)
    if not row:
        return sev
    return row.get(loc) or row.get("en") or sev


def risk_badge_label(locale: str, risk_level: str) -> str:
    """risk_level from get_risk_level: High/Medium/Low → UI Critical/High/Medium"""
    mapping = {"High": "bdg_critical", "Medium": "bdg_high", "Low": "bdg_medium"}
    key = mapping.get(risk_level or "", "bdg_low")
    return tr(locale, key)


def criticality_badge(locale: str, level: str) -> str:
    """Critical / High / Medium for asset criticality badges"""
    mp = {"Critical": "crit_level_crit", "High": "crit_level_high", "Medium": "crit_level_med"}
    key = mp.get(level, "crit_level_med")
    return tr(locale, key)
