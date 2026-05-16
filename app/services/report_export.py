# Экспорт отчётов: CSV и стилизованный PDF (локаль kk / ru / en)

from __future__ import annotations

import csv
import io
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session, joinedload

from app.i18n import severity_label, status_label, tr
from app.models import Asset, Vulnerability
from app.services.risk import get_risk_level

_FONT_NAME = "VPExport"
_FONT_REGISTERED = False

# Цвета в духе UI
_BG_HEADER = colors.HexColor("#0a0f17")
_BG_HEADER_2 = colors.HexColor("#121a28")
_TEXT_ON_DARK = colors.HexColor("#e8eef7")
_TEXT_BODY = colors.HexColor("#0f172a")
_ROW_ALT = colors.HexColor("#eef2f7")
_GRID = colors.HexColor("#c5cedd")

_REPORT_COLUMNS = (
    "report_col_id",
    "report_col_cve",
    "report_col_asset",
    "report_col_cvss",
    "report_col_epss",
    "report_col_risk",
    "report_col_risk_level",
    "report_col_asset_crit",
    "report_col_exploit",
    "report_col_exposure",
    "report_col_severity",
    "report_col_status",
    "report_col_description",
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _ensure_unicode_font() -> str:
    global _FONT_REGISTERED
    if _FONT_REGISTERED:
        return _FONT_NAME
    root = _project_root()
    candidates = [
        root / "static" / "fonts" / "DejaVuSans.ttf",
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts" / "arial.ttf",
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts" / "segoeui.ttf",
    ]
    for path in candidates:
        if path.is_file():
            pdfmetrics.registerFont(TTFont(_FONT_NAME, str(path)))
            _FONT_REGISTERED = True
            return _FONT_NAME
    raise RuntimeError(
        "No Unicode font for PDF: add static/fonts/DejaVuSans.ttf or install a system font (Arial)."
    )


def _severity_bucket(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def _vuln_to_row(v: Vulnerability, locale: str) -> dict[str, str | int | float]:
    try:
        bucket = _severity_bucket(float(v.cvss))
    except (TypeError, ValueError):
        bucket = "Low"
    risk_level = get_risk_level(float(v.risk_score or 0))
    desc = (v.description or "").replace("\r", " ").replace("\n", " ").strip()
    return {
        "id": v.id,
        "cve": v.cve or "",
        "asset_ip": v.asset.ip if v.asset else "",
        "cvss": float(v.cvss or 0),
        "epss": float(v.epss or 0),
        "risk_score": float(v.risk_score or 0),
        "risk_level": severity_label(locale, risk_level),
        "asset_criticality": float(v.asset.criticality if v.asset else 0),
        "exploit_factor": float(v.exploit_factor or 0),
        "exposure_factor": float(v.exposure_factor or 0),
        "severity": severity_label(locale, bucket),
        "status": status_label(locale, v.status or ""),
        "description": desc[:2000],
    }


def fetch_vulnerability_rows(db: Session, locale: str) -> list[dict[str, str | int | float]]:
    rows = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.asset))
        .order_by(Vulnerability.risk_score.desc())
        .all()
    )
    return [_vuln_to_row(v, locale) for v in rows]


def build_executive_summary(db: Session, locale: str) -> dict[str, Any]:
    """Сводка для PDF: риск, статусы, SLA, топ-5."""
    vulns = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.asset))
        .all()
    )
    total = len(vulns)
    risk_counts = {"High": 0, "Medium": 0, "Low": 0}
    for v in vulns:
        level = get_risk_level(float(v.risk_score or 0))
        risk_counts[level] = risk_counts.get(level, 0) + 1

    status_keys = (
        "New",
        "In Progress",
        "Fixed",
        "Open",
        "Pending Verification",
        "Resolved",
        "Verified",
    )
    status_counts: dict[str, int] = {k: 0 for k in status_keys}
    for v in vulns:
        st = v.status or ""
        if st in status_counts:
            status_counts[st] += 1

    closed = (
        status_counts["Fixed"]
        + status_counts["Resolved"]
        + status_counts["Verified"]
    )
    sla_percent = round(closed / total * 100, 1) if total else 0.0

    top5_src = sorted(vulns, key=lambda v: float(v.risk_score or 0), reverse=True)[:5]
    top5: list[dict[str, str | float]] = []
    for v in top5_src:
        rl = get_risk_level(float(v.risk_score or 0))
        top5.append(
            {
                "cve": v.cve or "—",
                "asset_ip": v.asset.ip if v.asset else "—",
                "risk_score": float(v.risk_score or 0),
                "risk_level": severity_label(locale, rl),
            }
        )

    return {
        "risk_counts": risk_counts,
        "status_counts": status_counts,
        "sla_percent": sla_percent,
        "top5": top5,
    }


def summary_counts(db: Session, rows: list[dict]) -> dict[str, int]:
    total_v = len(rows)
    vulns = db.query(Vulnerability).all()
    crit_n = sum(1 for v in vulns if _severity_bucket(float(v.cvss or 0)) == "Critical")
    assets_n = db.query(Asset).count()
    return {"vulnerabilities": total_v, "assets": assets_n, "critical_cvss": crit_n}


def _report_header_keys() -> tuple[str, ...]:
    return _REPORT_COLUMNS


def build_csv(locale: str, rows: list[dict[str, str | int | float]]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";", quoting=csv.QUOTE_MINIMAL)
    w.writerow([tr(locale, k) for k in _report_header_keys()])
    for r in rows:
        cvss_fmt = (
            f"{r['cvss']:.1f}".replace(".", ",")
            if locale == "ru"
            else f"{r['cvss']:.1f}"
        )
        w.writerow(
            [
                r["id"],
                r["cve"],
                r["asset_ip"],
                cvss_fmt,
                f"{r['epss']:.4f}",
                f"{r['risk_score']:.4f}",
                r["risk_level"],
                f"{r['asset_criticality']:.2f}",
                f"{r['exploit_factor']:.2f}",
                f"{r['exposure_factor']:.2f}",
                r["severity"],
                r["status"],
                r["description"],
            ]
        )
    return buf.getvalue().encode("utf-8-sig")


def _pdf_esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _pdf_row_cells(
    r: dict[str, str | int | float],
    small: ParagraphStyle,
    esc,
) -> list[Paragraph]:
    desc = esc(str(r["description"])[:200])
    if len(str(r["description"])) > 200:
        desc += "…"
    return [
        Paragraph(str(r["id"]), small),
        Paragraph(esc(str(r["cve"])), small),
        Paragraph(esc(str(r["asset_ip"])), small),
        Paragraph(f"{r['cvss']:.1f}", small),
        Paragraph(f"{r['epss']:.3f}", small),
        Paragraph(f"{r['risk_score']:.3f}", small),
        Paragraph(esc(str(r["risk_level"])), small),
        Paragraph(f"{r['asset_criticality']:.2f}", small),
        Paragraph(f"{r['exploit_factor']:.2f}", small),
        Paragraph(f"{r['exposure_factor']:.2f}", small),
        Paragraph(esc(str(r["severity"])), small),
        Paragraph(esc(str(r["status"])), small),
        Paragraph(desc, small),
    ]


def _pdf_table_col_widths(w_avail: float) -> list[float]:
    fixed = (
        10, 22, 20, 11, 12, 13, 16, 12, 12, 12, 16, 18,
    )
    used = sum(fixed) * mm
    desc_w = max(20 * mm, w_avail - used)
    return [w * mm for w in fixed] + [desc_w]


def _build_executive_pdf_block(
    locale: str,
    executive: dict[str, Any],
    font: str,
    w_avail: float,
    styles,
) -> Table:
    esc = _pdf_esc
    label_st = ParagraphStyle(
        "ExecLbl",
        parent=styles["Normal"],
        fontName=font,
        fontSize=8,
        leading=10,
        textColor=_TEXT_ON_DARK,
    )
    val_st = ParagraphStyle(
        "ExecVal",
        parent=styles["Normal"],
        fontName=font,
        fontSize=8,
        leading=10,
        textColor=_TEXT_ON_DARK,
    )
    title_st = ParagraphStyle(
        "ExecTitle",
        parent=styles["Normal"],
        fontName=font,
        fontSize=10,
        leading=12,
        textColor=_TEXT_ON_DARK,
        spaceAfter=4,
    )
    hdr_st = ParagraphStyle(
        "ExecHdr",
        parent=styles["Normal"],
        fontName=font,
        fontSize=7,
        leading=8,
        textColor=_TEXT_ON_DARK,
    )
    cell_st = ParagraphStyle(
        "ExecCell",
        parent=styles["Normal"],
        fontName=font,
        fontSize=7,
        leading=8,
        textColor=_TEXT_BODY,
    )

    rc = executive["risk_counts"]
    risk_lines = "<br/>".join(
        f"{severity_label(locale, lvl)}: <b>{rc.get(lvl, 0)}</b>"
        for lvl in ("High", "Medium", "Low")
    )

    sc = executive["status_counts"]
    status_parts: list[str] = []
    for key in ("New", "In Progress", "Open", "Pending Verification", "Fixed", "Resolved", "Verified"):
        if sc.get(key, 0) > 0:
            status_parts.append(f"{status_label(locale, key)}: <b>{sc[key]}</b>")
    status_lines = "<br/>".join(status_parts) if status_parts else "—"

    sla = executive["sla_percent"]
    half = w_avail / 2 - 3 * mm

    left_col = [
        [Paragraph(f"<b>{esc(tr(locale, 'report_exec_risk'))}</b>", label_st)],
        [Paragraph(risk_lines, val_st)],
        [Paragraph(f"<b>{esc(tr(locale, 'report_exec_status'))}</b>", label_st)],
        [Paragraph(status_lines, val_st)],
    ]
    right_col = [
        [Paragraph(f"<b>{esc(tr(locale, 'report_exec_sla'))}</b>", label_st)],
        [Paragraph(f"<b>{sla:.1f}%</b> {esc(tr(locale, 'within_sla'))}", val_st)],
    ]

    top5 = executive["top5"]
    top_headers = [
        tr(locale, "report_col_cve"),
        tr(locale, "report_col_asset"),
        tr(locale, "report_col_risk"),
        tr(locale, "report_col_risk_level"),
    ]
    top_data: list[list[Paragraph]] = [
        [Paragraph(f"<b>{esc(h)}</b>", hdr_st) for h in top_headers]
    ]
    for row in top5:
        top_data.append(
            [
                Paragraph(esc(str(row["cve"])), cell_st),
                Paragraph(esc(str(row["asset_ip"])), cell_st),
                Paragraph(f"{row['risk_score']:.3f}", cell_st),
                Paragraph(esc(str(row["risk_level"])), cell_st),
            ]
        )
    top_col_w = [half * 0.28, half * 0.28, half * 0.22, half * 0.22]
    top_tbl = Table(top_data, colWidths=top_col_w)
    top_tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _BG_HEADER),
                ("TEXTCOLOR", (0, 0), (-1, 0), _TEXT_ON_DARK),
                ("TEXTCOLOR", (0, 1), (-1, -1), _TEXT_BODY),
                ("FONTNAME", (0, 0), (-1, -1), font),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.25, _GRID),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _ROW_ALT]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )

    left_tbl = Table(left_col, colWidths=[half])
    left_tbl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    right_tbl = Table(right_col, colWidths=[half])
    right_tbl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))

    upper = Table([[left_tbl, right_tbl]], colWidths=[half, half])
    upper.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )

    outer_rows = [
        [Paragraph(f"<b>{esc(tr(locale, 'report_exec_title'))}</b>", title_st)],
        [upper],
        [Paragraph(f"<b>{esc(tr(locale, 'report_exec_top5'))}</b>", label_st)],
        [top_tbl],
    ]
    outer = Table(outer_rows, colWidths=[w_avail])
    outer.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _BG_HEADER_2),
                ("TEXTCOLOR", (0, 0), (-1, -1), _TEXT_ON_DARK),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return outer


def build_pdf(
    db: Session,
    locale: str,
    rows: list[dict[str, str | int | float]],
    summary: dict[str, int],
) -> bytes:
    font = _ensure_unicode_font()
    executive = build_executive_summary(db, locale)
    buffer = io.BytesIO()
    page = landscape(A4)
    w_page, _h_page = page

    report_day = datetime.now(timezone.utc).date().isoformat()
    pdf_title = f"{tr(locale, 'report_pdf_tab_title')} — {report_day}"
    pdf_subject = tr(locale, "report_doc_title")

    doc = SimpleDocTemplate(
        buffer,
        pagesize=page,
        leftMargin=10 * mm,
        rightMargin=10 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title=pdf_title,
        author="VulnPriority",
        subject=pdf_subject,
    )

    styles = getSampleStyleSheet()
    title_st = ParagraphStyle(
        "T",
        parent=styles["Heading1"],
        fontName=font,
        fontSize=16,
        textColor=_TEXT_ON_DARK,
        spaceAfter=4,
    )
    sub_st = ParagraphStyle(
        "S",
        parent=styles["Normal"],
        fontName=font,
        fontSize=9,
        textColor=colors.HexColor("#94a3b8"),
        spaceAfter=10,
    )
    small = ParagraphStyle(
        "Sm",
        parent=styles["Normal"],
        fontName=font,
        fontSize=6.5,
        leading=7.5,
        textColor=_TEXT_BODY,
    )
    header_cell = ParagraphStyle(
        "HdrSm",
        parent=styles["Normal"],
        fontName=font,
        fontSize=6.5,
        leading=7.5,
        textColor=_TEXT_ON_DARK,
    )
    sum_st = ParagraphStyle(
        "Sum",
        parent=styles["Normal"],
        fontName=font,
        fontSize=9,
        textColor=_TEXT_ON_DARK,
        spaceAfter=8,
        spaceBefore=4,
    )

    esc = _pdf_esc
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = tr(locale, "report_doc_title")
    sub = f"{tr(locale, 'report_generated')}: {generated}"

    w_avail = w_page - 20 * mm
    header_data = [
        [Paragraph(f"<b>{esc(title)}</b>", title_st)],
        [Paragraph(sub, sub_st)],
    ]
    header_tbl = Table(header_data, colWidths=[w_avail])
    header_tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _BG_HEADER),
                ("BOX", (0, 0), (-1, -1), 0, _BG_HEADER),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )

    sum_line = (
        f"{tr(locale, 'report_summary_vulns')}: <b>{summary['vulnerabilities']}</b> &nbsp;&nbsp; "
        f"{tr(locale, 'report_summary_assets')}: <b>{summary['assets']}</b> &nbsp;&nbsp; "
        f"{tr(locale, 'report_summary_critical')}: <b>{summary['critical_cvss']}</b>"
    )
    summary_block = Table([[Paragraph(sum_line, sum_st)]], colWidths=[w_avail])
    summary_block.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _BG_HEADER_2),
                ("TEXTCOLOR", (0, 0), (-1, -1), _TEXT_ON_DARK),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    executive_block = _build_executive_pdf_block(locale, executive, font, w_avail, styles)

    headers = [tr(locale, k) for k in _report_header_keys()]
    header_row = [Paragraph(f"<b>{esc(h)}</b>", header_cell) for h in headers]
    data: list[list[Paragraph]] = [header_row]
    for r in rows:
        data.append(_pdf_row_cells(r, small, esc))

    col_w = _pdf_table_col_widths(w_avail)
    main_tbl = Table(data, colWidths=col_w, repeatRows=1)
    main_tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _BG_HEADER),
                ("TEXTCOLOR", (0, 0), (-1, 0), _TEXT_ON_DARK),
                ("TEXTCOLOR", (0, 1), (-1, -1), _TEXT_BODY),
                ("FONTNAME", (0, 0), (-1, -1), font),
                ("FONTSIZE", (0, 0), (-1, -1), 6.5),
                ("ALIGN", (0, 0), (0, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, _GRID),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _ROW_ALT]),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )

    story = [
        header_tbl,
        Spacer(1, 3 * mm),
        summary_block,
        Spacer(1, 4 * mm),
        executive_block,
        Spacer(1, 6 * mm),
        main_tbl,
    ]
    doc.build(story)
    return buffer.getvalue()
