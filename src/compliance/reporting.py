"""Standardized incident reports and their dispatch adapters.

The report keeps the roadmap's four record classes in separate sections so a
reader can never mistake a model inference for an observed fact, or an action
taken for a human decision.

Safety boundary: no adapter in this module performs network I/O. The simulator
demonstrates the reporting *structure* without sending anything to a real
authority; a future regulatory adapter must be added deliberately, with its own
approval path, and must not default to enabled.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .contracts import LAYER_NAMES, IncidentTimeline, RecordClass

CLASS_TITLES = {
    RecordClass.OBSERVED_FACT.value: "Observed facts",
    RecordClass.MODEL_INFERENCE.value: "Model inferences",
    RecordClass.HUMAN_DECISION.value: "Human decisions",
    RecordClass.ACTION_TAKEN.value: "Actions taken",
}

CLASS_CAVEATS = {
    RecordClass.OBSERVED_FACT.value: "Recorded observations. Not interpreted.",
    RecordClass.MODEL_INFERENCE.value: "Machine inference with a confidence score. Not confirmed fact.",
    RecordClass.HUMAN_DECISION.value: "Decisions made by a named reviewer under a time-bound approval.",
    RecordClass.ACTION_TAKEN.value: "Controls applied, verified, expired or rolled back.",
}


@dataclass
class IncidentReport:
    report_id: str
    case_id: str
    scenario_id: Optional[str]
    title: str
    generated_at: str
    view: str
    summary: Dict[str, Any]
    sections: Dict[str, List[Dict[str, Any]]]
    integrity: Dict[str, Any]
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_report(
    timeline: IncidentTimeline,
    metrics: Optional[Dict[str, Any]] = None,
) -> IncidentReport:
    sections: Dict[str, List[Dict[str, Any]]] = {key: [] for key in CLASS_TITLES}
    for entry in timeline.entries:
        sections.setdefault(entry.record_class, []).append(entry.to_dict())

    first = timeline.entries[0].timestamp if timeline.entries else None
    last = timeline.entries[-1].timestamp if timeline.entries else None

    return IncidentReport(
        report_id=f"RPT-{timeline.case_id}",
        case_id=timeline.case_id,
        scenario_id=timeline.scenario_id,
        title=f"ACCDS incident report for case {timeline.case_id}",
        generated_at=datetime.now(timezone.utc).isoformat(),
        view=timeline.view,
        summary={
            "scenario_id": timeline.scenario_id,
            "records": len(timeline.entries),
            "first_record": first,
            "last_record": last,
            "layer_coverage": timeline.layer_coverage,
            "records_by_class": {key: len(value) for key, value in sections.items()},
        },
        sections=sections,
        integrity=timeline.chain_verification,
        metrics=metrics or {},
    )


def render_markdown(report: IncidentReport) -> str:
    lines: List[str] = [
        f"# {report.title}",
        "",
        f"- **Report ID:** {report.report_id}",
        f"- **Case ID:** {report.case_id}",
        f"- **Scenario:** {report.scenario_id or 'n/a'}",
        f"- **Generated:** {report.generated_at}",
        f"- **View:** `{report.view}`"
        + ("  (identifiers are pseudonymized)" if report.view == "operational" else "  (full fidelity)"),
        "",
        "## Integrity",
        "",
    ]
    integrity = report.integrity or {}
    status = "VERIFIED" if integrity.get("ok") else "FAILED"
    lines += [
        f"Audit chain: **{status}** - {integrity.get('records_checked', 0)} records checked, "
        f"{integrity.get('reason', 'no verification recorded')}.",
        "",
        f"Head hash: `{integrity.get('head_hash', 'n/a')}`",
        "",
        "## Summary",
        "",
        f"{report.summary['records']} audit records span "
        f"{report.summary['first_record']} to {report.summary['last_record']}.",
        "",
        "| Layer | Records |",
        "|---|---:|",
    ]
    for key in sorted(report.summary["layer_coverage"]):
        number = int(key.rsplit("_", 1)[-1])
        lines.append(f"| {number} {LAYER_NAMES.get(number, '')} | {report.summary['layer_coverage'][key]} |")

    for class_key, title in CLASS_TITLES.items():
        entries = report.sections.get(class_key, [])
        lines += ["", f"## {title}", "", f"_{CLASS_CAVEATS[class_key]}_", ""]
        if not entries:
            lines.append("None recorded.")
            continue
        lines += ["| Time | Layer | Actor | Outcome | Detail |", "|---|---|---|---|---|"]
        for entry in entries:
            detail = str(entry["summary"]).replace("|", "\\|")
            lines.append(
                f"| {entry['timestamp']} | {entry['layer']} | {entry['actor']} | "
                f"{entry['outcome']} | {detail} |"
            )

    privacy = (report.metrics or {}).get("privacy", {})
    if privacy:
        leak = privacy.get("leak_scan", {})
        lines += [
            "",
            "## Privacy controls",
            "",
            f"- Sensitive field instances handled: {privacy.get('sensitive_instances_handled', 0)}",
            f"- Fields pseudonymized: {privacy.get('fields_pseudonymized', 0)}",
            f"- Fields dropped: {privacy.get('fields_dropped', 0)}",
            f"- Free-text substitutions: {privacy.get('free_text_substitutions', 0)}",
            f"- Leak scan: {'clean' if leak.get('clean') else 'LEAKS FOUND: ' + ', '.join(leak.get('leaked_terms', []))}",
        ]

    lines += [
        "",
        "---",
        "",
        "Generated by ACCDS Layer 6 (Compliance & Privacy). This report is produced "
        "inside a hospital digital twin and was not transmitted to any external authority.",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Dispatch adapters - configurable, and deliberately all local
# --------------------------------------------------------------------------
class ReportAdapter:
    name = "base"
    performs_network_io = False

    def dispatch(self, report: IncidentReport, markdown: str) -> Dict[str, Any]:
        raise NotImplementedError


class NullReportAdapter(ReportAdapter):
    """Accepts the report and discards it. The default for demonstrations."""

    name = "null"

    def dispatch(self, report: IncidentReport, markdown: str) -> Dict[str, Any]:
        return {"adapter": self.name, "delivered": False, "bytes": len(markdown)}


class StdoutReportAdapter(ReportAdapter):
    name = "stdout"

    def dispatch(self, report: IncidentReport, markdown: str) -> Dict[str, Any]:
        print(markdown)
        return {"adapter": self.name, "delivered": True, "bytes": len(markdown)}


class FileReportAdapter(ReportAdapter):
    """Writes the report to disk as Markdown and JSON."""

    name = "file"

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.written: List[Path] = []

    def dispatch(self, report: IncidentReport, markdown: str) -> Dict[str, Any]:
        md_path = self.output_dir / f"{report.report_id}.md"
        json_path = self.output_dir / f"{report.report_id}.json"
        md_path.write_text(markdown, encoding="utf-8")
        json_path.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
        self.written = [md_path, json_path]
        return {
            "adapter": self.name,
            "delivered": True,
            "files": [str(md_path), str(json_path)],
        }


ADAPTERS: Dict[str, Any] = {
    "null": NullReportAdapter,
    "stdout": StdoutReportAdapter,
    "file": FileReportAdapter,
}


def get_adapter(name: str, **kwargs: Any) -> ReportAdapter:
    try:
        factory = ADAPTERS[name]
    except KeyError as error:
        raise ValueError(
            f"unknown report adapter '{name}'. Available: {', '.join(sorted(ADAPTERS))}. "
            "No network adapter ships with this package by design."
        ) from error
    return factory(**kwargs) if kwargs else factory()
