"""JSON report output."""

from __future__ import annotations

import os
from pathlib import Path

from vitia_invenire.models import AssessmentReport


def generate(report: AssessmentReport, output_dir: str) -> str:
    """Serialize the report to a JSON file.

    Args:
        report: The assessment report to serialize.
        output_dir: Directory to write the report file.

    Returns:
        Path to the generated JSON file.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = report.scan_start.strftime("%Y%m%d_%H%M%S")
    filename = f"{report.hostname}_{timestamp}.json"
    filepath = Path(output_dir) / filename

    json_str = report.model_dump_json(indent=2)
    filepath.write_text(json_str, encoding="utf-8")

    return str(filepath)
