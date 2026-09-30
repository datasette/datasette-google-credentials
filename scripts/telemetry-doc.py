#!/usr/bin/env python3
"""Render README.md's OpenTelemetry reference from the telemetry registry.

Rewrites the block between the telemetry-reference markers so the docs
cannot drift from the code; `--check` exits non-zero if the file would
change (run in CI). The registry entries carry
everything this needs (descriptions are Markdown), so this is a small
renderer, not a copy of core's cog-into-RST generator.
"""

from __future__ import annotations

import sys
from pathlib import Path

from datasette_google_auth.telemetry_registry import METRICS, SPANS

README = Path(__file__).parent.parent / "README.md"
START = "<!-- telemetry-reference:start -->"
END = "<!-- telemetry-reference:end -->"


def render() -> str:
    lines: list[str] = []
    lines.append("#### Spans")
    lines.append("")
    for span in SPANS:
        lines.append(f"**`{span}`** — {span.description}")
        lines.append("")
        if span.attributes:
            attrs = []
            for attribute in span.attributes:
                optional = " *(optional)*" if attribute.optional else ""
                attrs.append(f"- `{attribute}`{optional} — {attribute.description}")
            lines.append("Attributes:")
            lines.append("")
            lines.extend(attrs)
            lines.append("")
    lines.append("#### Metrics")
    lines.append("")
    lines.append("| Metric | Kind | Unit | Attributes | Description |")
    lines.append("|---|---|---|---|---|")
    for metric in METRICS:
        attrs = "<br>".join(f"`{a}`" for a in metric.attributes) or "—"
        description = metric.description.replace("|", "\\|")
        lines.append(
            f"| `{metric}` | {metric.kind} | `{metric.unit}` | {attrs} "
            f"| {description} |"
        )
    lines.append("")
    lines.append(
        "Attribute meanings match the span attributes of the same name above. "
        "`datasette_google_auth.credential.id` is never a metric dimension, and "
        "no signal carries a token, code, key material, email, actor id, label, "
        "URL path or query, or error message."
    )
    lines.append("")
    lines.append("Histogram buckets (seconds):")
    lines.append("")
    for metric in METRICS:
        if metric.buckets:
            boundaries = ", ".join(str(b) for b in metric.buckets)
            lines.append(f"- `{metric}`: {boundaries}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    check = "--check" in sys.argv
    text = README.read_text()
    if START not in text or END not in text:
        print(f"README.md is missing the {START} / {END} markers", file=sys.stderr)
        return 1
    head, rest = text.split(START, 1)
    _, tail = rest.split(END, 1)
    updated = f"{head}{START}\n\n{render()}\n{END}{tail}"
    if updated == text:
        return 0
    if check:
        print(
            "README.md telemetry reference is stale; run `just telemetry-doc`",
            file=sys.stderr,
        )
        return 1
    README.write_text(updated)
    print("Rewrote README.md telemetry reference")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
