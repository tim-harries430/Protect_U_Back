from __future__ import annotations

import argparse
import html
import json
from pathlib import Path


ORDER = (
    "naked_agent",
    "prompt_guardrail",
    "keyword_guardrail",
    "content_sha256_endpoint",
    "legacy_endpoint",
    "xray_access_only",
    "xray_process_only",
    "full_pub_reference",
)
LABELS = {
    "naked_agent": "Naked",
    "prompt_guardrail": "Prompt",
    "keyword_guardrail": "Keyword",
    "content_sha256_endpoint": "Content SHA",
    "legacy_endpoint": "Endpoint",
    "xray_access_only": "Access-only",
    "xray_process_only": "Process-only",
    "full_pub_reference": "Full PUB",
}


def render(score_path: Path, out_path: Path) -> None:
    report = json.loads(score_path.read_text(encoding="utf-8"))
    detectors = report["detectors"]
    width, height = 1200, 720
    left, top, right, bottom = 90, 100, 670, 620
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<style>text{font-family:Arial,"Microsoft YaHei",sans-serif;fill:#1e252b}.small{font-size:14px}.label{font-size:16px}.title{font-size:25px;font-weight:700}.axis{stroke:#1e252b;stroke-width:2}.grid{stroke:#d9dee2;stroke-width:1}.base{fill:#9ca4aa;stroke:#1e252b;stroke-width:2}.abl{fill:#72a9d6;stroke:#2867a5;stroke-width:2}.pub{fill:#e2676b;stroke:#b52b31;stroke-width:2}.bar{fill:#9ca4aa}.barabl{fill:#2867a5}.barpub{fill:#b52b31}</style>',
        '<text x="600" y="42" text-anchor="middle" class="title">Baseline and PUB security-utility comparison</text>',
        '<text x="90" y="78" class="label">A  Security-utility plane</text>',
        f'<rect x="{left}" y="{top}" width="{right-left}" height="{bottom-top}" fill="none" class="axis"/>',
    ]
    for i in range(6):
        value = i / 5
        x = left + value * (right - left)
        y = bottom - value * (bottom - top)
        lines += [
            f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{bottom}" class="grid"/>',
            f'<line x1="{left}" y1="{y:.1f}" x2="{right}" y2="{y:.1f}" class="grid"/>',
            f'<text x="{x:.1f}" y="{bottom+24}" text-anchor="middle" class="small">{value:.1f}</text>',
            f'<text x="{left-14}" y="{y+5:.1f}" text-anchor="end" class="small">{value:.1f}</text>',
        ]
    lines += [
        f'<rect x="{left+0.8*(right-left):.1f}" y="{top}" width="{0.2*(right-left):.1f}" height="{0.2*(bottom-top):.1f}" fill="#dff1e3"/>',
        f'<text x="{right-55}" y="{top+25}" text-anchor="middle" class="small">ideal</text>',
        f'<text x="{(left+right)/2:.1f}" y="{height-34}" text-anchor="middle" class="label">benign completion rate</text>',
        f'<text x="25" y="{(top+bottom)/2:.1f}" transform="rotate(-90 25 {(top+bottom)/2:.1f})" text-anchor="middle" class="label">attack capture rate</text>',
        '<text x="735" y="78" class="label">B  Binary F1</text>',
    ]
    point_offsets = {
        "naked_agent": (-85, -12), "prompt_guardrail": (-85, 18),
        "keyword_guardrail": (15, 38), "content_sha256_endpoint": (14, -8),
        "legacy_endpoint": (14, -20), "xray_access_only": (14, 5),
        "xray_process_only": (14, -36), "full_pub_reference": (14, -10),
    }
    for index, name in enumerate(ORDER):
        row = detectors[name]
        x = left + float(row["benign_completion_rate"]) * (right - left)
        y = bottom - float(row["attack_capture_rate"]) * (bottom - top)
        kind = row["kind"]
        css = "pub" if kind == "reference" else "abl" if kind == "ablation" else "base"
        if kind == "ablation":
            shape = f'<polygon points="{x:.1f},{y-9:.1f} {x-9:.1f},{y+8:.1f} {x+9:.1f},{y+8:.1f}" class="{css}"/>'
        elif kind == "reference":
            shape = f'<path d="M{x:.1f},{y-11:.1f} L{x+4:.1f},{y-4:.1f} L{x+11:.1f},{y:.1f} L{x+4:.1f},{y+4:.1f} L{x:.1f},{y+11:.1f} L{x-4:.1f},{y+4:.1f} L{x-11:.1f},{y:.1f} L{x-4:.1f},{y-4:.1f} Z" class="{css}"/>'
        else:
            shape = f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" class="{css}"/>'
        dx, dy = point_offsets[name]
        lines += [shape, f'<text x="{x+dx:.1f}" y="{y+dy:.1f}" class="small">{html.escape(LABELS[name])}</text>']

        bar_y = 112 + index * 62
        bar_x, bar_max = 870, 270
        f1 = float(row["f1"])
        bar_width = f1 / 0.7 * bar_max
        bar_css = "barpub" if kind == "reference" else "barabl" if kind == "ablation" else "bar"
        lines += [
            f'<text x="850" y="{bar_y+15}" text-anchor="end" class="small">{html.escape(LABELS[name])}</text>',
            f'<rect x="{bar_x}" y="{bar_y}" width="{bar_width:.1f}" height="22" rx="4" class="{bar_css}"/>',
            f'<text x="{bar_x+bar_width+8:.1f}" y="{bar_y+16}" class="small">{f1:.3f}</text>',
        ]
    lines += [
        '<text x="735" y="630" class="small">n = 10 attack + 10 control; frozen v3 oracle</text>',
        '</svg>',
    ]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Render Figure 11 from baseline_score.json")
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--score", default=str(root / "baseline" / "run_v3" / "baseline_score.json"))
    parser.add_argument("--out", default=str(root / "_recomputed" / "figure11_baseline_security_utility.svg"))
    args = parser.parse_args()
    render(Path(args.score).resolve(), Path(args.out).resolve())
    print(f"[figure11] wrote {Path(args.out).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
