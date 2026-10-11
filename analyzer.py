#!/usr/bin/env python3
"""
Password Security Analyzer
===========================
A tool that analyzes password strength and generates a security report.

Modes:
  - single: analyze one password
  - bulk:   analyze many passwords from a file

Outputs:
  - HTML report (single or bulk)
  - JSON results
  - CSV (bulk mode)

Author: batool jameel
License: MIT
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from password_checker import analyze
from bulk_checker import analyze_list, analyze_file


# --------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------

def banner(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def write_csv(path, rows, fieldnames=None):
    if not rows:
        return
    if fieldnames is None:
        fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def print_single_report(report):
    """Pretty print for a single password analysis."""
    banner("PASSWORD ANALYSIS")
    print(f"  Password:     {report['password_masked']}")
    print(f"  Length:       {report['length']}")
    print(f"  Entropy:      {report['entropy_bits']} bits")
    print(f"  Score:        {report['score']}/100")
    print(f"  Strength:     {report['strength']}")
    print(f"  Crack time:   {report['crack_time']}")
    print(f"  Repetition:   {report['has_repetition']}")
    print(f"  Sequence:     {report['has_sequence']}")
    print(f"  Common:       {report['is_common']}")

    banner("CHARACTER SETS")
    for k, v in report["character_sets"].items():
        mark = "[+]" if v else "[-]"
        print(f"  {mark} {k}")

    if report["suggestions"]:
        banner("SUGGESTIONS")
        for s in report["suggestions"]:
            print(f"  - {s}")


def print_bulk_summary(summary):
    """Pretty print for bulk analysis."""
    banner("BULK ANALYSIS SUMMARY")
    print(f"  Total passwords:    {summary['total']}")
    print(f"  Very Weak:          {summary['very_weak']}")
    print(f"  Weak:               {summary['weak']}")
    print(f"  Medium:             {summary['medium']}")
    print(f"  Strong:             {summary['strong']}")
    print(f"  Very Strong:        {summary['very_strong']}")
    print(f"  Average score:      {summary['average_score']}/100")


# --------------------------------------------------------------------
# Report Generation
# --------------------------------------------------------------------

def generate_html(template_name, context, output_path):
    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template(template_name)
    html = template.render(**context)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


# --------------------------------------------------------------------
# Entry Point
# --------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Password Security Analyzer - check password strength"
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # -- single mode --
    p_single = sub.add_parser("single", help="Analyze one password")
    p_single.add_argument("password", help="Password to analyze")
    p_single.add_argument(
        "-o", "--output", default=None,
        help="Output dir (default: output/single_YYYYMMDD_HHMMSS)"
    )

    # -- bulk mode --
    p_bulk = sub.add_parser("bulk", help="Analyze passwords from a file")
    p_bulk.add_argument("filepath", help="Path to file (one password per line)")
    p_bulk.add_argument(
        "-o", "--output", default=None,
        help="Output dir (default: output/bulk_YYYYMMDD_HHMMSS)"
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # SINGLE MODE
    # ------------------------------------------------------------------
    if args.mode == "single":
        report = analyze(args.password)
        print_single_report(report)

        if args.output is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"output/single_{ts}"
        else:
            output_dir = args.output

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # Save JSON
        write_json(out / "report.json", report)

        # HTML report
        generate_html(
            "report_template.html",
            {
                "mode": "single",
                "report": report,
                "generated_at": datetime.now().isoformat(timespec="seconds"),
            },
            out / "report.html",
        )

        print(f"\n  [+] Report:   {out}/report.html")
        print(f"  [+] JSON:     {out}/report.json\n")

    # ------------------------------------------------------------------
    # BULK MODE
    # ------------------------------------------------------------------
    elif args.mode == "bulk":
        if not os.path.exists(args.filepath):
            print(f"[!] File not found: {args.filepath}")
            sys.exit(1)

        result = analyze_file(args.filepath)
        print_bulk_summary(result["summary"])

        if args.output is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"output/bulk_{ts}"
        else:
            output_dir = args.output

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # JSON
        write_json(out / "results.json", result)

        # CSV
        csv_rows = []
        for r in result["results"]:
            csv_rows.append({
                "password": r["password"],
                "length": r["length"],
                "entropy": r["entropy_bits"],
                "score": r["score"],
                "strength": r["strength"],
                "crack_time": r["crack_time"],
                "is_common": r["is_common"],
                "has_sequence": r["has_sequence"],
                "has_repetition": r["has_repetition"],
            })
        write_csv(out / "results.csv", csv_rows)

        # HTML
        generate_html(
            "report_template.html",
            {
                "mode": "bulk",
                "result": result,
                "generated_at": datetime.now().isoformat(timespec="seconds"),
            },
            out / "report.html",
        )

        print(f"\n  [+] Report:   {out}/report.html")
        print(f"  [+] JSON:     {out}/results.json")
        print(f"  [+] CSV:      {out}/results.csv\n")

    banner("DONE")


if __name__ == "__main__":
    main() 