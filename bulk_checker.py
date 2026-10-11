"""
Bulk Checker
=============
Analyzes a list of passwords (from a file or list) and returns:
  - Per-password analysis
  - Summary statistics
  - Weakest passwords
  - Sorted results
"""

from password_checker import analyze


def analyze_list(passwords):
    """
    Analyze a list of passwords.
    Returns dict with results + summary.
    """
    results = []

    for pwd in passwords:
        pwd = pwd.strip()
        if not pwd:
            continue
        report = analyze(pwd)
        report["password"] = pwd  # keep original for bulk mode
        results.append(report)

    if not results:
        return {
            "results": [],
            "summary": {
                "total": 0,
                "very_weak": 0,
                "weak": 0,
                "medium": 0,
                "strong": 0,
                "very_strong": 0,
                "average_score": 0,
            },
            "weakest": [],
        }

    # Count by strength
    summary = {
        "total": len(results),
        "very_weak": sum(1 for r in results if r["strength"] == "VERY WEAK"),
        "weak": sum(1 for r in results if r["strength"] == "WEAK"),
        "medium": sum(1 for r in results if r["strength"] == "MEDIUM"),
        "strong": sum(1 for r in results if r["strength"] == "STRONG"),
        "very_strong": sum(1 for r in results if r["strength"] == "VERY STRONG"),
        "average_score": round(
            sum(r["score"] for r in results) / len(results), 1
        ),
    }

    # Weakest 10
    weakest = sorted(results, key=lambda r: r["score"])[:10]

    return {
        "results": results,
        "summary": summary,
        "weakest": weakest,
    }


def analyze_file(filepath):
    """Read passwords from a file (one per line) and analyze them."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    return analyze_list(passwords)