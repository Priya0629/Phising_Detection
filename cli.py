import argparse
import csv
from phish_detector import check_url

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def colorize(text, label):
    """Apply colors based on result type"""
    if "Suspicious" in text:
        return RED + text + RESET
    elif "Looks safe" in text:
        return GREEN + text + RESET
    else:
        return YELLOW + text + RESET

def print_table(rows, headers):
    """Prints results in a simple color-coded table"""
    col_widths = [max(len(str(row[i])) for row in rows + [headers]) for i in range(len(headers))]
    # Header
    header_line = " | ".join(str(headers[i]).ljust(col_widths[i]) for i in range(len(headers)))
    print("\n" + header_line)
    print("-" * len(header_line))
    # Rows
    for row in rows:
        row_display = []
        for i, val in enumerate(row):
            if headers[i].lower() == "result":
                row_display.append(colorize(str(val), val).ljust(col_widths[i] + 10))
            else:
                row_display.append(str(val).ljust(col_widths[i]))
        print(" | ".join(row_display))
    print()

def run_single(url: str, export=None):
    result = check_url(url)
    rows = [[url, result]]
    print_table(rows, ["URL", "Result"])

    if export:
        with open(export, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "result"])
            writer.writerow([url, result])
        print(f"✅ Results exported to {export}")

def run_file(path: str, export=None):
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            url = row.get("url", "")
            if url:
                result = check_url(url)
                label = row.get("label", "")
                rows.append([url, result, label])

    print_table(rows, ["URL", "Result", "Expected"])

    if export:
        with open(export, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "result", "expected"])
