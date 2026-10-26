"""TraceNest: a log analyzer and incident investigation toolkit."""
import argparse
import csv
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

LEVEL_RE = re.compile(r"\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HTTP_RE = re.compile(r'"\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^"\s]+)\s+HTTP/[\d.]+"\s+(\d{3})')
DURATION_RE = re.compile(r"\b(?:duration|elapsed|latency|took)[=: ]+(\d+(?:\.\d+)?)\s*(ms|s|sec|seconds)?\b", re.I)
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?")

def parse_line(line, line_number=1):
    ts = TS_RE.search(line)
    lm = LEVEL_RE.search(line)
    level = lm.group(1).upper() if lm else "UNKNOWN"
    if level == "WARNING": level = "WARN"
    if level == "CRITICAL": level = "FATAL"
    hm = HTTP_RE.search(line)
    dm = DURATION_RE.search(line)
    duration = None
    if dm:
        duration = float(dm.group(1)) * (1000 if (dm.group(2) or "ms").lower() in {"s", "sec", "seconds"} else 1)
    return {"line_number": line_number, "timestamp": ts.group(0) if ts else None,
            "level": level, "http_method": hm.group(1) if hm else None,
            "http_path": hm.group(2) if hm else None, "http_status": int(hm.group(3)) if hm else None,
            "ip_addresses": IP_RE.findall(line), "duration_ms": duration, "message": line.rstrip("\r\n")}

def analyze_lines(lines):
    entries = [parse_line(line, i) for i, line in enumerate(lines, 1) if line.strip()]
    levels = Counter(e["level"] for e in entries)
    statuses = Counter(str(e["http_status"]) for e in entries if e["http_status"] is not None)
    endpoints = Counter(e["http_path"] for e in entries if e["http_path"])
    durations = [e["duration_ms"] for e in entries if e["duration_ms"] is not None]
    errors = [e for e in entries if e["level"] in {"ERROR", "FATAL"} or (e["http_status"] is not None and e["http_status"] >= 500)]
    return {"generated_at": datetime.now().isoformat(timespec="seconds"), "total_entries": len(entries),
            "level_counts": dict(sorted(levels.items())), "http_status_counts": dict(sorted(statuses.items())),
            "top_endpoints": endpoints.most_common(10), "duration_count": len(durations),
            "average_duration_ms": round(sum(durations)/len(durations), 2) if durations else None,
            "max_duration_ms": max(durations) if durations else None, "error_count": len(errors),
            "errors": errors, "entries": entries}

def analyze_file(path):
    with Path(path).open(encoding="utf-8", errors="replace") as f: return analyze_lines(f)

def write_json(report, path):
    Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

def write_csv(report, path):
    fields = ["line_number", "timestamp", "level", "http_method", "http_path", "http_status", "ip_addresses", "duration_ms", "message"]
    with Path(path).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader()
        for item in report["entries"]:
            row = dict(item); row["ip_addresses"] = ", ".join(row["ip_addresses"]); writer.writerow(row)

def print_report(r):
    print("\n========== TRACENEST REPORT ==========")
    print(f"Log entries analyzed: {r['total_entries']}\nErrors / fatal entries: {r['error_count']}")
    print("\nSeverity counts:")
    for k, v in r["level_counts"].items(): print(f"  {k:<8} {v}")
    print("\nHTTP status counts:")
    for k, v in r["http_status_counts"].items(): print(f"  {k}: {v}")
    print("\nMost-used endpoints:")
    for k, v in r["top_endpoints"]: print(f"  {k}: {v}")
    if r["average_duration_ms"] is not None:
        print(f"\nAverage duration: {r['average_duration_ms']} ms\nMaximum duration: {r['max_duration_ms']} ms")
    if r["errors"]:
        print("\nError samples:")
        for e in r["errors"][:8]: print(f"  Line {e['line_number']} [{e['level']}] {e['message'][:180]}")

def main():
    parser = argparse.ArgumentParser(description="Analyze application and server logs")
    parser.add_argument("logfile", nargs="?", help="Text log file path")
    parser.add_argument("--sample", action="store_true", help="Analyze included sample.log")
    parser.add_argument("--json", dest="json_path", help="Write full report to JSON")
    parser.add_argument("--csv", dest="csv_path", help="Export parsed entries to CSV")
    args = parser.parse_args()
    path = Path(__file__).resolve().parent / "sample.log" if args.sample else (Path(args.logfile) if args.logfile else None)
    if path is None: parser.error("Provide a logfile path or use --sample.")
    try: report = analyze_file(path)
    except OSError as exc: parser.error(str(exc))
    print_report(report)
    if args.json_path: write_json(report, args.json_path); print(f"\nJSON report saved to {args.json_path}")
    if args.csv_path: write_csv(report, args.csv_path); print(f"CSV export saved to {args.csv_path}")

if __name__ == "__main__": main()
