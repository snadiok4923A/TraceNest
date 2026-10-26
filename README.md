# TraceNest — Log Analyzer & Incident Toolkit

TraceNest is a Python command-line utility for exploring application/server logs. It extracts common severity levels, HTTP status codes, endpoints, IP addresses, timestamps, and request durations, then creates a readable summary.

## Features
- Count log levels and HTTP status codes
- Find frequently used endpoints
- Calculate average and maximum recorded request duration
- Collect error/fatal entries and HTTP 5xx responses
- Export reports to JSON and parsed entries to CSV
- Includes a sample log and automated tests
- Python standard library only

## Requirements
Python 3.9+. No third-party packages required.

## Quick start
Analyze the included sample:
```bash
python tracenest.py --sample
```
Analyze your own log:
```bash
python tracenest.py app.log
```
Export reports:
```bash
python tracenest.py app.log --json report.json --csv parsed_entries.csv
```

## Tests
```bash
python -m unittest discover -s tests -v
```

## Structure
```text
TraceNest-Log-Analyzer/
├── tracenest.py
├── sample.log
├── tests/test_tracenest.py
├── README.md
├── LICENSE
└── .gitignore
```

## Limitations and privacy
Log formats vary, so custom formats may need adjusted parsing patterns. Treat logs as sensitive: they can contain IP addresses, user identifiers, tokens, or private data. Do not upload real logs to a public repository without reviewing and sanitizing them.

## License
MIT License. See `LICENSE`.
