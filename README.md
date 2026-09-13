# mc-log-analyzer

Tiny regex-based Minecraft server log diagnostics. Zero dependencies beyond the
Python 3.11+ stdlib. Designed for the Mars Host panel: feed it the latest.log
output and it surfaces known root causes with a fix hint.

## What it detects

| ID | Severity | Trigger |
| --- | --- | --- |
| `eula_not_accepted` | CRITICAL | `eula.txt` not set to true |
| `port_bind_failure` | CRITICAL | server port already bound |
| `java_version_mismatch` | CRITICAL | plugin requires newer Java class version |
| `oom_heap` | CRITICAL | JVM `OutOfMemoryError: Java heap space` / kernel kill |
| `oom_metaspace` | CRITICAL | JVM `OutOfMemoryError: Metaspace` |
| `missing_plugin_dependency` | ERROR | `Could not load 'X' in folder 'plugins'` etc. |
| `corrupted_chunk` | CRITICAL | `RegionFileException` / corrupted `.mca` |
| `sqlite_db_locked` | ERROR | `sqlite3.OperationalError: database is locked` |

## Usage

```python
from analyzer import analyze_log

issues = analyze_log(open("latest.log").read())
for i in issues:
    print(i.severity, i.id, "—", i.title)
```

Or as a CLI:

```bash
python3 analyzer.py latest.log                 # text report
python3 analyzer.py latest.log --format json   # machine-readable
cat latest.log | python3 analyzer.py           # stdin
```

## Tests

```bash
python3 -m pytest tests/
```

## Extending

Add a new rule:

```python
{
    "id": "my_rule",
    "pattern": re.compile(r"my regex", re.IGNORECASE),
    "title": "Human title",
    "severity": "WARNING",   # one of CRITICAL, ERROR, WARNING
    "cause": "Why it happens",
    "solution": "How to fix it",
}
```

…then add a positive test in `tests/test_analyzer.py`.
