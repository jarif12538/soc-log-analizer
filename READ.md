
**SOC Log Analyzer**

- **Description:** Lightweight Python tool to parse SSH authentication logs, detect suspicious activity (failed logins, brute-force attempts, and successful logins after multiple failures), and save alerts in `reports/` for review. Includes a tiny Node.js backend to serve saved alerts.

**Features:**
- Detect failed and successful SSH logins from syslog-style entries.
- Identify suspicious usernames (configurable).
- Detect brute-force attempts within a configurable time window.
- Flag successful logins that occur after repeated failures.
- Persist alerts to `reports/alerts.json` and `reports/alerts.txt` and expose them via a simple HTTP API.

**Requirements:**
- Python 3.8+ (recommended)
- Node.js (for the backend API)

**Quickstart**

1. Create a virtual environment and install test deps (if you use one):

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # optional (project currently has no deps)
```

2. Configure the log file location and detection thresholds in [src/config.py](src/config.py).

3. Run the analyzer (reads the file configured in [src/config.py](src/config.py)):

```
python main.py
```

4. Start the backend API to browse alerts (from `Backend/`):

```
cd Backend
npm install
npm start
# open http://localhost:3000/alerts
```

**Configuration**
- The main configuration values are in [src/config.py](src/config.py):
	- `LOG_FILE` — path to the SSH auth log (default: `logs/auth.log`).
	- `SUSPICIOUS_USERS` — set of usernames considered suspicious.
	- `BRUTE_FORCE_THRESHOLD` and `BRUTE_FORCE_WINDOW` — controls brute-force detection sensitivity.

**Important files**
- [main.py](main.py) — primary runner that parses logs and generates alerts.
- [src/parser.py](src/parser.py) — log-line parsing utilities and timestamp extraction.
- [src/detector.py](src/detector.py) — core detection logic (failed counts, brute-force, severity).
- [src/alerts.py](src/alerts.py) — alert formatting and persistence to `reports/`.
- [Backend/api.js](Backend/api.js) — small Express API that serves `reports/alerts.json`.
- [tests/](tests/) — unit tests for parser and detector logic.

**Testing**
- Run the unit tests with `pytest` from the repository root:

```
pytest -q

```

**Notes & Next Steps**
- Add a `requirements.txt` or `pyproject.toml` to pin Python dependencies.
- Consider rotating/archiving `reports/alerts.json` to avoid unbounded growth.
- Add configuration for log rotation and incremental processing for large logs.


