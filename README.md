# CronHive

Cross-infrastructure cron job discovery, inventory & dead-job alerting.

CronHive scans system and user crontabs, validates schedules, redacts secrets
from commands, detects dead/missed jobs, and generates inventory reports.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan a crontab file
python cronhive.py --scan-file /etc/crontab --system --output json

# Scan current user's crontab
python cronhive.py --scan-user

# Scan a custom crontab file (user format, no user column)
python cronhive.py --scan-file ./my_crontab

# JSON output
python cronhive.py --scan-file /etc/crontab --system --output json
```

## Features

- **Discovery**: Parse system crontabs (`/etc/crontab`) and user crontabs (`crontab -l`)
- **Validation**: Verify every cron expression is syntactically valid
- **Secret Redaction**: Auto-scrub `password=`, `token=`, `api_key=` from output
- **Dead Job Detection**: Detect jobs that missed their expected run window
- **Path Safety**: Reject paths with traversal attempts (`..`)

## Run Tests

```bash
pytest test_cronhive.py -v
```

## License

MIT
