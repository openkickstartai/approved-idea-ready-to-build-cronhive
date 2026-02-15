"""CronHive - Cross-infrastructure cron job discovery, inventory & dead-job alerting."""
import dataclasses
import datetime
import json
import os
import re
import subprocess
import sys

from croniter import croniter

SECRET_RE = re.compile(
    r"(password|secret|token|api[_\-]?key|credentials)\s*[=:]\s*\S+", re.I
)
SPECIAL_SCHEDS = {
    "@reboot", "@yearly", "@annually", "@monthly",
    "@weekly", "@daily", "@midnight", "@hourly",
}


@dataclasses.dataclass
class CronJob:
    source: str
    schedule: str
    command: str
    user: str = ""
    valid: bool = True


def redact(cmd):
    """Redact potential secrets from command strings."""
    return SECRET_RE.sub(lambda m: m.group(1) + "=***", cmd)


def validate_schedule(expr):
    """Validate a cron expression."""
    if not isinstance(expr, str) or not expr.strip():
        return False
    if expr.startswith("@"):
        return expr in SPECIAL_SCHEDS
    try:
        croniter(expr)
        return True
    except (ValueError, KeyError, TypeError):
        return False


def parse_crontab(text, source="unknown", system=False):
    """Parse crontab text into CronJob list. system=True expects user field."""
    jobs = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        if len(tokens) >= 2 and "=" in tokens[0]:
            continue
        if line.startswith("@"):
            parts = line.split(None, 2 if system else 1)
            need = 3 if system else 2
            if len(parts) >= need:
                sched, user = parts[0], (parts[1] if system else "")
                cmd = parts[-1]
                jobs.append(CronJob(source, sched, redact(cmd), user, validate_schedule(sched)))
            continue
        parts = line.split(None, 6 if system else 5)
        need = 7 if system else 6
        if len(parts) < need:
            continue
        sched = " ".join(parts[:5])
        user = parts[5] if system else ""
        cmd = parts[6] if system else parts[5]
        jobs.append(CronJob(source, sched, redact(cmd), user, validate_schedule(sched)))
    return jobs


def scan_file(path, system=False):
    """Scan a crontab file with path traversal protection."""
    if ".." in path:
        return []
    real = os.path.realpath(path)
    try:
        with open(real) as f:
            return parse_crontab(f.read(), source=real, system=system)
    except (PermissionError, FileNotFoundError, OSError):
        return []


def is_dead(schedule, last_run, now=None):
    """Check if a job missed its expected run window."""
    now = now or datetime.datetime.now()
    if not validate_schedule(schedule):
        return True, None
    if schedule in ("@reboot",):
        return False, None
    try:
        it = croniter(schedule, last_run)
        expected = it.get_next(datetime.datetime)
        next_after = it.get_next(datetime.datetime)
        interval = (next_after - expected).total_seconds()
        overdue = (now - expected).total_seconds()
        return overdue > interval * 2, expected
    except Exception:
        return True, None


def inventory(jobs):
    """Generate inventory report dict."""
    return {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total": len(jobs),
        "valid": sum(1 for j in jobs if j.valid),
        "invalid": sum(1 for j in jobs if not j.valid),
        "jobs": [dataclasses.asdict(j) for j in jobs],
    }


def main():
    import argparse
    p = argparse.ArgumentParser(description="CronHive - cron discovery & alerting")
    p.add_argument("--scan-file", action="append", default=[], help="Crontab file")
    p.add_argument("--system", action="store_true", help="System crontab format")
    p.add_argument("--scan-user", action="store_true", help="Scan user crontab")
    p.add_argument("--output", choices=["json", "text"], default="text")
    args = p.parse_args()
    jobs = []
    for f in args.scan_file:
        jobs.extend(scan_file(f, system=args.system))
    if args.scan_user:
        try:
            r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                jobs.extend(parse_crontab(r.stdout, source="user:" + os.getenv("USER", "?")))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("Warning: could not read user crontab", file=sys.stderr)
    report = inventory(jobs)
    if args.output == "json":
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"CronHive: {report['total']} jobs ({report['valid']} valid, {report['invalid']} invalid)")
        for j in report["jobs"]:
            s = "V" if j["valid"] else "X"
            print(f"  [{s}] {j['schedule']:20s} | {j['user'] or '-':8s} | {j['command'][:50]}")


if __name__ == "__main__":
    main()
