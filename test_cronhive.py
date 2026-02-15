"""Tests for CronHive."""
import datetime
import pytest
from cronhive import parse_crontab, validate_schedule, redact, is_dead, inventory, CronJob, scan_file


def test_parse_user_crontab():
    text = "# backup jobs\nSHELL=/bin/bash\n*/5 * * * * /usr/bin/backup.sh\n0 2 * * * /opt/run --password=hunter2\n"
    jobs = parse_crontab(text, source="test")
    assert len(jobs) == 2
    assert jobs[0].schedule == "*/5 * * * *"
    assert jobs[0].command == "/usr/bin/backup.sh"
    assert jobs[0].valid is True
    assert "hunter2" not in jobs[1].command
    assert "***" in jobs[1].command


def test_parse_system_crontab():
    text = "*/10 * * * * root /usr/sbin/logrotate\n0 3 * * 0 www-data /opt/weekly.sh\n"
    jobs = parse_crontab(text, source="/etc/crontab", system=True)
    assert len(jobs) == 2
    assert jobs[0].user == "root"
    assert jobs[0].command == "/usr/sbin/logrotate"
    assert jobs[1].user == "www-data"


def test_parse_special_schedules():
    text = "@hourly /usr/bin/hourly_task\n@daily /usr/bin/daily_task\n"
    jobs = parse_crontab(text, source="test")
    assert len(jobs) == 2
    assert jobs[0].schedule == "@hourly"
    assert jobs[0].valid is True
    assert jobs[1].schedule == "@daily"


def test_validate_schedule_valid():
    assert validate_schedule("*/5 * * * *") is True
    assert validate_schedule("0 2 * * 1-5") is True
    assert validate_schedule("@daily") is True
    assert validate_schedule("@reboot") is True
    assert validate_schedule("0 0 1 1 *") is True


def test_validate_schedule_invalid():
    assert validate_schedule("not a schedule") is False
    assert validate_schedule("") is False
    assert validate_schedule(None) is False
    assert validate_schedule("@bogus") is False


def test_redact_secrets():
    assert "s3cret" not in redact("cmd --password=s3cret")
    assert "***" in redact("cmd --api_key=abc123")
    assert "***" in redact("cmd token=xyz")
    assert redact("safe command") == "safe command"
    assert "***" in redact("export credentials=foo")


def test_dead_job_detected():
    now = datetime.datetime(2024, 6, 15, 12, 0, 0)
    last = datetime.datetime(2024, 6, 15, 11, 0, 0)
    dead, expected = is_dead("*/5 * * * *", last, now)
    assert dead is True
    assert expected is not None


def test_alive_job():
    now = datetime.datetime(2024, 6, 15, 12, 0, 0)
    last = datetime.datetime(2024, 6, 15, 2, 0, 0)
    dead, _ = is_dead("0 2 * * *", last, now)
    assert dead is False


def test_dead_invalid_schedule():
    now = datetime.datetime(2024, 6, 15, 12, 0, 0)
    last = datetime.datetime(2024, 6, 15, 11, 0, 0)
    dead, expected = is_dead("invalid", last, now)
    assert dead is True
    assert expected is None


def test_reboot_not_dead():
    now = datetime.datetime(2024, 6, 15, 12, 0, 0)
    last = datetime.datetime(2024, 1, 1, 0, 0, 0)
    dead, _ = is_dead("@reboot", last, now)
    assert dead is False


def test_inventory_report():
    jobs = [
        CronJob("test", "*/5 * * * *", "/bin/job1", valid=True),
        CronJob("test", "bad", "/bin/job2", valid=False),
    ]
    report = inventory(jobs)
    assert report["total"] == 2
    assert report["valid"] == 1
    assert report["invalid"] == 1
    assert len(report["jobs"]) == 2
    assert "generated_at" in report


def test_scan_file_path_traversal():
    result = scan_file("../../etc/shadow")
    assert result == []


def test_scan_file_nonexistent():
    result = scan_file("/nonexistent/crontab")
    assert result == []


def test_parse_skips_comments_and_env():
    text = "# comment\nMAILTO=admin@example.com\nPATH=/usr/bin\n*/5 * * * * /bin/task\n"
    jobs = parse_crontab(text, source="test")
    assert len(jobs) == 1
    assert jobs[0].command == "/bin/task"
