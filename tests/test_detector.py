from datetime import datetime, timedelta

from src.detector import (detect_bruteforce, get_severity)


def test_bruteforce_detected():

    start = datetime.now()

    timestamps = [
        start,
        start + timedelta(seconds=10),
        start + timedelta(seconds=20)
    ]

    result = detect_bruteforce(
        timestamps,
        threshold=3,
        window_seconds=60
    )

    assert result is True


def test_bruteforce_not_detected():

    start = datetime.now()

    timestamps = [
        start,
        start + timedelta(seconds=70),
        start + timedelta(seconds=140)
    ]

    result = detect_bruteforce(
        timestamps,
        threshold=3,
        window_seconds=60
    )

    assert result is False

from src.detector import get_severity


def test_low_severity():

    assert get_severity(1) == "LOW"
    assert get_severity(2) == "LOW"


def test_medium_severity():

    assert get_severity(3) == "MEDIUM"
    assert get_severity(4) == "MEDIUM"


def test_high_severity():

    assert get_severity(5) == "HIGH"
    assert get_severity(10) == "HIGH"

def test_success_after_failures():

    failed_attempts = {
        "192.168.1.50": {
            "admin": 5
        }
    }

    successful_logins = {
        "192.168.1.50": "admin"
    }

    from src.detector import detect_success_after_failures

    alerts = detect_success_after_failures(
        failed_attempts,
        successful_logins
    )

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["username"] == "admin"
    assert alerts[0]["failed_attempts"] == 5