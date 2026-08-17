from src.parser import parse_log_line


def test_failed_login():

    line = (
        "Aug 16 10:15:20 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event["event_type"] == "failed_login"
    assert event["username"] == "admin"
    assert event["source_ip"] == "192.168.1.50"


def test_successful_login():

    line = (
        "Aug 16 10:20:30 server sshd[1234]: "
        "Accepted password for jarif from 192.168.1.20"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event["event_type"] == "successful_login"
    assert event["username"] == "jarif"
    assert event["source_ip"] == "192.168.1.20"


def test_invalid_log():

    line = "This is not an SSH authentication log"

    event = parse_log_line(line)

    assert event is None