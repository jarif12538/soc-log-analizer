import re
from datetime import datetime


def parse_log_line(line):

    # -----------------------------------
    # Extract timestamp
    # -----------------------------------

    time_match = re.search(
        r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})",
        line
    )

    # -----------------------------------
    # Extract username
    # -----------------------------------

    username_match = re.search(
        r"Failed password for (?:invalid user )?(\S+)",
        line
    )

    # -----------------------------------
    # Extract source IP
    # -----------------------------------

    ip_match = re.search(
        r"from (\d{1,3}(?:\.\d{1,3}){3})",
        line
    )

    # -----------------------------------
    # Failed login
    # -----------------------------------

    if (
        "Failed password" in line
        and time_match
        and username_match
        and ip_match
    ):

        month = time_match.group(1)
        day = time_match.group(2)
        clock = time_match.group(3)

        event_time = datetime.strptime(
            f"{datetime.now().year} {month} {day} {clock}",
            "%Y %b %d %H:%M:%S"
        )

        return {
            "event_type": "failed_login",
            "timestamp": event_time,
            "username": username_match.group(1),
            "source_ip": ip_match.group(1)
        }

    # -----------------------------------
    # Successful login
    # -----------------------------------

    username_match = re.search(
        r"Accepted password for (\S+)",
        line
    )

    if (
        "Accepted password" in line
        and time_match
        and username_match
        and ip_match
    ):

        month = time_match.group(1)
        day = time_match.group(2)
        clock = time_match.group(3)

        event_time = datetime.strptime(
            f"{datetime.now().year} {month} {day} {clock}",
            "%Y %b %d %H:%M:%S"
        )

        return {
            "event_type": "successful_login",
            "timestamp": event_time,
            "username": username_match.group(1),
            "source_ip": ip_match.group(1)
        }

    return None