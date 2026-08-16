import re
from datetime import datetime
import json


# -----------------------------------
# Parse log line
# -----------------------------------

def parse_log_line(line):

    # Failed login
    if "Failed password" in line:

        time = re.search(
            r"(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})",
            line
        )

        username = re.search(
            r"for (\w+)",
            line
        )

        ip = re.search(
            r"from (\d+\.\d+\.\d+\.\d+)",
            line
        )

        if time and username and ip:

            event_time = datetime.strptime(
                f"{datetime.now().year} {time.group(1)}",
                "%Y %b %d %H:%M:%S"
            )

            return {
                "event_type": "failed_login",
                "timestamp": event_time,
                "username": username.group(1),
                "source_ip": ip.group(1)
            }

    # Successful login
    if "Accepted password" in line:

        time = re.search(
            r"(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})",
            line
        )

        username = re.search(
            r"for (\w+)",
            line
        )

        ip = re.search(
            r"from (\d+\.\d+\.\d+\.\d+)",
            line
        )

        if time and username and ip:

            event_time = datetime.strptime(
                f"{datetime.now().year} {time.group(1)}",
                "%Y %b %d %H:%M:%S"
            )

            return {
                "event_type": "successful_login",
                "timestamp": event_time,
                "username": username.group(1),
                "source_ip": ip.group(1)
            }

    return None


# -----------------------------------
# Process failed login
# -----------------------------------

def process_failed_login(
        event,
        failed_attempts,
        failed_attempts_times,
        suspicious_users,
        printed_suspicious_users
    ):

    username = event["username"]
    source_ip = event["source_ip"]
    event_time = event["timestamp"]

    # Check suspicious username
    if (
        username in suspicious_users
        and username not in printed_suspicious_users
    ):

        print(
            "\n🚨 SUSPICIOUS USERNAME DETECTED:",
            username
        )

        printed_suspicious_users.add(username)

    # Update failed attempts count
    if source_ip not in failed_attempts:
        failed_attempts[source_ip] = {}

    if username not in failed_attempts[source_ip]:
        failed_attempts[source_ip][username] = 1

    else:
        failed_attempts[source_ip][username] += 1

    # Update timestamps
    if source_ip not in failed_attempts_times:
        failed_attempts_times[source_ip] = {}

    if username not in failed_attempts_times[source_ip]:
        failed_attempts_times[source_ip][username] = []

    failed_attempts_times[source_ip][username].append(
        event_time
    )


# -----------------------------------
# Process successful login
# -----------------------------------

def process_successful_login(
        event,
        successful_logins,
        failed_attempts
    ):

    username = event["username"]
    source_ip = event["source_ip"]

    # Store successful login
    successful_logins[source_ip] = username

    print("\nSuccessful login detected:")
    print("Source IP:", source_ip)
    print("Target username:", username)

    failed_count = failed_attempts.get(
        source_ip,
        {}
    ).get(
        username,
        0
    )

    print("Failed attempts:", failed_count)


# -----------------------------------
# Calculate severity
# -----------------------------------

def calculate_severity(count):

    if count >= 5:
        return "HIGH"

    elif count >= 3:
        return "MEDIUM"

    else:
        return "LOW"


# -----------------------------------
# Alert function
# -----------------------------------

def show_alerts(ip, username, count, severity):

    alert_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    alert = {
        "timestamp": alert_time,
        "alert_type": "Possible brute-force attack",
        "severity": severity,
        "source_ip": ip,
        "username": username,
        "failed_attempts": count
    }

    # Display alert
    print("\n======== SECURITY ALERT ========")
    print("Alert time:", alert_time)
    print("Alert type:", alert["alert_type"])
    print("Severity:", severity)
    print("Source IP:", ip)
    print("Target username:", username)
    print("Failed attempts before success:", count)
    print("================================")

    # Save human-readable alert
    with open("reports/alerts.txt", "a") as report:

        report.write(
            f"""
======== SECURITY ALERT ========
Alert time: {alert_time}
Alert type: Possible brute-force attack
Severity: {severity}
Source IP: {ip}
Target username: {username}
Failed attempts before success: {count}
================================

"""
        )

    # Save JSON alert
    with open("reports/alerts.json", "a") as report:

        report.write(
            json.dumps(alert) + "\n"
        )


# -----------------------------------
# Configuration
# -----------------------------------

log_file = "logs/auth.log"

suspicious_users = {
    "root",
    "admin",
    "administrator",
    "test",
    "guest"
}


# -----------------------------------
# Storage
# -----------------------------------

failed_attempts_times = {}
failed_attempts = {}
unique_ips = set()
successful_logins = {}
printed_suspicious_users = set()


# -----------------------------------
# Read log file
# -----------------------------------

with open(log_file, "r") as file:

    for line in file:

        event = parse_log_line(line)

        if event is None:
            continue

        source_ip = event["source_ip"]

        # Track unique IP
        unique_ips.add(source_ip)

        # Failed login
        if event["event_type"] == "failed_login":

            process_failed_login(
                event,
                failed_attempts,
                failed_attempts_times,
                suspicious_users,
                printed_suspicious_users
            )

        # Successful login
        elif event["event_type"] == "successful_login":

            process_successful_login(
                event,
                successful_logins,
                failed_attempts
            )


# -----------------------------------
# Generate alerts
# -----------------------------------

total_failed_attempts = 0

high_alerts = 0
medium_alerts = 0
low_alerts = 0


for ip, users in failed_attempts.items():

    for username, count in users.items():

        total_failed_attempts += count

        # Calculate severity
        severity = calculate_severity(count)

        # Count alerts by severity
        if severity == "HIGH":

            high_alerts += 1

        elif severity == "MEDIUM":

            medium_alerts += 1

        else:

            low_alerts += 1

        # Generate alert
        show_alerts(
            ip,
            username,
            count,
            severity
        )


# -----------------------------------
# Time Window Analysis
# -----------------------------------

print("\n====== Time Window ======")

for ip, users in failed_attempts_times.items():

    for username, timestamps in users.items():

        if len(timestamps) >= 2:

            first_attempt = timestamps[0]
            last_attempt = timestamps[-1]

            time_difference = (
                last_attempt - first_attempt
            )

            time_window = str(time_difference)

            print("Source IP:", ip)
            print("Target username:", username)
            print("Failed attempts:", len(timestamps))
            print("Time window:", time_window)

            print(
                "Time span:",
                time_difference.total_seconds(),
                "seconds"
            )

            print("===============================")

            # Critical brute-force detection
            if (
                len(timestamps) >= 2
                and time_difference.total_seconds() <= 60
            ):

                print("🚨 CRITICAL ALERT")
                print(
                    "Possible brute-force attack detected!"
                )

                print("Source IP:", ip)
                print("Target username:", username)

                print(
                    "Failed attempts:",
                    len(timestamps)
                )

                print("Time window:", time_window)

                print(
                    "Time span:",
                    time_difference.total_seconds(),
                    "seconds"
                )

                print("===============================")


# -----------------------------------
# Successful Login After Failed Logins
# -----------------------------------

print(
    "\n====== SUCCESS AFTER FAILED LOGINS ======"
)

for ip, username in successful_logins.items():

    failed_count = failed_attempts.get(
        ip,
        {}
    ).get(
        username,
        0
    )

    if failed_count >= 3:

        print("🚨 CRITICAL ALERT")

        print(
            "Possible brute-force attack "
            "followed by successful login!"
        )

        print("Source IP:", ip)
        print("Target username:", username)

        print(
            "Failed attempts before success:",
            failed_count
        )

        print("========================================")


# -----------------------------------
# SOC Summary
# -----------------------------------

print("\n========== SOC SUMMARY ==========")

print(
    "Total unique IPs:",
    len(unique_ips)
)

print(
    "Total failed attempts:",
    total_failed_attempts
)

print(
    "High severity alerts:",
    high_alerts
)

print(
    "Medium severity alerts:",
    medium_alerts
)

print(
    "Low severity alerts:",
    low_alerts
)

print("=================================")