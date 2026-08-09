import re
from datetime import datetime
import json


# -----------------------------------
# Alert function
# -----------------------------------

def show_alerts(ip, username, count, severity):
    alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Create structured alert
    alert = {
        "timestamp": alert_time,
        "alert_type": "Possible brute-force attack",
        "severity": severity,
        "source_ip": ip,
        "username": username,
        "failed_attempts": count
    }

    # Display alert in terminal
    print("\n======== SECURITY ALERT ========")
    print("Alert time:", alert_time)
    print("Alert type:", alert["alert_type"])
    print("Severity:", severity)
    print("Source IP:", ip)
    print("Target username:", username)
    print("Failed attempts:", count)
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
Failed attempts: {count}
================================

"""
        )

    # Save JSON alert
    with open("reports/alerts.json", "a") as report:
        report.write(json.dumps(alert) + "\n")


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

failed_attempts = {}
unique_ips = set()
successful_logins = {}

# -----------------------------------
# Read log file
# -----------------------------------

with open(log_file, "r") as file:

    for line in file:

        # -----------------------------------
        # Failed login detection
        # -----------------------------------

        if "Failed password" in line:

            username = re.search(r"for (\w+)", line)
            ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

            if username and ip:

                username = username.group(1)
                source_ip = ip.group(1)

                # Track unique IP
                unique_ips.add(source_ip)

                # Detect suspicious username
                if username in suspicious_users:
                    print(
                        "⚠️ Suspicious username detected:",
                        username
                    )

                # Create IP dictionary
                if source_ip not in failed_attempts:
                    failed_attempts[source_ip] = {}

                # Count attempts
                if username not in failed_attempts[source_ip]:
                    failed_attempts[source_ip][username] = 1

                else:
                    failed_attempts[source_ip][username] += 1


        # -----------------------------------
        # Successful login detection
        # -----------------------------------

        if "Accepted password" in line:

            username = re.search(r"for (\w+)", line)
            ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

            if username and ip:

                username = username.group(1)
                source_ip = ip.group(1)

                # Track unique IP
                unique_ips.add(source_ip)

                print("\nSuccessful login detected:")
                print("Source IP:", source_ip)
                print("Target username:", username)

                print(
                    "Failed attempts:",
                    failed_attempts.get(
                        source_ip,
                        {}
                    ).get(
                        username,
                        0
                    )
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

        # Determine severity
        if count >= 5:
            severity = "HIGH"
            high_alerts += 1

        elif count >= 3:
            severity = "MEDIUM"
            medium_alerts += 1

        else:
            severity = "LOW"
            low_alerts += 1

        # Generate alert
        show_alerts(
            ip,
            username,
            count,
            severity
        )


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