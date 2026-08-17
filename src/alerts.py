import json
from datetime import datetime


# -----------------------------------
# Save and display normal alert
# -----------------------------------

def show_alert(
    ip,
    username,
    count,
    severity,
    alert_type="Possible brute-force attack"
):

    alert_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    alert = {
        "timestamp": alert_time,
        "alert_type": alert_type,
        "severity": severity,
        "source_ip": ip,
        "username": username,
        "failed_attempts": count
    }

    # -----------------------------------
    # Display alert
    # -----------------------------------

    print("\n======== SECURITY ALERT ========")

    print(
        "Alert time:",
        alert_time
    )

    print(
        "Alert type:",
        alert_type
    )

    print(
        "Severity:",
        severity
    )

    print(
        "Source IP:",
        ip
    )

    print(
        "Target username:",
        username
    )

    print(
        "Failed attempts:",
        count
    )

    print(
        "================================"
    )


    # -----------------------------------
    # Save JSON alert
    # -----------------------------------

    with open(
        "reports/alerts.json",
        "a"
    ) as report:

        report.write(
            json.dumps(alert) + "\n"
        )


    # -----------------------------------
    # Save text alert
    # -----------------------------------

    with open(
        "reports/alerts.txt",
        "a"
    ) as report:

        report.write(
            "\n======== SECURITY ALERT ========\n"
        )

        report.write(
            f"Alert time: {alert_time}\n"
        )

        report.write(
            f"Alert type: {alert_type}\n"
        )

        report.write(
            f"Severity: {severity}\n"
        )

        report.write(
            f"Source IP: {ip}\n"
        )

        report.write(
            f"Target username: {username}\n"
        )

        report.write(
            f"Failed attempts: {count}\n"
        )

        report.write(
            "================================\n"
        )


# -----------------------------------
# Critical brute-force alert
# -----------------------------------

def show_critical_bruteforce_alert(
    ip,
    username,
    count,
    time_difference
):

    print("\n🚨 CRITICAL ALERT")

    print(
        "Possible brute-force attack detected!"
    )

    print(
        "Source IP:",
        ip
    )

    print(
        "Target username:",
        username
    )

    print(
        "Failed attempts:",
        count
    )

    print(
        "Time window:",
        time_difference
    )

    print(
        "================================"
    )


# -----------------------------------
# Successful login after failures
# -----------------------------------

def show_success_after_failed_alert(
    ip,
    username,
    count
):

    print("\n🚨 CRITICAL ALERT")

    print(
        "Possible brute-force attack "
        "followed by successful login!"
    )

    print(
        "Source IP:",
        ip
    )

    print(
        "Target username:",
        username
    )

    print(
        "Failed attempts before success:",
        count
    )

    print(
        "================================"
    )