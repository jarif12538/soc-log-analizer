from src.parser import parse_log_line

from src.detector import (
    process_failed_login,
    detect_bruteforce,
    get_severity,
    detect_success_after_failures
)

from src.alerts import (
    show_alert,
    show_critical_bruteforce_alert,
    show_success_after_failed_alert
)

from src.config import (
    LOG_FILE,
    SUSPICIOUS_USERS,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW
)


# -----------------------------------
# Storage
# -----------------------------------

failed_attempts = {}
failed_attempts_times = {}

successful_logins = {}

unique_ips = set()
printed_suspicious_users = set()


# -----------------------------------
# Read log file
# -----------------------------------

with open(LOG_FILE, "r") as file:

    for line in file:

        event = parse_log_line(line)

        if event is None:
            continue

        username = event["username"]
        source_ip = event["source_ip"]

        # Track unique IP
        unique_ips.add(source_ip)


        # -----------------------------------
        # Failed login
        # -----------------------------------

        if event["event_type"] == "failed_login":

            process_failed_login(
                event,
                failed_attempts,
                failed_attempts_times,
                SUSPICIOUS_USERS,
                printed_suspicious_users
            )


        # -----------------------------------
        # Successful login
        # -----------------------------------

        elif event["event_type"] == "successful_login":

            successful_logins[source_ip] = username

            print("\nSuccessful login detected:")

            print(
                "Source IP:",
                source_ip
            )

            print(
                "Target username:",
                username
            )

            print(
                "Failed attempts:",
                failed_attempts
                .get(source_ip, {})
                .get(username, 0)
            )


# -----------------------------------
# Generate severity alerts
# -----------------------------------

total_failed_attempts = 0

high_alerts = 0
medium_alerts = 0
low_alerts = 0


for ip, users in failed_attempts.items():

    for username, count in users.items():

        total_failed_attempts += count

        severity = get_severity(count)

        if severity == "HIGH":

            high_alerts += 1

        elif severity == "MEDIUM":

            medium_alerts += 1

        else:

            low_alerts += 1


        # -----------------------------------
        # SAVE ALERT
        # -----------------------------------

        show_alert(
            ip,
            username,
            count,
            severity
        )


# -----------------------------------
# Brute-force time window detection
# -----------------------------------

print("\n====== TIME WINDOW ANALYSIS ======")


for ip, users in failed_attempts_times.items():

    for username, timestamps in users.items():

        if len(timestamps) < 2:
            continue


        # Check whether brute force occurred

        is_bruteforce = detect_bruteforce(
            timestamps,
            BRUTE_FORCE_THRESHOLD,
            BRUTE_FORCE_WINDOW
        )


        first_attempt = timestamps[0]
        last_attempt = timestamps[-1]

        time_difference = (
            last_attempt - first_attempt
        )


        print(
            "\nSource IP:",
            ip
        )

        print(
            "Target username:",
            username
        )

        print(
            "Failed attempts:",
            len(timestamps)
        )

        print(
            "Time window:",
            time_difference
        )


        # -----------------------------------
        # Critical brute-force alert
        # -----------------------------------

        if is_bruteforce:

            show_critical_bruteforce_alert(
                ip,
                username,
                len(timestamps),
                time_difference
            )


# -----------------------------------
# Successful login after failed attempts
# -----------------------------------

print(
    "\n====== SUCCESS AFTER FAILED LOGINS ======"
)


success_after_failure_alerts = (
    detect_success_after_failures(
        failed_attempts,
        successful_logins,
        BRUTE_FORCE_THRESHOLD
    )
)


for alert in success_after_failure_alerts:

    show_success_after_failed_alert(
        alert["source_ip"],
        alert["username"],
        alert["failed_attempts"]
    )


# -----------------------------------
# SOC Summary
# -----------------------------------

print(
    "\n========== SOC SUMMARY =========="
)


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


print(
    "================================="
)