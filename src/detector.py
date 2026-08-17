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

    # -----------------------------------
    # Suspicious username detection
    # -----------------------------------

    if (
        username in suspicious_users
        and username not in printed_suspicious_users
    ):

        print(
            f"\n🚨 SUSPICIOUS USERNAME DETECTED: {username}"
        )

        printed_suspicious_users.add(username)

    # -----------------------------------
    # Count failed attempts
    # -----------------------------------

    if source_ip not in failed_attempts:

        failed_attempts[source_ip] = {}

    if username not in failed_attempts[source_ip]:

        failed_attempts[source_ip][username] = 1

    else:

        failed_attempts[source_ip][username] += 1

    # -----------------------------------
    # Store timestamps
    # -----------------------------------

    if source_ip not in failed_attempts_times:

        failed_attempts_times[source_ip] = {}

    if username not in failed_attempts_times[source_ip]:

        failed_attempts_times[source_ip][username] = []

    failed_attempts_times[source_ip][username].append(
        event_time
    )


def detect_bruteforce(
    timestamps,
    threshold=3,
    window_seconds=60
):

    # -----------------------------------
    # Need enough attempts
    # -----------------------------------

    if len(timestamps) < threshold:

        return False

    # -----------------------------------
    # Check time window
    # -----------------------------------

    for i in range(len(timestamps)):

        start_time = timestamps[i]

        for j in range(
            i + threshold - 1,
            len(timestamps)
        ):

            end_time = timestamps[j]

            time_difference = (
                end_time - start_time
            ).total_seconds()

            if time_difference <= window_seconds:

                return True

    return False


def get_severity(count):

    # -----------------------------------
    # Determine alert severity
    # -----------------------------------

    if count >= 5:

        return "HIGH"

    elif count >= 3:

        return "MEDIUM"

    else:

        return "LOW"

def detect_success_after_failures(
    failed_attempts,
    successful_logins,
    threshold=3
):

    alerts = []

    for ip, username in successful_logins.items():

        failed_count = (
            failed_attempts
            .get(ip, {})
            .get(username, 0)
        )

        if failed_count >= threshold:

            alerts.append({
                "source_ip": ip,
                "username": username,
                "failed_attempts": failed_count
            })

    return alerts