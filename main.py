import re

def show_alerts(ip, username, count):
    print("\n========security alerts=========")
    print("alert type: possible brute-force attack detected!")
    print("severity: HIGH")
    print("Source IP:", ip)
    print("Target username:", username)
    print("Failed attempts:", count)
    print("=================================\n")

log_file = "logs/auth.log"

failed_attempts = {}

with open(log_file, "r") as file:
    for line in file:

        if "Failed password" in line:
            username = re.search(r"for (\w+)", line)
            ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

            if username and ip:
                username = username.group(1)
                source_ip = ip.group(1)

                if source_ip not in failed_attempts:
                    failed_attempts[source_ip] = {}

                if username not in failed_attempts[source_ip]:
                    failed_attempts[source_ip][username] = 1
                else:
                    failed_attempts[source_ip][username] += 1

        if "Accepted password" in line:
            username = re.search(r"for (\w+)", line)
            ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

            if username and ip:
                username = username.group(1)
                source_ip = ip.group(1)

                print("Successful login detected:")
                print("Source IP:", source_ip)
                print("Target username:", username)
                print(
                    "Failed attempts:",
                    failed_attempts.get(source_ip, {}).get(username, 0)
                )
                print("\n")

for ip, users in failed_attempts.items():
    for username, count in users.items():

        if count >= 3:
            show_alerts(ip, username, count)