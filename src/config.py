# -----------------------------------
# Log configuration
# -----------------------------------

LOG_FILE = "logs/auth.log"


# -----------------------------------
# Suspicious usernames
# -----------------------------------

SUSPICIOUS_USERS = {
    "root",
    "admin",
    "administrator",
    "test",
    "guest"
}


# -----------------------------------
# Brute-force detection
# -----------------------------------

BRUTE_FORCE_THRESHOLD = 3

BRUTE_FORCE_WINDOW = 60