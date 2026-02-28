import os

_PRIMARY_LOG_FILE = r"C:\ProgramData\SHCS\shcs.log"
_FALLBACK_LOG_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "shcs.log"
)


def read_last_logs():
    for log_file in [_PRIMARY_LOG_FILE, _FALLBACK_LOG_FILE]:
        try:
            if not os.path.exists(log_file):
                continue

            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()

            lines.reverse()

            return "".join(lines)

        except (OSError, PermissionError):
            continue

    return ""

