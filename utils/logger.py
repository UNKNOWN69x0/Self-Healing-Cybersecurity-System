import os
from datetime import datetime

_PRIMARY_LOG_DIR = r"C:\ProgramData\SHCS"
_FALLBACK_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


def _get_log_file():
    for log_dir in [_PRIMARY_LOG_DIR, _FALLBACK_LOG_DIR]:
        try:
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, "shcs.log")
            # Verify we can write to this location
            with open(log_path, "a", encoding="utf-8") as f:
                f.flush()
            return log_path
        except (OSError, PermissionError):
            continue
    return None


def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"{timestamp} - {message}"

    print(log_line)

    try:
        log_file = _get_log_file()
        if log_file:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
                f.flush()
    except Exception as e:
        print(f"[LOGGER ERROR] {e}")
