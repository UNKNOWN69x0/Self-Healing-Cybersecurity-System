import os
from datetime import datetime

LOG_DIR = r"C:\ProgramData\SHCS"
LOG_FILE = os.path.join(LOG_DIR, "shcs.log")


def log_event(message):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"{timestamp} - {message}\n"

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
            f.flush()  # force write immediately

    except Exception as e:
        # Last-resort fallback (NEVER silent)
        print(f"[LOGGER ERROR] {e}")
