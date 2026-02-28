<<<<<<< HEAD
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
            f.flush()  # 🔑 force write immediately

    except Exception as e:
        # Last-resort fallback (NEVER silent)
        print(f"[LOGGER ERROR] {e}")


=======
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "shcs.log")


def log_event(message):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - {message}\n")
    except Exception:
        pass

>>>>>>> ff48c825f9fd64ae919885467895d38972d81c36
