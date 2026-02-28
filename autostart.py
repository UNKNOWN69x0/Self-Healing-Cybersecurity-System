import os
import sys


def add_to_startup():
    """Register the SHCS agent to run at Windows logon via Task Scheduler."""
    exe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "main.exe")
    cmd = (
        f'schtasks /create /tn "SHCS Agent" '
        f'/tr "\\"{exe_path}\\" --agent" '
        f'/sc onlogon /rl highest /f'
    )
    result = os.system(cmd)
    if result == 0:
        print("SHCS Agent task created successfully.")
    else:
        print("Failed to create SHCS Agent task. Run as Administrator.", file=sys.stderr)


if __name__ == "__main__":
    add_to_startup()
