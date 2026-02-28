from utils.logger import log_event

try:
    from plyer import notification as _plyer_notification
except ImportError:
    _plyer_notification = None

_SEVERITY_ICONS = {
    "INFO": "ℹ",
    "MEDIUM": "⚠",
    "HIGH": "🔴",
    "CRITICAL": "🚨",
}

_SEVERITY_ORDER = ["INFO", "MEDIUM", "HIGH", "CRITICAL"]


def notify_user(title, message, severity="INFO"):
    """Show a desktop toast notification and log the event.

    Falls back to log-only if plyer is unavailable or the notification fails.

    Args:
        title: Notification title string.
        message: Body text of the notification.
        severity: One of 'INFO', 'MEDIUM', 'HIGH', 'CRITICAL'.
    """
    icon = _SEVERITY_ICONS.get(severity, "")
    log_event(f"NOTIFICATION [{severity}] {icon} {title}: {message}")

    if _plyer_notification is not None:
        try:
            _plyer_notification.notify(
                title=f"{icon} {title}",
                message=message,
                app_name="SHCS",
                timeout=5,
            )
        except Exception:
            pass
