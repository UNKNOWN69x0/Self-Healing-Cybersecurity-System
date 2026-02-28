try:
    import pystray
    from PIL import Image, ImageDraw
    _PYSTRAY_AVAILABLE = True
except ImportError:
    _PYSTRAY_AVAILABLE = False


def _make_icon_image():
    """Create a simple shield icon for the system tray."""
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Draw a filled blue shield shape
    draw.polygon(
        [(size // 2, 4), (size - 4, 14), (size - 4, 36), (size // 2, size - 4), (4, 36), (4, 14)],
        fill=(30, 120, 220, 255),
    )
    return img


def create_tray_icon(on_open_dashboard, on_quit):
    """Create and return a pystray system tray icon.

    Args:
        on_open_dashboard: Callable invoked when 'Open Dashboard' is clicked.
        on_quit: Callable invoked when 'Quit' is clicked.

    Returns:
        A pystray.Icon instance (not yet running), or None if pystray is
        unavailable.
    """
    if not _PYSTRAY_AVAILABLE:
        return None

    def _open(icon, item):
        on_open_dashboard()

    def _quit(icon, item):
        icon.stop()
        on_quit()

    menu = pystray.Menu(
        pystray.MenuItem("Open Dashboard", _open, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit", _quit),
    )

    icon = pystray.Icon(
        "SHCS",
        _make_icon_image(),
        "Self-Healing Cybersecurity System",
        menu,
    )
    return icon
