"""Launcher used for the packaged executable (also works as `python run.py`).

Starts the web app on a free local port and opens the browser. Nmap itself is NOT bundled
(its license restricts redistribution), so it must be installed separately.
"""
import socket
import threading
import webbrowser

import uvicorn

from app.core.nmap_runner import is_privileged
from app.main import app  # explicit import so PyInstaller bundles the app


def free_port(start: int = 8000) -> int:
    for port in range(start, start + 20):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise SystemExit("No free port found between 8000 and 8019.")


if __name__ == "__main__":
    port = free_port()
    url = f"http://127.0.0.1:{port}"
    print(f"IoT Network Scanner running at {url}  (press Ctrl+C to stop)")
    if not is_privileged():
        print("Note: not running as root/Administrator. In-depth scans need it. "
              "Restart with: sudo ./iot-scanner  (macOS/Linux)")
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=port, log_config=None)
