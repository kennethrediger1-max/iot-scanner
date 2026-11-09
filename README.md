# IoT Network Scanner

FastAPI + Nmap + a single-page Tailwind UI. Finding rules come from the CRC IoT Scan Kit (`app/core/rules.py`).

    python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
    pip install -r requirements-dev.txt
    sudo "$(which python)" -m uvicorn app.main:app --port 8000   # Windows: run from an Administrator terminal
    # open http://127.0.0.1:8000

Run tests: `pip install -r requirements-dev.txt` then `pytest -q tests`. Only scan networks you own or have written permission to scan.

## Build an executable

PyInstaller builds for the OS it runs on, so build on each target OS.

    ./build.sh      # macOS / Linux  -> dist/iot-scanner   (run with sudo)
    build.bat       # Windows        -> dist\iot-scanner.exe (asks for Administrator)

Nmap must still be installed on the machine that runs the executable.
