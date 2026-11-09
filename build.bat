@echo off
REM Build a single-file executable for Windows. Output: dist\iot-scanner.exe
python -m venv .venv || goto :err
call .venv\Scripts\activate || goto :err
pip install -r requirements.txt pyinstaller || goto :err
REM --uac-admin makes Windows prompt for Administrator rights when the exe starts
pyinstaller --onefile --name iot-scanner --uac-admin ^
  --add-data "app\static;app\static" ^
  --collect-submodules uvicorn --hidden-import psutil ^
  run.py || goto :err
echo Built dist\iot-scanner.exe
exit /b 0
:err
echo Build failed.
exit /b 1
