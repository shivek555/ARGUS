@echo off
rem ARGUS launcher (Windows): double-click, or run "run.bat [port]".
rem First run installs the locked Python packages and builds the dashboard; later runs just start.
rem Set ARGUS_NO_BROWSER=1 to skip opening the browser. Delete dashboard\dist to force a rebuild.
setlocal
title ARGUS
cd /d "%~dp0"
set "PORT=%~1"
if "%PORT%"=="" set "PORT=8000"

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.11 and try again.
  pause
  exit /b 1
)

python -c "import fastapi, uvicorn, sklearn" >nul 2>nul
if errorlevel 1 (
  echo Installing Python packages ^(first run only^)...
  python -m pip install -r requirements.txt -c constraints.txt
  if errorlevel 1 (
    echo pip install failed.
    pause
    exit /b 1
  )
)

if not exist "dashboard\dist\index.html" (
  where npm >nul 2>nul
  if errorlevel 1 (
    echo Node.js ^(npm^) was not found. It is needed once, to build the dashboard.
    pause
    exit /b 1
  )
  echo Building the dashboard ^(first run only^)...
  call npm --prefix dashboard ci
  if errorlevel 1 (
    pause
    exit /b 1
  )
  call npm --prefix dashboard run build
  if errorlevel 1 (
    pause
    exit /b 1
  )
)

powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort %PORT% -State Listen -ErrorAction SilentlyContinue) { exit 1 }"
if errorlevel 1 (
  echo Port %PORT% is already in use ^(is ARGUS already running?^).
  echo Close the other ARGUS window, or start on another port: run.bat 8001
  pause
  exit /b 1
)

echo Starting ARGUS on http://127.0.0.1:%PORT%  ^(about 15 s^). Close this window or press Ctrl+C to stop.
if not "%ARGUS_NO_BROWSER%"=="1" (
  start "" /b powershell -NoProfile -WindowStyle Hidden -Command "for($i=0;$i -lt 60;$i++){try{Invoke-WebRequest -UseBasicParsing http://127.0.0.1:%PORT%/api/health -TimeoutSec 2 | Out-Null; Start-Process 'http://127.0.0.1:%PORT%/#/demo'; break}catch{Start-Sleep 2}}"
)
python -m argus.api --port %PORT%
echo.
echo ARGUS stopped.
pause
