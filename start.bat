@echo off
echo ========================================
echo   ERLIK PENTEST AGENT - STARTUP
echo ========================================
echo.

:: 1. Start Docker containers
echo [1/3] Starting Docker containers...
cd /d "%~dp0"
docker compose up -d
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Docker failed! Make sure Docker Desktop is running first.
    echo Right-click Docker Desktop icon in system tray and click "Restart"
    pause
    exit /b 1
)
echo      Containers started OK
echo.

:: 2. Wait for services
echo [2/3] Waiting for services to be ready...
timeout /t 5 /nobreak >nul

:: 3. Start FastAPI server
echo [3/3] Starting FastAPI server...
cd /d "%~dp0"
call .venv\Scripts\activate
start "Erlik Server" cmd /k ".venv\Scripts\activate && python -m uvicorn orchestrator.main:app --host 0.0.0.0 --port 8002 --reload"

:: 4. Wait and open browser
timeout /t 4 /nobreak >nul
echo.
echo ========================================
echo   ALL RUNNING! Opening dashboard...
echo ========================================
echo.
echo   Dashboard:  http://localhost:8002
echo   Juice Shop: http://localhost:3000
echo   ZAP API:    http://localhost:8090
echo.
echo   To stop: docker compose down
echo ========================================
start http://localhost:8002
pause
