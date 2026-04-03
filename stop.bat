@echo off
echo Stopping Erlik Pentest Agent...
cd /d "%~dp0"
docker compose down
taskkill /F /IM uvicorn.exe 2>nul
echo.
echo All stopped.
pause
