@echo off
echo Stopping Erlik Pentest Agent...
cd /d C:\Users\nonec\projects\pentest-agent
docker compose down
taskkill /F /IM uvicorn.exe 2>nul
echo.
echo All stopped.
pause
