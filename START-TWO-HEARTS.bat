@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
 echo Node.js is not installed. Install Node.js 24 LTS or newer.
 pause
 exit /b 1
)
if not exist node_modules call npm install
start "Two Hearts Cafe POS" http://localhost:3000
node server.js
