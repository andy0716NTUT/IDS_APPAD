@echo off
rem APPAD 本地 Demo 一鍵啟動（雙擊即可）
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_demo.ps1"
pause
