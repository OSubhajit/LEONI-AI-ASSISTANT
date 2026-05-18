@echo off
title LEONI v6.0
echo  Starting LEONI...
start "LEONI Backend" cmd /k "python backend\app.py"
timeout /t 2 /nobreak >nul
start "" "http://localhost:5000"
echo  LEONI running at http://localhost:5000
