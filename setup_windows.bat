@echo off
title LEONI v6.0 Setup
echo.
echo  LEONI v6.0 - Windows Setup
echo  ===========================
echo.
python --version >nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python not found.
    echo  Install Python 3.9+ from https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH"
    pause & exit /b 1
)
echo  [1/3] Python found.
pip install -r backend\requirements.txt
if errorlevel 1 (echo  ERROR: pip install failed. & pause & exit /b 1)
echo.
echo  [2/3] Dependencies installed.
echo.
echo  [3/3] Groq API Key (FREE at console.groq.com - no credit card needed)
set /p GROQ_KEY="  Paste Groq key here (or Enter to skip): "
if not "%GROQ_KEY%"=="" (
    setx GROQ_API_KEY "%GROQ_KEY%" >nul
    echo  Groq key saved.
) else echo  Skipped. Set later in LEONI Settings.
echo.
echo  SETUP COMPLETE! Run START_LEONI.bat to start.
pause
