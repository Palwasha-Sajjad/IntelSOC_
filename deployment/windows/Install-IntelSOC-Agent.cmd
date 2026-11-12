@echo off
setlocal

rem Run the existing IntelSOC Windows installer with administrator privileges.
set "INTELSOC_INSTALLER=%~dp0Install-IntelSOC-Agent.ps1"

if not exist "%INTELSOC_INSTALLER%" (
    echo ERROR: Install-IntelSOC-Agent.ps1 must be in the same folder.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $env:INTELSOC_INSTALLER + '"')) -Verb RunAs -Wait -PassThru; exit $p.ExitCode } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }"
set "INTELSOC_RESULT=%ERRORLEVEL%"

if not "%INTELSOC_RESULT%"=="0" (
    echo.
    echo IntelSOC installation did not complete successfully. Exit code: %INTELSOC_RESULT%
) else (
    echo.
    echo IntelSOC installer finished successfully.
)

pause
exit /b %INTELSOC_RESULT%
