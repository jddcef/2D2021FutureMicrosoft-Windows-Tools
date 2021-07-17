echo off
color 03
title System Restorer
cls

:wincheck
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Microsoft Windows XP" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows Vista" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows 7" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows 8" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows 8.1" >nul 2>nul
if %errorlevel% EQU 0 (goto :nosupport) (else :SystemRestore)

:nosupport
echo Your Windows Version is not Support This Script.
echo Supported OS is: Windows 10 Higher OS.
timeout 2 > nul 
cls
goto :exit

:SystemRestore
echo.System Restore
echo.
echo.	ID	Option
echo.
echo.	1	Create a restore point
echo.	2	Restore Windows if you created a restore point
echo.	3	Exit
echo.
choice /c:123 /n /m "Select ID for Continue : "

if %errorlevel% EQU 1 goto Checkpoint-Computer
if %errorlevel% EQU 2 goto Restore-Computer
if %errorlevel% EQU 3 goto exit
:: --------------------------------------------------

:Checkpoint-Computer
cls
powershell.exe -ExecutionPolicy Bypass -Command "& '%~dp0data\scripts\Checkpoint-Computer.ps1'"
cls
echo.The operation completed successfully.
pause
goto SystemRestore
:: --------------------------------------------------

:Restore-Computer
cls
echo.WARNING: The Computer needs to reboot and take some time to complete this process.
choice /c YN /n /m "Are you sure? (Y/N): "
if %errorlevel% EQU 1 powershell.exe -ExecutionPolicy Bypass -Command "& '%~dp0data\scripts\Restore-Computer.ps1'"
if %errorlevel% EQU 2 goto Menu
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto restart
if %errorlevel% EQU 2 goto exit

:restart
shutdown /r

:exit
exit
