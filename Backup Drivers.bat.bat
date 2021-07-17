echo off
color 03
title Backup Drivers
cls

:wincheck
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Microsoft Windows XP" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows Vista" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows 7" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows 8" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows 8.1" >nul 2>nul
if %errorlevel% EQU 0 (goto :nosupport) (else :start)

:nosupport
echo Your Windows Version is not Support This Script.
echo Supported OS is: Windows 10 Higher OS.
timeout 2 > nul 
cls
goto :exit

:start
md DriversBackup
Dism /Online /Export-Driver /Destination:%~dp0\DriversBackup
cls
echo.The operation completed successfully, Would You Like To Exit?
set /p l=
if "%l%" == "yes" goto :exit
if "%l%" == "no" goto :exit
cls

:exit
exit
cls
exit
