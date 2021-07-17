echo off
color 03
title Background Cooler
cls

:winxpcheck
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Microsoft Windows XP" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows Vista" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows 7" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows 8" >nul 2>nul
%SystemRoot%\System32\reg.exe query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName | find "Windows 8.1" >nul 2>nul
if %errorlevel% EQU 0 goto :nosupport else 

:starr
echo Welcome To Background Cooler!
timeout 2 > nul
cls

echo Perparing To Disable Background Apps...
timeout 2 > nul 
cls

Reg Add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f

echo Background Apps Has Been Disabled!
timeout 2 > nul 
cls

echo Would You Like To Revert? (Yes/No)
set /p a=
if "%a%" == "Yes" goto :revert
if "%a%" == "No" goto :exit

:revert
Reg Add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 0 /f
cls
echo Background Apps Has Been Enabled! Would You Like To Exit? (Yes/No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :exit

:nosupport
echo Your Windows Version is not Support This Script.
echo Supported OS is: Windows 10 Higher OS.
timeout 2 > nul 
cls
goto :exit

:exit 
exit
cls
exit
