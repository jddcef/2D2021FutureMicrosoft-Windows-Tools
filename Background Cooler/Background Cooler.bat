echo off
color 03
title Background Cooler
cls

echo Welcome To Win11BackgroundCooler!
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


:exit 
exit
cls
exit