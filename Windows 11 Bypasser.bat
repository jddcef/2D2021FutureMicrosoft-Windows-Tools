echo off
color 03
title Windows 11 Bypasser
cls

REG ADD HKLM\SYSTEM\Setup\LabConfig 
cls
REG ADD HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1
cls
REG ADD HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1
cls
echo Windows 11 TPM And Secure Boot Has Been Disabled! Would You Like To Revert? (Yes/No)
 set /p l=
if "%l%" == "Yes" goto :revert
if "%l%" == "No" goto :exit
cls

:revert
REG ADD HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 0
cls
REG ADD HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 0
cls
echo Windows 11 TPM And Secure Boot Checking Has Been Enabled! Would You Like To Exit? (Yes/No)
 set /p l=
if "%l%" == "Yes" goto :exit
if "%l%" == "No" goto :exit
cls

:exit
exit
cls
exit