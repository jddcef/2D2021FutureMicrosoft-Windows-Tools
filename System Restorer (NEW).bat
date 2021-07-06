echo off
color 03
title System Restorer
cls

:SystemRestore

cls
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
