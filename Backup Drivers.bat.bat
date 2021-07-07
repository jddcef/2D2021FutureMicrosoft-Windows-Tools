echo off
color 03
title Backup Drivers
cls

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
