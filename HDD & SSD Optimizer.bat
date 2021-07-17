echo off
color F0
title HDD & SSD Optimizer
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
echo Welcome to the HDD and SSD Optimizer!
timeout 3 > nul

:question 
echo Type "ssd" For SSD Optimizations.
echo ---------------------------------
echo Type "hdd" For HDD Optimizations.
echo ---------------------------------
echo Type "assist" if you Don't Know Which Drive.
echo --------------------------------------------
echo Type "exit" To Exit.
echo --------------------------------------------
echo What Would You Like?
set /p a=
if "%a%" == "ssd" goto :ssd
if "%a%" == "hdd" goto :hdd
if "%a%" == "assist" goto :assist
if "%a%" == "exit" goto :exit


:assist
echo Open Start Go To Windows Administrative Tools, Click On Defragment and Optimize Drives.
echo And ypu Will Know Which Drive.
echo Would You Like To Exit?
set /p a=
if "%a%" == "yes" goto :exit
if "%a%" == "no" goto :question

:hdd
fsutil behavior set disabledeletenotify 1 > nul
fsutil behavior set mftzone 2 > nul 
fsutil behavior set disablelastaccess 1 > nul
fsutil behavior set memoryusage 2 > nul
fsutil behavior set encryptpagingfile 0 > nul
goto :exit

:ssd
fsutil behavior set disabledeletenotify 0 > nul
fsutil behavior set mftzone 2 > nul 
fsutil behavior set disablelastaccess 1 > nul
fsutil behavior set memoryusage 2 > nul
fsutil behavior set encryptpagingfile 0 > nul
goto :exit

:exit
exit
