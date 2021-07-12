echo off
color 03
title Windows Cleaner
cls
 
Dism /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
for /D %%x in ("%USERPROFILES%\*") do (
	del /F /Q "%%x\Documents\*.tmp" 2>NUL
	del /F /Q "%%x\My Documents\*.tmp" 2>NUL
	del /F /S /Q "%%x\*.blf" 2>NUL
	del /F /S /Q "%%x\*.regtrans-ms" 2>NUL
	del /F /S /Q "%%x\AppData\LocalLow\Sun\Java\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Google\Chrome\User Data\Default\Cache\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Google\Chrome\User Data\Default\JumpListIconsOld\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Google\Chrome\User Data\Default\JumpListIcons\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Google\Chrome\User Data\Default\Local Storage\http*.*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Google\Chrome\User Data\Default\Media Cache\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Microsoft\Internet Explorer\Recovery\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Microsoft\Terminal Server Client\Cache\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Microsoft\Windows\Caches\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Microsoft\Windows\Explorer\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Microsoft\Windows\History\low\*" /AH 2>NUL
	del /F /S /Q "%%x\AppData\Local\Microsoft\Windows\INetCache\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Microsoft\Windows\WER\ReportArchive\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Microsoft\Windows\WER\ReportQueue\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Microsoft\Windows\WebCache\*" 2>NUL
	del /F /S /Q "%%x\AppData\Local\Temp\*" 2>NUL
	del /F /S /Q "%%x\AppData\Roaming\Adobe\Flash Player\*" 2>NUL
	del /F /S /Q "%%x\AppData\Roaming\Macromedia\Flash Player\*" 2>NUL
	del /F /S /Q "%%x\AppData\Roaming\Microsoft\Windows\Recent\*" 2>NUL
	del /F /S /Q "%%x\Application Data\Adobe\Flash Player\*" 2>NUL
	del /F /S /Q "%%x\Application Data\Macromedia\Flash Player\*" 2>NUL
	del /F /S /Q "%%x\Application Data\Microsoft\Dr Watson\*" 2>NUL
	del /F /S /Q "%%x\Application Data\Microsoft\Windows\WER\ReportArchive\*" 2>NUL
	del /F /S /Q "%%x\Application Data\Microsoft\Windows\WER\ReportQueue\*" 2>NUL
	del /F /S /Q "%%x\Application Data\Sun\Java\*" 2>NUL
	del /F /S /Q "%%x\Local Settings\Application Data\ApplicationHistory\*" 2>NUL
	del /F /S /Q "%%x\Local Settings\Application Data\Google\Chrome\User Data\Default\Cache\*" 2>NUL
	del /F /S /Q "%%x\Local Settings\Application Data\Google\Chrome\User Data\Default\JumpListIconsOld\*" 2>NUL
	del /F /S /Q "%%x\Local Settings\Application Data\Google\Chrome\User Data\Default\JumpListIcons\*" 2>NUL
	del /F /S /Q "%%x\Local Settings\Application Data\Google\Chrome\User Data\Default\Local Storage\http*.*" 2>NUL
	del /F /S /Q "%%x\Local Settings\Application Data\Google\Chrome\User Data\Default\Media Cache\*" 2>NUL
	del /F /S /Q "%%x\Local Settings\Application Data\Microsoft\Dr Watson\*" 2>NUL
	del /F /S /Q "%%x\Local Settings\Application Data\Microsoft\Internet Explorer\Recovery\*" 2>NUL
	del /F /S /Q "%%x\Local Settings\Application Data\Microsoft\Terminal Server Client\Cache\*" 2>NUL
	del /F /S /Q "%%x\Local Settings\Temp\*" 2>NUL
	del /F /S /Q "%%x\Local Settings\Temporary Internet Files\*" 2>NUL
	del /F /S /Q "%%x\Recent\*" 2>NUL
REM if exist %SystemDrive%\Windows.old\ (
	REM takeown /F %SystemDrive%\Windows.old\* /R /A /D Y
	REM echo y| cacls %SystemDrive%\Windows.old\*.* /C /T /grant administrators:F
	REM rmdir /S /Q %SystemDrive%\Windows.old\
 REM if exist %SystemDrive%\$Windows.~BT\ (
	REM takeown /F %SystemDrive%\$Windows.~BT\* /R /A
	REM icacls %SystemDrive%\$Windows.~BT\*.* /T /grant administrators:F
	REM rmdir /S /Q %SystemDrive%\$Windows.~BT\
 REM if exist %SystemDrive%\$Windows.~WS (
	REM takeown /F %SystemDrive%\$Windows.~WS\* /R /A
	REM icacls %SystemDrive%\$Windows.~WS\*.* /T /grant administrators:F
	REM rmdir /S /Q %SystemDrive%\$Windows.~WS\
 del /F /S /Q "%WINDIR%\TEMP\*" 2>NUL
rmdir /S /Q %SystemDrive%\Temp 2>NUL
for %%i in (bat,cmd,txt,log,jpg,jpeg,tmp,temp,bak,backup,exe) do (
	del /F /Q "%SystemDrive%\*.%%i" 2>NUL
 for %%i in (NVIDIA,ATI,AMD,Dell,Intel,HP) do (
	rmdir /S /Q "%SystemDrive%\%%i" 2>NUL
cls
if exist "%ProgramFiles%\Nvidia Corporation\Installer2" rmdir /s /q "%ProgramFiles%\Nvidia Corporation\Installer2"
if exist "%ALLUSERSPROFILE%\NVIDIA Corporation\NetService" del /f /q "%ALLUSERSPROFILE%\NVIDIA Corporation\NetService\*.exe"

if exist %SystemDrive%\MSOCache rmdir /S /Q %SystemDrive%\MSOCache

if exist %SystemDrive%\i386 rmdir /S /Q %SystemDrive%\i386

if exist %SystemDrive%\RECYCLER rmdir /s /q %SystemDrive%\RECYCLER
if exist %SystemDrive%\$Recycle.Bin rmdir /s /q %SystemDrive%\$Recycle.Bin

%REG% delete "HKCU\SOFTWARE\Classes\Local Settings\Muicache" /f

echo. >> %LOGPATH%\%LOGFILE%
if exist "%ALLUSERSPROFILE%\Microsoft\Windows\WER\ReportArchive" rmdir /s /q "%ALLUSERSPROFILE%\Microsoft\Windows\WER\ReportArchive"
if exist "%ALLUSERSPROFILE%\Microsoft\Windows\WER\ReportQueue" rmdir /s /q "%ALLUSERSPROFILE%\Microsoft\Windows\WER\ReportQueue"

if exist "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Scans\History\Results\Quick" rmdir /s /q "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Scans\History\Results\Quick"
if exist "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Scans\History\Results\Resource" rmdir /s /q "%ALLUSERSPROFILE%\Microsoft\Windows Defender\Scans\History\Results\Resource"

if exist "%ALLUSERSPROFILE%\Microsoft\Search\Data\Temp" rmdir /s /q "%ALLUSERSPROFILE%\Microsoft\Search\Data\Temp"

del /F /Q %WINDIR%\*.log 2>NUL
del /F /Q %WINDIR%\*.txt 2>NUL
del /F /Q %WINDIR%\*.bmp 2>NUL
del /F /Q %WINDIR%\*.tmp 2>NUL
rmdir /S /Q %WINDIR%\Web\Wallpaper\Dell 2>NUL
cls
if exist "%ProgramFiles%\NVIDIA Corporation\Installer" rmdir /s /q "%ProgramFiles%\NVIDIA Corporation\Installer" 2>NUL
if exist "%ProgramFiles%\NVIDIA Corporation\Installer2" rmdir /s /q "%ProgramFiles%\NVIDIA Corporation\Installer2" 2>NUL
if exist "%ProgramFiles(x86)%\NVIDIA Corporation\Installer" rmdir /s /q "%ProgramFiles(x86)%\NVIDIA Corporation\Installer" 2>NUL
if exist "%ProgramFiles(x86)%\NVIDIA Corporation\Installer2" rmdir /s /q "%ProgramFiles(x86)%\NVIDIA Corporation\Installer2" 2>NUL
if exist "%ProgramData%\NVIDIA Corporation\Downloader" rmdir /s /q "%ProgramData%\NVIDIA Corporation\Downloader" 2>NUL
if exist "%ProgramData%\NVIDIA\Downloader" rmdir /s /q "%ProgramData%\NVIDIA\Downloader" 2>NUL
cls
if %WIN_VER_NUM% lss 6.0 (
	del /f /q %WINDIR%\System32\dllcache\tourstrt.exe 2>NUL
	del /f /q %WINDIR%\System32\dllcache\tourW.exe 2>NUL
	del /f /q %WINDIR%\System32\tourstart.exe
	rmdir /S /Q %WINDIR%\Help\Tours 2>NUL
cls
if %WIN_VER_NUM% lss 6.0 %REG% add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Applets\Tour" /v RunCount /t REG_DWORD /d 00000000 /f

echo %WIN_VER% | findstr /i /c:"server" >NUL
if %ERRORLEVEL%==0 (
	echo.
	echo  ! Server operating system detected.
	echo    Removing built-in media files ^(.wav, .midi, etc^)...
	echo.
	echo.  && echo  ! Server operating system detected. Removing built-in media files ^(.wave, .midi, etc^)... && echo.

	:: 2. Take ownership of the files so we can actually delete them. By default even Administrators have Read-only rights.
	echo    Taking ownership of %WINDIR%\Media in order to delete files... && echo.
	echo    Taking ownership of %WINDIR%\Media in order to delete files...  && echo.
	if exist %WINDIR%\Media takeown /f %WINDIR%\Media /r /d y 2>NUL && echo.
	if exist %WINDIR%\Media icacls %WINDIR%\Media /grant administrators:F /t  && echo.
cls
	:: 3. Do the cleanup
	rmdir /S /Q %WINDIR%\Media 2>NUL
cls      

:: JOB: Windows CBS logs
::      these only exist on Vista and up, so we look for "Microsoft", and assuming we don't find it, clear out the folder
echo %WIN_VER% | findstr /v /i /c:"Microsoft" >NUL && del /F /Q %WINDIR%\logs\CBS\* 2>NUL

:: JOB: Windows XP/2003: Cleanup hotfix uninstallers. They use a lot of space so removing them is beneficial.
:: Really we should use a tool that deletes their corresponding registry entries, but oh well.

::  0. Check Windows version.
::    We simply look for "Microsoft" in the version name, because only versions prior to Vista had the word "Microsoft" as part of their version name
::    Everything after XP/2k3 drops the "Microsoft" prefix
if %WIN_VER_NUM% lss 6.0 (
	:: 1. If we made it here we're doing the cleanup. Notify user and log it.
	echo.
	echo  ! Windows XP/2003 detected.
	echo    Removing hotfix uninstallers...
	echo.
	echo.  && echo  ! Windows XP/2003 detected. Removing hotfix uninstallers...
        pushd %WINDIR%
	dir /A:D /B $*$ > "%TEMP%\hotfix_nuke_list.txt" 2>NUL
        for /f %%i in ("%TEMP%\hotfix_nuke_list.txt") do (
		rmdir /S /Q %%i 2>NUL
  del "%TEMP%\hotfix_nuke_list.txt"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f
takeown /f "%WINDIR%\winsxs\pending.xml" /a
icacls "%WINDIR%\winsxs\pending.xml" /grant:r Administrators:F /c
del "%WINDIR%\winsxs\pending.xml" /s /f /q
cls
del "C:\$Recycle.bin" /s /f /q
del "D:\$Recycle.bin" /s /f /q
del "Z:\$Recycle.bin" /s /f /q
del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat" /s /f /q
del "%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr*.dat" /s /f /q
del "%LocalAppData%\Microsoft\Windows\WebCache" /s /f /q
del "%LocalAppData%\Temp" /s /f /q
del "%ProgramData%\USOPrivate\UpdateStore" /s /f /q
del "%ProgramData%\USOShared\Logs" /s /f /q
del "%temp%" /s /f /q
del "%WINDIR%\Logs" /s /f /q
del "%WINDIR%\Installer\$PatchCache$" /s /f /q
del "%WINDIR%\SoftwareDistribution\Download" /s /f /q
del "%WINDIR%\System32\LogFiles" /s /f /q
del "%WINDIR%\System32\winevt\Logs" /s /f /q
del "%WINDIR%\Temp" /s /f /q
del "%WINDIR%\WinSxS\Backup" /s /f /q
cls
Dism /get-mountedwiminfo
Dism /cleanup-mountpoints
Dism /cleanup-wim
Dism /Online /Cleanup-Image /StartComponentCleanup
cls
echo The Cleaner Has been cleaned Windows! Would You Like To Exit? (Yes/No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :exit
