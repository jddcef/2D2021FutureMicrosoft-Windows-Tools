echo off
color 03
title Windows Activator
cls

echo Loading Data For Activations...
timeout 2 > nul     
cls

echo Data Has Succesfully Loaded.
timeout 2 > nul     
cls

:question
echo Choose Your Windows Versions For Activation:
echo --------------------------------------------
echo Type "win10" For Windows 10 Activation Or Lower OS.
echo ------------------------------------------------
echo Type "win11" For Windows 11 Activation (People Who Have Windows 11)
echo ----------------------------------------------------
echo Type "office" For Microsoft Office Products Activations.
echo -------------------------------------------------------
echo Type "exit" To Exit
echo -------------------------------------------------------
echo  Type "office 365" For Office 365 Activations.
echo ------------------------------------------------------
echo Type "check activation" To Check Windows Activation.
echo -----------------------------------------------------
echo What Would You Like?
set /p a=
if "%a%" == "win10" goto :win10
if "%a%" == "win11" goto :win11
if "%a%" == "office" goto :office
if "%a%" == "exit" goto :exit
if "%a%" == "office 365" goto :office365
if "%a%" == "check activation" goto :CheckWindowsactivation

:CheckWindowsactivation
cls
cd /d %~dp0
setLocal EnableDelayedExpansion
if exist "%Windir%\Sysnative\sppsvc.exe" set SysPath=%Windir%\Sysnative
if exist "%Windir%\System32\sppsvc.exe"  set SysPath=%Windir%\System32

echo  Windows Status:
echo =================
ver
cscript //nologo %SysPath%\slmgr.vbs /dli
cscript //nologo %SysPath%\slmgr.vbs /xpr

echo.
echo.
call :msgBox ok

echo Would You Like To Exit?
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :question
office365
title Activate Office 365 for FREE - MSGuides.com&cls&echo ============================================================================&echo Operation: Activating Microsoft software products for FREE without software&echo ============================================================================&echo.&echo Supported Products: Office 365 (x86-x64)&echo.&echo.&(if exist "%ProgramFiles%\Microsoft Office\Office16\ospp.vbs" cd /d "%ProgramFiles%\Microsoft Office\Office16")&(if exist "%ProgramFiles(x86)%\Microsoft Office\Office16\ospp.vbs" cd /d "%ProgramFiles(x86)%\Microsoft Office\Office16")&(for /f %%x in ('dir /b ..\root\Licenses16\proplusvl_kms*.xrm-ms') do cscript ospp.vbs /inslic:"..\root\Licenses16\%%x" >nul)&(for /f %%x in ('dir /b ..\root\Licenses16\proplusvl_mak*.xrm-ms') do cscript ospp.vbs /inslic:"..\root\Licenses16\%%x" >nul)&echo.&echo ============================================================================&echo Activating your Office 365...&cscript //nologo slmgr.vbs /ckms >nul&cscript //nologo ospp.vbs /setprt:1688 >nul&cscript //nologo ospp.vbs /unpkey:WFG99 >nul&cscript //nologo ospp.vbs /unpkey:DRTFM >nul&cscript //nologo ospp.vbs /unpkey:BTDRB >nul&cscript //nologo ospp.vbs /inpkey:XQNVK-8JYDB-WJ9W3-YJ8YR-WFG99 >nul&set i=1
:server
if %i%==1 set KMS=kms7.MSGuides.com
if %i%==2 set KMS=kms8.MSGuides.com
if %i%==3 set KMS=kms9.MSGuides.com
if %i%==4 goto notsupported
cscript //nologo ospp.vbs /sethst:%KMS% >nul&echo ============================================================================&echo.&echo.
cscript //nologo ospp.vbs /act | find /i "successful" && (echo.&echo ============================================================================&echo.&echo || (echo The connection to Bypass server failed! Trying to connect to another one... & echo Please wait... & echo. & echo. & set /a i+=1 & goto server)
explorer "http://MSGuides.com"&goto halt
:notsupported
echo.&echo ============================================================================&echo Sorry! Your Office 365 Version is not supported.&echo Please try installing the latest version here: bit.ly/odt2k16
:halt
echo The Activation Has Been Completed Succesfully. Would You Like To Exit?
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :question

:office
cscript ospp.vbs /inpkey:XQNVK-8JYDB-WJ9W3-YJ8YR-WFG99
cscript ospp.vbs /unpkey:BTDRB >nul
cscript ospp.vbs /unpkey:KHGM9 >nul
cscript ospp.vbs /unpkey:CPQVG >nul
cscript ospp.vbs /sethst:kms8.msguides.com
cscript ospp.vbs /setprt:1688
cscript ospp.vbs /act
cls
echo The Activation Has Been Completed Succesfully. Would You Like To Exit?
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :question

:win10
title Activate Windows 7 / 8 / 8.1 / 10 for FREE!&cls&echo =====================================&echo #Copyright: MSGuides.com&echo =====================================&echo.&echo #Supported products:&echo - Windows 7 Professional&echo - Windows 7 Professional N&echo - Windows 7 Professional E&echo - Windows 7 Enterprise&echo - Windows 7 Enterprise N&echo - Windows 7 Enterprise E&echo - Windows 8 Core&echo - Windows 8 Core Single Language&echo - Windows 8 Professional&echo - Windows 8 Professional N&echo - Windows 8 Professional WMC&echo - Windows 8 Enterprise&echo - Windows 8 Enterprise N&echo - Windows 8.1 Core&echo - Windows 8.1 Core N&echo - Windows 8.1 Core Single Language&echo - Windows 8.1 Professional&echo - Windows 8.1 Professional N&echo - Windows 8.1 Professional WMC&echo - Windows 8.1 Enterprise&echo - Windows 8.1 Enterprise N&echo - Windows 10 Home&echo - Windows 10 Home N&echo - Windows 10 Home Single Language&echo - Windows 10 Home Country Specific&echo - Windows 10 Professional&echo - Windows 10 Professional N&echo - Windows 10 Education N&echo - Windows 10 Education N&echo - Windows 10 Enterprise&echo - Windows 10 Enterprise N&echo - Windows 10 Enterprise LTSB&echo - Windows 10 Enterprise LTSB N&echo.&echo.&echo ====================================&echo Activating your Windows... & cscript //nologo c:\windows\system32\slmgr.vbs /ipk FJ82H-XT6CR-J8D7P-XQJJ2-GPDD4 >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk MRPKT-YTG23-K7D7T-X2JMM-QY7MG >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk W82YF-2Q76Y-63HXB-FGJG9-GF7QX >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk 33PXH-7Y6KF-2VJC9-XBBR8-HVTHH >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk YDRBP-3D83W-TY26F-D46B2-XCKRJ >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk C29WB-22CC8-VJ326-GHFJW-H9DH4 >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk BN3D2-R7TKB-3YPBD-8DRP2-27GG4 >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk 2WN2H-YGCQR-KFX6K-CD6TF-84YXQ >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk NG4HW-VH26C-733KW-K6F98-J8CK4 >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk XCVCF-2NXM9-723PB-MHCB7-2RYQQ >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk GNBB8-YVD74-QJHX6-27H4K-8QHDG >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk 32JNW-9KQ84-P47T8-D8GGY-CWCK7 >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk JMNMF-RHW7P-DMY6X-RF3DR-X2BQT >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk M9Q9P-WNJJT-6PXPY-DWX8H-6XWKK >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk 7B9N3-D94CG-YTVHR-QBPX3-RJP64 >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk BB6NG-PQ82V-VRDPW-8XVD2-V8P66 >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk GCRJD-8NW9H-F2CDX-CCM8D-9D6T9 >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk HMCNV-VVBFX-7HMBH-CTY9B-B4FXY >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk 789NJ-TQK6T-6XTH8-J39CJ-J8D3P >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk TX9XD-98N7V-6WMQ6-BX7FG-H8Q99 >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk 3KHY7-WNT83-DGQKR-F7HPR-844BM >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk 7HNRX-D7KGG-3K4RQ-4WPJ4-YTDFH >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk PVMJN-6DFY6-9CCP6-7BKTT-D3WVR >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX >nul&cscript //nologo c:\windows\system32\slmgr.vbs /ipk MH37W-N47XK-V7XM9-C7227-GCQG9 >nul
echo ------------------------------------&echo.&echo.&set i=1
:server
if %i%==1 set KMS_Sev=kms7.MSGuides.com
if %i%==2 set KMS_Sev=kms8.MSGuides.com
if %i%==3 set KMS_Sev=kms9.MSGuides.com
if %i%==4 goto notsupported
cscript //nologo c:\windows\system32\slmgr.vbs /skms %KMS_Sev% >nul
cscript //nologo c:\windows\system32\slmgr.vbs /ato | find /i "successfully" && (echo.& echo ====================================== & || (echo The connection to the server failed! Trying to connect to another one... & echo Please wait... & echo. & echo. & set /a i+=1 & goto server)
explorer "http://MSGuides.com"&goto halt
:notsupported
echo ======================================&echo.&echo Sorry! Your version is not supported.
timeout 2 > nul     
cls
goto :exit
:halt
echo The Activation Has Been Completed Succesfully. Would You Like To Exit?
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :question

:win11
title Activate Windows 11 ALL versions for FREE!&cls&echo ============================================================================&echo #Project: Activating Microsoft software products for FREE without software&echo ============================================================================&echo.&echo #Supported products:&echo - Windows 11 Home&echo - Windows 11 Home N&echo - Windows 11 Home Single Language&echo - Windows 11 Home Country Specific&echo - Windows 11 Professional&echo - Windows 11 Professional N&echo - Windows 11 Education N&echo - Windows 11 Education N&echo - Windows 11 Enterprise&echo - Windows 11 Enterprise N&echo - Windows 11 Enterprise LTSB&echo - Windows 11 Enterprise LTSB N&echo.&echo.&echo ============================================================================&echo Activating your Windows...&cscript //nologo slmgr.vbs /upk >nul&cscript //nologo slmgr.vbs /cpky >nul&wmic os | findstr /I "enterprise" >nul
if %errorlevel% EQU 0 (cscript //nologo slmgr.vbs /ipk NPPR9-FWDCX-D2C8J-H872K-2YT43 >nul&cscript //nologo slmgr.vbs /ipk DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4 >nul&cscript //nologo slmgr.vbs /ipk WNMTR-4C88C-JK8YV-HQ7T2-76DF9 >nul&cscript //nologo slmgr.vbs /ipk 2F77B-TNFGY-69QQF-B8YKP-D69TJ >nul&cscript //nologo slmgr.vbs /ipk DCPHK-NFMTC-H88MJ-PFHPY-QJ4BJ >nul&cscript //nologo slmgr.vbs /ipk QFFDN-GRT3P-VKWWX-X7T3R-8B639 >nul) else wmic os | findstr /I "11 pro" >nul
if %errorlevel% EQU 0 (cscript //nologo slmgr.vbs /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX >nul&cscript //nologo slmgr.vbs /ipk MH37W-N47XK-V7XM9-C7227-GCQG9 >nul&cscript //nologo slmgr.vbs /ipk 6TP4R-GNPTD-KYYHQ-7B7DP-J447Y >nul&cscript //nologo slmgr.vbs /ipk NW6C2-QMPVW-D7KKK-3GKT6-VCFB2 >nul&cscript //nologo slmgr.vbs /ipk 33QT6-RCNYF-DXB4F-DGP7B-7MHX9 >nul) else wmic os | findstr /I "home" >nul
if %errorlevel% EQU 0 (cscript //nologo slmgr.vbs /ipk TX9XD-98N7V-6WMQ6-BX7FG-H8Q99 >nul&cscript //nologo slmgr.vbs /ipk 3KHY7-WNT83-DGQKR-F7HPR-844BM >nul&cscript //nologo slmgr.vbs /ipk 7HNRX-D7KGG-3K4RQ-4WPJ4-YTDFH >nul&cscript //nologo slmgr.vbs /ipk PVMJN-6DFY6-9CCP6-7BKTT-D3WVR >nul) else (echo.)
set i=1
:server
if %i%==1 set KMS_Sev=kms7.MSGuides.com
if %i%==2 set KMS_Sev=kms8.MSGuides.com
if %i%==3 set KMS_Sev=kms9.MSGuides.com
if %i%==4 goto notsupported
cscript //nologo slmgr.vbs /skms %KMS_Sev% >nul&echo ============================================================================&echo.&echo.
cscript //nologo slmgr.vbs /ato | find /i "successfully" && (echo.&echo ============================================================================&echo.&echo || (echo The connection to my KMS server failed! Trying to connect to another one... & echo Please wait... & echo. & echo. & set /a i+=1 & goto server)
explorer "https://activatewindows10.com/"&goto halt
:notsupported
echo ============================================================================&echo.&echo Sorry! Your version is not supported.&echo.
timeout 2 > nul     
cls
goto :exit
:halt
echo The Activation Has Been Completed Succesfully. Would You Like To Exit?
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :question

:exit
exit
cls
exit
