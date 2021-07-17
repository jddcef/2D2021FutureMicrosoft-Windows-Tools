echo off
color F0
title GPU Optimizer
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
echo Welcome to the GPU Optimizer!
timeout 2 > nul
cls

:question
echo Type "nividia" For Nividia GPU Optimizations.
echo ---------------------------------------------
echo Type "amd" For AMD GPU Optimizations
echo ------------------------------------
echo Type "intel" For Intel GPU Optimizations.
echo --------------------------------------------
echo Type "assist" If You Don't Know Which GPU You Have.
echo ---------------------------------------------------
echo What Would You Like?
set /p a=
if "%a%" == "nividia" goto :nvidia
if "%a%" == "amd" goto :amd
if "%a%" == "intel" goto :intel
if "%a%" == "assist" goto :assist

:assist
echo Press Win+X Then Click On Device Manager, Click Display Adapters. And You Will Know Which GPU You Have. (yes/no)
echo Would You Like To Exit
set /p a=
if "%a%" == "yes" goto :exit
if "%a%" == "no" goto :exit

:nvidia
cls
echo Optimizing 0%%

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 5%%

reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f > nul
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 10%%

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul

cls
echo Optimizing 15%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d 4 /f > nul

cls
echo Optimizing 20%%

bcdedit /deletevalue useplatformclock > nul
bcdedit /set disabledynamictick yes > nul
bcdedit /set useplatformtick yes > nul
bcdedit /set tscsyncpolicy enhanced > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set /set x2apicpolicy enable > nul
bcdedit /timeout 0 > nul

cls
echo Optimizing 25%%

bcdedit /set nx optout > nul
bcdedit /set bootux disabled > nul
bcdedit /set bootmenupolicy standard > nul
bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set hypervisorlaunchtype off > nul
bcdedit /set tpmbootentropy ForceDisable > nul

cls
echo Optimizing 30%%


bcdedit /set quietboot yes > nul
bcdedit /set {globalsettings} custom:16000067 true > nul
bcdedit /set {globalsettings} custom:16000069 true > nul
bcdedit /set {globalsettings} custom:16000068 true > nul
bcdedit /set linearaddress57 OptOut > nul
bcdedit /set increaseuserva 268435328 > nul
bcdedit /set firstmegabytepolicy UseAll > nul
bcdedit /set avoidlowmemory 0x8000000 > nul
bcdedit /set nolowmem Yes > nul

cls
echo Optimizing 35%%

bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set configaccesspolicy Default > nul
bcdedit /set MSI Default > nul
bcdedit /set usephysicaldestination No > nul
bcdedit /set usefirmwarepcisettings No > nul

cls
echo Optimizing 40%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 45%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 50%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v PerfAnalyzeMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidGfxPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableCEPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisableCudaContextPreemption /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisablePreemptionOnS3S4 /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MonitorLatencyTolerance /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatencyCheckEnabled /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v Latency /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 55%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceDefault /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceFSVP /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyTolerancePerfOverride /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceScreenOffIR /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceVSyncEnabled /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v RtlCapabilityCheckLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyActivelyUsed /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleLongTime /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 60%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleMonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleNoContext /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleShortTime /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleVeryLongTime /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle0 /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle0MonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle1 /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle1MonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceMemory /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 65%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceNoContext /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceNoContextMonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceOther /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceTimerPeriod /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultMemoryRefreshLatencyToleranceActivelyUsed /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultMemoryRefreshLatencyToleranceMonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v Latency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MaxIAverageGraphicsLatencyInOneBucket /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MiracastPerfTrackGraphicsLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MonitorLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TransitionLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 70%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v PerfAnalyzeMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidGfxPreemption /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 75%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableCEPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 80%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v PerfAnalyzeMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidGfxPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableCEPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v DisableCudaContextPreemption /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v DisablePreemptionOnS3S4 /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 85%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v MonitorLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v TimeStampInterval /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DpiMapIommuContiguous /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DisableCudaContextPreemption /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DisablePreemptionOnS3S4 /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MonitorLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v D3PCLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v F1TransitionLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LOWLATENCY /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v Node3DLowLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PciLatencyTimerControl /t REG_DWORD /d 32 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMDeepL1EntryLatencyUsec /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RmGspcMaxFtuS /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RmGspcMinFtuS /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RmGspcPerioduS /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrEiIdleThresholdUs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrGrIdleThresholdUs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrGrRgIdleThresholdUs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrMsIdleThresholdUs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v VRDirectFlipDPCDelayUs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v VRDirectFlipTimingMarginUs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v VRDirectJITFlipMsHybridFlipDelayUs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v vrrCursorMarginUs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v vrrDeflickerMarginUs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v vrrDeflickerMaxUs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PerfAnalyzeMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v EnableMidGfxPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v EnableMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v EnableCEPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DisableCudaContextPreemption /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DisablePreemptionOnS3S4 /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v MonitorLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d1 /f > nul

cls
echo Optimizing 90%%

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v IRQ8Priority /t REG_DWORD /d 1 /f > nul 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HibernateEnabledDefault /t REG_DWORD /d 0 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetBT" /v Start /t REG_DWORD /d 4 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f > nul
reg add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "00000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "00000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v CursorSensitivity /t REG_DWORD /d 00002710 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v CursorUpdateInterval /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v IRRemoteNavigationDelta /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v AttractionRectInsetInDIPS /t REG_DWORD /d 00000005 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v DistanceThresholdInDIPS /t REG_DWORD /d 00000028 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v MagnetismDelayInMilliseconds /t REG_DWORD /d 00000032 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v MagnetismUpdateIntervalInMilliseconds /t REG_DWORD /d 00000010 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v VelocityInDIPSPerSecond /t REG_DWORD /d 00000168 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d 30 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 00000014 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseSensitivity /t REG_SZ /d 10 /f > nul

cls
echo Optimizing 95%%

netsh winsock set autotuning on > nul
netsh int tcp set global fastopen=enable > nul
netsh interface ipv4 set dns name="Wi-Fi" static 1.1.1.1 > nul
netsh interface ipv4 add dns name="Wi-Fi" 1.0.0.1 index=2 > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DefaultReceiveWindow /t REG_DWORD /d 10000 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DefaultSendWindow /t REG_DWORD /d 10000 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DynamicSendBufferDisable /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v EnableDynamicBacklog /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v MinimumDynamicBacklog /t REG_DWORD /d 20 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v MaximumDynamicBacklog /t REG_DWORD /d 1000 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DynamicBacklogGrowthDelta /t REG_DWORD /d 10 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v KeepAliveInterval /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 128 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 20 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 5 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v TcpAckFrequency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v TCPNoDelay /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 100%%
timeout 2 > nul
goto :finish

:amd
cls
echo Optimizing 0%%

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 5%%

reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f > nul
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 10%%

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul

cls
echo Optimizing 15%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d 4 /f > nul

cls
echo Optimizing 20%%

bcdedit /deletevalue useplatformclock > nul
bcdedit /set disabledynamictick yes > nul
bcdedit /set useplatformtick yes > nul
bcdedit /set tscsyncpolicy enhanced > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set /set x2apicpolicy enable > nul
bcdedit /timeout 0 > nul

cls
echo Optimizing 25%%

bcdedit /set nx optout > nul
bcdedit /set bootux disabled > nul
bcdedit /set bootmenupolicy standard > nul
bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set hypervisorlaunchtype off > nul
bcdedit /set tpmbootentropy ForceDisable > nul

cls
echo Optimizing 30%%


bcdedit /set quietboot yes > nul
bcdedit /set {globalsettings} custom:16000067 true > nul
bcdedit /set {globalsettings} custom:16000069 true > nul
bcdedit /set {globalsettings} custom:16000068 true > nul
bcdedit /set linearaddress57 OptOut > nul
bcdedit /set increaseuserva 268435328 > nul
bcdedit /set firstmegabytepolicy UseAll > nul
bcdedit /set avoidlowmemory 0x8000000 > nul
bcdedit /set nolowmem Yes > nul

cls
echo Optimizing 35%%

bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set configaccesspolicy Default > nul
bcdedit /set MSI Default > nul
bcdedit /set usephysicaldestination No > nul
bcdedit /set usefirmwarepcisettings No > nul

cls
echo Optimizing 40%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 45%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 50%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v PerfAnalyzeMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidGfxPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableCEPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisableCudaContextPreemption /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisablePreemptionOnS3S4 /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MonitorLatencyTolerance /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatencyCheckEnabled /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v Latency /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 55%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceDefault /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceFSVP /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyTolerancePerfOverride /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceScreenOffIR /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceVSyncEnabled /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v RtlCapabilityCheckLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyActivelyUsed /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleLongTime /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 60%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleMonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleNoContext /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleShortTime /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleVeryLongTime /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle0 /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle0MonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle1 /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle1MonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceMemory /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 65%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceNoContext /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceNoContextMonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceOther /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceTimerPeriod /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultMemoryRefreshLatencyToleranceActivelyUsed /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultMemoryRefreshLatencyToleranceMonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v Latency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MaxIAverageGraphicsLatencyInOneBucket /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MiracastPerfTrackGraphicsLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MonitorLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TransitionLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 70%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v PerfAnalyzeMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidGfxPreemption /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 75%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableCEPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 80%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v PerfAnalyzeMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidGfxPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableCEPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v DisableCudaContextPreemption /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v DisablePreemptionOnS3S4 /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 85%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v MonitorLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v TimeStampInterval /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DpiMapIommuContiguous /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRSnoopL1Latency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRSnoopL0Latency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRNoSnoopL1Latency /t REG_DWORD /d 1 /f > nul 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRMaxNoSnoopLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v KMD_RpmComputeLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DalUrgentLatencyNs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v memClockSwitchLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PP_RTPMComputeF1Latency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PP_DGBMMMaxTransitionLatencyUvd /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PP_DGBPMMaxTransitionLatencyGfx /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DalNBLatencyForUnderFlow /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DalDramClockChangeLatencyNs /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRSnoopL1Latency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRSnoopL0Latency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRNoSnoopL1Latency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRNoSnoopL0Latency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRMaxSnoopLatencyValue /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRMaxNoSnoopLatencyValue /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 90%%

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v IRQ8Priority /t REG_DWORD /d 1 /f > nul 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HibernateEnabledDefault /t REG_DWORD /d 0 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetBT" /v Start /t REG_DWORD /d 4 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f > nul
reg add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "00000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "00000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v CursorSensitivity /t REG_DWORD /d 00002710 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v CursorUpdateInterval /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v IRRemoteNavigationDelta /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v AttractionRectInsetInDIPS /t REG_DWORD /d 00000005 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v DistanceThresholdInDIPS /t REG_DWORD /d 00000028 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v MagnetismDelayInMilliseconds /t REG_DWORD /d 00000032 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v MagnetismUpdateIntervalInMilliseconds /t REG_DWORD /d 00000010 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v VelocityInDIPSPerSecond /t REG_DWORD /d 00000168 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d 30 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 00000014 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseSensitivity /t REG_SZ /d 10 /f > nul

cls
echo Optimizing 95%%

netsh winsock set autotuning on > nul
netsh int tcp set global fastopen=enable > nul
netsh interface ipv4 set dns name="Wi-Fi" static 1.1.1.1 > nul
netsh interface ipv4 add dns name="Wi-Fi" 1.0.0.1 index=2 > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DefaultReceiveWindow /t REG_DWORD /d 10000 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DefaultSendWindow /t REG_DWORD /d 10000 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DynamicSendBufferDisable /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v EnableDynamicBacklog /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v MinimumDynamicBacklog /t REG_DWORD /d 20 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v MaximumDynamicBacklog /t REG_DWORD /d 1000 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DynamicBacklogGrowthDelta /t REG_DWORD /d 10 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v KeepAliveInterval /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 128 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 20 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 5 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v TcpAckFrequency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v TCPNoDelay /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 100%%
timeout 2 > nul
goto :finish

:intel
cls
echo Optimizing 0%%

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 5%%

reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f > nul
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 10%%

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul

cls
echo Optimizing 15%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d 4 /f > nul

cls
echo Optimizing 20%%

bcdedit /deletevalue useplatformclock > nul
bcdedit /set disabledynamictick yes > nul
bcdedit /set useplatformtick yes > nul
bcdedit /set tscsyncpolicy enhanced > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set /set x2apicpolicy enable > nul
bcdedit /timeout 0 > nul

cls
echo Optimizing 25%%

bcdedit /set nx optout > nul
bcdedit /set bootux disabled > nul
bcdedit /set bootmenupolicy standard > nul
bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set hypervisorlaunchtype off > nul
bcdedit /set tpmbootentropy ForceDisable > nul

cls
echo Optimizing 30%%


bcdedit /set quietboot yes > nul
bcdedit /set {globalsettings} custom:16000067 true > nul
bcdedit /set {globalsettings} custom:16000069 true > nul
bcdedit /set {globalsettings} custom:16000068 true > nul
bcdedit /set linearaddress57 OptOut > nul
bcdedit /set increaseuserva 268435328 > nul
bcdedit /set firstmegabytepolicy UseAll > nul
bcdedit /set avoidlowmemory 0x8000000 > nul
bcdedit /set nolowmem Yes > nul

cls
echo Optimizing 35%%

bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set configaccesspolicy Default > nul
bcdedit /set MSI Default > nul
bcdedit /set usephysicaldestination No > nul
bcdedit /set usefirmwarepcisettings No > nul

cls
echo Optimizing 40%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 45%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 50%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v PerfAnalyzeMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidGfxPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableCEPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisableCudaContextPreemption /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisablePreemptionOnS3S4 /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MonitorLatencyTolerance /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatencyCheckEnabled /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v Latency /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 55%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceDefault /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceFSVP /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyTolerancePerfOverride /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceScreenOffIR /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceVSyncEnabled /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v RtlCapabilityCheckLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyActivelyUsed /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleLongTime /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 60%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleMonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleNoContext /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleShortTime /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleVeryLongTime /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle0 /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle0MonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle1 /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceIdle1MonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceMemory /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 65%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceNoContext /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceNoContextMonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceOther /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultLatencyToleranceTimerPeriod /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultMemoryRefreshLatencyToleranceActivelyUsed /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultMemoryRefreshLatencyToleranceMonitorOff /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v Latency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MaxIAverageGraphicsLatencyInOneBucket /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MiracastPerfTrackGraphicsLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MonitorLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v TransitionLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 70%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v PerfAnalyzeMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidGfxPreemption /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 75%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v EnableCEPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul

cls
echo Optimizing 80%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v PerfAnalyzeMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidGfxPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnableCEPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v DisableCudaContextPreemption /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v DisablePreemptionOnS3S4 /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 85%%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v MonitorLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v TimeStampInterval /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DpiMapIommuContiguous /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 90%%

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v IRQ8Priority /t REG_DWORD /d 1 /f > nul 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HibernateEnabledDefault /t REG_DWORD /d 0 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetBT" /v Start /t REG_DWORD /d 4 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f > nul
reg add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "00000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "00000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v CursorSensitivity /t REG_DWORD /d 00002710 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v CursorUpdateInterval /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v IRRemoteNavigationDelta /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v AttractionRectInsetInDIPS /t REG_DWORD /d 00000005 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v DistanceThresholdInDIPS /t REG_DWORD /d 00000028 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v MagnetismDelayInMilliseconds /t REG_DWORD /d 00000032 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v MagnetismUpdateIntervalInMilliseconds /t REG_DWORD /d 00000010 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v VelocityInDIPSPerSecond /t REG_DWORD /d 00000168 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d 30 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 00000014 /f > nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseSensitivity /t REG_SZ /d 10 /f > nul

cls
echo Optimizing 95%%

netsh winsock set autotuning on > nul
netsh int tcp set global fastopen=enable > nul
netsh interface ipv4 set dns name="Wi-Fi" static 1.1.1.1 > nul
netsh interface ipv4 add dns name="Wi-Fi" 1.0.0.1 index=2 > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DefaultReceiveWindow /t REG_DWORD /d 10000 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DefaultSendWindow /t REG_DWORD /d 10000 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DynamicSendBufferDisable /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v EnableDynamicBacklog /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v MinimumDynamicBacklog /t REG_DWORD /d 20 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v MaximumDynamicBacklog /t REG_DWORD /d 1000 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DynamicBacklogGrowthDelta /t REG_DWORD /d 10 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v KeepAliveInterval /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 128 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 20 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 5 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v TcpAckFrequency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v TCPNoDelay /t REG_DWORD /d 1 /f > nul

cls
echo Optimizing 100%%
timeout 1 > nul
goto :finish

:finish
cls
title Finished! 
echo                    GPU Optimization is finished!
timeout 1 > nul
cls  
goto :exit             

:exit
cls
title Exiting 
echo                      Exiting the CMD...
timeout 1 > nul
exit
