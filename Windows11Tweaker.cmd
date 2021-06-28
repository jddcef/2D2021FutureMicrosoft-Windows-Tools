echo off
color 03
title Windows11Tweaker
cls

:question
echo Type "optimization" for Best Windows Optimizations  Type "start service" To Start Services App!
echo -----------------------------------------------------------------------------------------------
echo Type "restore" to Create a System Restore Point. Type "stop service" To Stop Services App!
echo Type "use-restore" To Use the Restore Point.         
echo -----------------------------------------------------------------------------------------------
echo Type "revert" to Reverse the effects of the optimization Type "backup" To Backup Your Drives.
echo ----------------------------------------------------------------------------------------------
echo Type "restart" to Restart your PC in 5 minutes! Type "clean" To Disk Cleanup! (Does Not Remove Windows)  
echo --------------------------------------------------------------------------------------------------------
echo Type "info" For More Info About The Optimizations. Type "reset update" to Reset Windows Update.   
echo -----------------------------------------------------------------------------------------------
echo Type "exit" to Exit. Type "enable feature" to Enable Windows Feature App! 
echo --------------------------------------------------------------------------
echo Type "disable feature To Disable Windows Feature App! Type "user" To User Account Management.
echo ---------------------------------------------------------------------------------------------
echo Type "scan" To Scan and Repair corrupt files. Type "windows check activate" To Check Windows Activation Status!
echo ---------------------------------------------------------------------------------------------------------------  
echo Type "hd & sd" For HDD & SSD Optimization! Type "remove-package" To Remove Apps. 
echo -----------------------------------------------------------------------------------
echo Type "gpu" For GPU Optimizer! 
echo -----------------------------
echo Which one would you like?
set /p a=
if "%a%" == "optimization" goto :optimize
if "%a%" == "restore" goto :restore
if "%a%" == "revert" goto :revert
if "%a%" == "restart" goto :prompt
if "%a%" == "info" goto :info
if "%a%" == "exit" goto :exit
if "%a%" == "scan" goto :scan
if "%a%" == "backup" goto :drive
if "%a%" == "clean" goto :disk
if "%a%" == "reset update" goto :ResetUpdate
if "%a%" == "user" goto :User Account Management
if "%a%" == "remove-package" goto :Remove-Package
if "%a%" == "enable feature" goto :Enable-WindowsOptionalFeature
if "%a%" == "disable feature" goto :Disable-WindowsOptionalFeature
if "%a%" == "start service" goto :Start-Service
if "%a%" == "disable service" goto :Stop-Service
if "%a%" == "use-restore" goto :restore-Pc
if "%a%" == "windows check activate" goto :CheckWindowsactivation
if "%a%" == "hd & sd" goto :hdd & ssd
if "%a%" == "gpu" goto :gpu
cls

:gpu


echo Type "Nividia" For Nividia GPU Optimizations.
echo ---------------------------------------------
echo Type "Amd" For AMD GPU Optimizations.
echo --------------------------------------------
echo Type "Intel" For Intel GPU Optimizations.
echo --------------------------------------------
echo Don't Know Which GPU You Have? Type "assist" For Help.
echo ------------------------------------------------------
echo Which one would you like?
set /p a=
if "%a%" == "Nividia" goto :nividia
if "%a%" == "Amd" goto :amd
if "%a%" == "Intel" goto :intel
if "%a%" == "assist" goto :assist

:assist
echo Press Win+X Then Click On "Device Manager" Find "Display Adapters" And Done.
echo Would You Like To Exit? (Yes)
set /p a=
if "%a%" == "Yes" goto :gpu

:nividia
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f > nul
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f > nul
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
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d 4 /f > nul
cls
bcdedit /deletevalue useplatformclock > nul
bcdedit /set disabledynamictick yes > nul
bcdedit /set useplatformtick yes > nul
bcdedit /set tscsyncpolicy enhanced > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set /set x2apicpolicy enable > nul
bcdedit /timeout 0 > nul
bcdedit /set nx optout > nul
bcdedit /set bootux disabled > nul
bcdedit /set bootmenupolicy standard > nul
bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set hypervisorlaunchtype off > nul
bcdedit /set tpmbootentropy ForceDisable > nul
bcdedit /set quietboot yes > nul
bcdedit /set {globalsettings} custom:16000067 true > nul
bcdedit /set {globalsettings} custom:16000069 true > nul
bcdedit /set {globalsettings} custom:16000068 true > nul
bcdedit /set linearaddress57 OptOut > nul
bcdedit /set increaseuserva 268435328 > nul
bcdedit /set firstmegabytepolicy UseAll > nul
bcdedit /set avoidlowmemory 0x8000000 > nul
bcdedit /set nolowmem Yes > nul
bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set configaccesspolicy Default > nul
bcdedit /set MSI Default > nul
bcdedit /set usephysicaldestination No > nul
bcdedit /set usefirmwarepcisettings No > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul
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
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceDefault /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceFSVP /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyTolerancePerfOverride /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceScreenOffIR /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceVSyncEnabled /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v RtlCapabilityCheckLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyActivelyUsed /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleLongTime /t REG_DWORD /d 1 /f > nul
cls
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
echo Your Nividia GPU Optimization Is Aplied!, Would You Like To Exit (Yes/No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No"  goto :gpu

:amd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > nul
cls
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
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d 4 /f > nul
cls
bcdedit /deletevalue useplatformclock > nul
bcdedit /set disabledynamictick yes > nul
bcdedit /set useplatformtick yes > nul
bcdedit /set tscsyncpolicy enhanced > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set /set x2apicpolicy enable > nul
bcdedit /timeout 0 > nul
cls
bcdedit /set nx optout > nul
bcdedit /set bootux disabled > nul
bcdedit /set bootmenupolicy standard > nul
bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set hypervisorlaunchtype off > nul
bcdedit /set tpmbootentropy ForceDisable > nul
cls
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
bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set configaccesspolicy Default > nul
bcdedit /set MSI Default > nul
bcdedit /set usephysicaldestination No > nul
bcdedit /set usefirmwarepcisettings No > nul
cls
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
cls
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul
cls
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
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceDefault /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceFSVP /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyTolerancePerfOverride /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceScreenOffIR /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceVSyncEnabled /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v RtlCapabilityCheckLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyActivelyUsed /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleLongTime /t REG_DWORD /d 1 /f > nul
cls
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
echo Your Nividia GPU Optimization Is Aplied!, Would You Like To Exit (Yes/No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No"  goto :gpu

:intel
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > nul
cls
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
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d 4 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d 4 /f > nul
cls
bcdedit /deletevalue useplatformclock > nul
bcdedit /set disabledynamictick yes > nul
bcdedit /set useplatformtick yes > nul
bcdedit /set tscsyncpolicy enhanced > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set /set x2apicpolicy enable > nul
bcdedit /timeout 0 > nul
cls
bcdedit /set nx optout > nul
bcdedit /set bootux disabled > nul
bcdedit /set bootmenupolicy standard > nul
bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set hypervisorlaunchtype off > nul
bcdedit /set tpmbootentropy ForceDisable > nul
cls
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
bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set vsmlaunchtype Off > nul
bcdedit /set vm No > nul
bcdedit /set configaccesspolicy Default > nul
bcdedit /set MSI Default > nul
bcdedit /set usephysicaldestination No > nul
bcdedit /set usefirmwarepcisettings No > nul
cls
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RMDisablePostL2Compression /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmGpsPsEnablePerCpuCoreDpc /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v RmDisableRegistryCaching /t REG_DWORD /d 1 /f > nul
clsreg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisableWriteCombining /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnablePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v GPUPreemptionLevel /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v ComputePreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidGfxPreemptionVGPU /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableMidBufferPreemptionForHighTdrTimeout /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableAsyncMidBufferPreemption /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v EnableSCGMidBufferPreemption /t REG_DWORD /d 0 /f > nul
cls
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
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceDefault /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceFSVP /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyTolerancePerfOverride /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceScreenOffIR /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceVSyncEnabled /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v RtlCapabilityCheckLatency /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyActivelyUsed /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DefaultD3TransitionLatencyIdleLongTime /t REG_DWORD /d 1 /f > nul
cls
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
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v MonitorLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v TimeStampInterval /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DpiMapIommuContiguous /t REG_DWORD /d 1 /f > nul
cls
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
:hdd & ssd
echo Welcome To HDD & SSD Optimizer!
echo -------------------------------
echo Type "hdd" If You Have HDD.
echo ------------------------------
echo Type "ssd" If You Have SSD.
echo ----------------------------
echo Don't Know Which Drive You Have? Well, Type "assist" For A Turtorial.
echo ---------------------------------------------------------------------
echo Type "exit" To Exit HDD & SSD Optimizations.
echo ---------------------------------------------------------------------
echo What Would You Like?
set /p a=
if "%a%" == "hdd" goto :hdd
if "%a%" == "ssd" goto :ssd
if "%a%" == "assist" goto :about
if "%a%" == "exit" goto :question

:hdd
fsutil behavior set disabledeletenotify 1 > nul
fsutil behavior set mftzone 2 > nul 
fsutil behavior set disablelastaccess 1 > nul
fsutil behavior set memoryusage 2 > nul
fsutil behavior set encryptpagingfile 0 > nul
echo The Operation Completed Successfully, Would You Like To Exit? (Yes/No) 
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :hdd & ssd

:ssd
fsutil behavior set disabledeletenotify 0 > nul
fsutil behavior set mftzone 2 > nul 
fsutil behavior set disablelastaccess 1 > nul
fsutil behavior set memoryusage 2 > nul
fsutil behavior set encryptpagingfile 0 > nul
echo The Operation Completed Successfully, Would You Like To Exit? (Yes/No) 
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :hdd & ssd

:about
Goto Start "Windows Administrative Tools" Folder Open "Defragment and Optimize Drives" When Open, You Will See "Media Type" And And You Will Know if You Have HDD & SSD.
echo Would You Like To Exit? (Yes/No) 
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :hdd & ssd
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
choice /c YN /n /m "Do You Want To Exit (Yes/No)"
if %errorlevel% EQU 1 goto :exit
if %errorlevel% EQU 2 goto :question

:Start-Service
cls
powershell.exe -ExecutionPolicy Bypass -Command "& '%~dp0data\scripts\Start-Service.ps1'"
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue Start Service program? (Yes/No) "
if %errorlevel% EQU 1 goto :Start-Service
if %errorlevel% EQU 2 goto :question

:Stop-Service
cls
powershell.exe -ExecutionPolicy Bypass -Command "& '%~dp0data\scripts\Stop-Service.ps1'"
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue Stop Service program? (Yes/No) "
if %errorlevel% EQU 1 goto :Stop-Service
if %errorlevel% EQU 2 goto :question

:Remove-Package
cls
echo.Remove-Package Menu
echo.
echo.   Package Name				Package Name
echo.
echo.1	Connect			19	Media Features 				
echo.2	Cortana			20	Microsoft Message Queue (MSMQ) Server
echo.3	Get Help		21	Microsoft Print to PDF		
echo.4	Microsoft Edge		22	MultiPoint Connector 	
echo.5	Mixed Reality Portal	23	Print and Document Services	
echo.6	OneDrive		24	RAS Connection Manager Adminitration Kit 		
echo.7	Quick Assist		25	Remove Differential Compression API Support		
echo.8	Windows Defender	26	RIP Listener	
echo.9	Windows Spotlight	27	Services for NFS
echo.10	Windows Photo Viewer	28	Simple Network Management Protocol 
echo.11	Snipping Tool		29	Simple TCPIP services 
echo.12	Active Directory	30	SMB 1.0/CIFS File Sharing Support			
echo.13	Containers		31	Telnet-TFTP Client			
echo.14	Assigned Access		32	Windows Identify Foundation 3.5
echo.15	Device Lockdown		33	Windows Powershell 2.0	
echo.16	Hyper-V			34	Windows TIFF IFilter							
echo.17	Internet Explorer	35	XPS Services	
echo.18	Legacy Components	36	XPS Viewer
echo.      !Remove Stuff That You Don't Know!
echo.Type 37 To Return Main menu
echo.				

set /p option=Select The Package Name And press Enter: 
if %option% EQU Connect (
    call :Connect
) else if %option% EQU Cortana (
    call :Cortana
) else if %option% EQU Get Help (
    call :GetHelp
) else if %option% EQU Microsoft Edge (
    goto MicrosoftEdge
) else if %option% EQU Mixed Reality Portal (
    goto MixedRealityPortal
) else if %option% EQU OneDrive (
    goto OneDrive
) else if %option% EQU Quick Assist (
    goto QuickAssist
) else if %option% EQU Windows Defender (
    goto WindowsDefender
) else if %option% EQU Windows Spotlight (
    goto WindowsSpotlight
) else if %option% EQU Windows Photo Viewer (
    goto PhotoViewer
) else if %option% EQU Snipping Tool (
    goto SnippingTool
) else if %option% EQU Active Directory (
    goto ActiveDirectory
) else if %option% EQU Containers (
    goto Containers
) else if %option% EQU Assigned Access (
    goto AssignedAccess
) else if %option% EQU Device Lockdown (
    goto DeviceLockdown
) else if %option% EQU Hyper-V (
    goto Hyper-V
) else if %option% EQU Internet Explorer (
    goto InternetExplorer11
) else if %option% EQU Legacy Components (
    goto LegacyComponents
) else if %option% EQU Media Features (
    goto MediaFeatures
) else if %option% EQU Microsoft Message Queue (MSMQ) Server (
    goto MessageQueue
) else if %option% EQU Microsoft Print to PDF (
    goto PrinttoPDF
) else if %option% EQU MultiPoint Connector (
    goto MultiPointConnector
) else if %option% EQU Print and Document Services (
    goto PrintandDocument
) else if %option% EQU RAS Connection Manager Adminitration Kit (
    goto RASConnectionManager
) else if %option% EQU Remove Differential Compression API Support (
    goto DifferentialCompressionAPI
) else if %option% EQU RIP Listener (
    goto RIPListener
) else if %option% EQU Services for NFS (
    goto ServicesforNFS
) else if %option% EQU Simple Network Management Protocol (
    goto SimpleNetwork
) else if %option% EQU Simple TCPIP services (
    goto SimpleTCPIP
) else if %option% EQU SMB 1.0/CIFS File Sharing Support (
    goto FileSharingSupport
) else if %option% EQU Telnet-TFTP Client (
    goto TelnetClient
) else if %option% EQU Windows Identify Foundation 3.5 (
    goto IdentifyFoundation
) else if %option% EQU Windows Powershell 2.0 (
    goto Powershell2.0
) else if %option% EQU Windows TIFF IFilter (
    goto TIFFIFilter
) else if %option% EQU XPS Services (
    goto XPSServices
) else if %option% EQU XPS Viewer (
    goto XPSViewer
) else if %option% EQU 37 (
    goto :question
) else (
    goto Remove-Package
)
:: ------------------------------------------------------------------------------------

:Connect
cls
choice /c YN /n /m "WARNING: The application can not be Reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-Connect
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-Connect
cls
reg query "%key%" | findstr /c:PPIProjection
if %errorlevel% EQU 0 goto removeconnect
if %errorlevel% EQU 1 goto not-found

:removeconnect
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:PPIProjection ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:PPIProjection ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
: ------------------------------------------------------------------------------------

:Cortana
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-Cortana
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-Cortana
cls
reg query "%key%" | findstr /c:Cortana
if %errorlevel% EQU 0 goto removecortana
if %errorlevel% EQU 1 goto not-found

:removecortana
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Cortana ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Cortana ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Remove-Package
: ------------------------------------------------------------------------------------

:GetHelp
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-ContactSupport
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-ContactSupport
cls
reg query "%key%" | findstr /c:ContactSupport
if %errorlevel% EQU 0 goto removecontactsupport
if %errorlevel% EQU 1 goto not-found

:removecontactsupport
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:ContactSupport ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:ContactSupport ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
: ------------------------------------------------------------------------------------

:MicrosoftEdge
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-MicrosoftEdge
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-MicrosoftEdge
cls
reg query "%key%" | findstr /c:Internet-Browser
if %errorlevel% EQU 0 goto removeinternetbrowser
if %errorlevel% EQU 1 goto not-found

:removeinternetbrowser
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Internet-Browser ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Internet-Browser ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
: ------------------------------------------------------------------------------------

:MixedRealityPortal
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-MixedRealityPortal
if %errorlevel% EQU 2 goto Menu
: --------------------------------------------------

:Remove-MixedRealityPortal
cls
reg query "%key%" | findstr /c:Holographic
if %errorlevel% EQU 0 goto removeholographic
if %errorlevel% EQU 1 goto not-found

:removeholographic
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Holographic ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Holographic ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Remove-Package
: ------------------------------------------------------------------------------------

:OneDrive
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-OneDrive
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-OneDrive
cls
cd\
dir /b /s | findstr /c:OneDriveSetup.exe
if %errorlevel% EQU 0 goto uninstall-onedrive
if %errorlevel% EQU 1 goto file-not-found

:uninstall-onedrive
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
) ELSE (
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
)
for /f %%a in ('dir /b /s ^| findstr /c:OneDriveSetup.exe') do (
	takeown /f %%a
	icacls %%a /grant %username%:F
	start /wait %%a /uninstall
	del /s /q %%a
	goto removeonedrive
)

:removeonedrive
cls
reg query "%key%" | findstr /c:OneDrive
if %errorlevel% EQU 0 goto removeonedrivepackage
if %errorlevel% EQU 1 goto not-found

:removeonedrivepackage
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:OneDrive ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:OneDrive ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package

:file-not-found
echo.File Not Found
pause
goto removeonedrive
: ------------------------------------------------------------------------------------

:QuickAssist
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-QuickAssist
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-QuickAssist
cls
reg query "%key%" | findstr /c:QuickAssist
if %errorlevel% EQU 0 goto removequickassist
if %errorlevel% EQU 1 goto not-found

:removequickassist
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:QuickAssist ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:QuickAssist ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
: ------------------------------------------------------------------------------------

:WindowsDefender
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-WindowsDefender
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-WindowsDefender
cls
reg query "%key%" | findstr /c:Defender
if %errorlevel% EQU 0 goto removedefender
if %errorlevel% EQU 1 goto not-found

:removedefender
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Defender ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Defender ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "hide:windowsdefender" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /t REG_DWORD /d 0 /f
takeown /f "%SystemRoot%\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy"
takeown /f "%SystemRoot%\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\Assets"
takeown /f "%SystemRoot%\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\pris"
icacls "%SystemRoot%\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy" /grant %username%:F
icacls "%SystemRoot%\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\Assets" /grant %username%:F
icacls "%SystemRoot%\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\pris" /grant %username%:F
rd /s /q "%SystemRoot%\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy"
cls
echo.The operation completed successfully.
echo.How to delete the Windows Defender Security Center icon in the Start menu.
echo See details https://goo.gl/8HtNsc
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Remove-Package
:: ------------------------------------------------------------------------------------

:WindowsSpotlight
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-WindowsSpotlight
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-WindowsSpotlight
cls
reg query "%key%" | findstr /c:ContentDeliveryManager
if %errorlevel% EQU 0 goto removecontentdeliverymanager
if %errorlevel% EQU 1 goto not-found

:removecontentdeliverymanager
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:ContentDeliveryManager ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:ContentDeliveryManager ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:PhotoViewer
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-PhotoViewer
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-PhotoViewer
cls
reg query "%key%" | findstr /c:PhotoBasicPackage
if %errorlevel% EQU 0 goto removephotobasicpackage
if %errorlevel% EQU 1 goto not-found

:removephotobasicpackage
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:PhotoBasicPackage ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:PhotoBasicPackage ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:SnippingTool
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-SnippingTool
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-SnippingTool
cls
reg query "%key%" | findstr /c:SnippingTool
if %errorlevel% EQU 0 goto removesnippingtool
if %errorlevel% EQU 1 goto not-found

:removesnippingtool
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:SnippingTool ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:SnippingTool ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:ActiveDirectory
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-ActiveDirectory
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-ActiveDirectory
cls
reg query "%key%" | findstr /c:DirectoryServices
if %errorlevel% EQU 0 goto removedirectoryservices
if %errorlevel% EQU 1 goto not-found

:removedirectoryservices
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:DirectoryServices ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:DirectoryServices ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:Containers
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-Containers
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-Containers
cls
reg query "%key%" | findstr /c:Containers-Opt
if %errorlevel% EQU 0 goto removecontainersopt
if %errorlevel% EQU 1 goto not-found

:removecontainersopt
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Containers-Opt ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Containers-Opt ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:AssignedAccess
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-AssignedAccess
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-AssignedAccess
cls
reg query "%key%" | findstr /c:AssignedAccess
if %errorlevel% EQU 0 goto removeassignedaccess
if %errorlevel% EQU 1 goto not-found

:removeassignedaccess
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:AssignedAccess ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:AssignedAccess ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Remove-Package
:: ------------------------------------------------------------------------------------

:DeviceLockdown
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-DeviceLockdown
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-DeviceLockdown
cls
reg query "%key%" | findstr /c:Embedded
if %errorlevel% EQU 0 goto removedevicelockdown
if %errorlevel% EQU 1 goto not-found

:removedevicelockdown
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Embedded ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Embedded ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Remove-Package
:: ------------------------------------------------------------------------------------

:Hyper-V
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-Hyper-V
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-Hyper-V
cls
reg query "%key%" | findstr /c:HyperV
if %errorlevel% EQU 0 goto removehyperv
if %errorlevel% EQU 1 goto not-found

:removehyperv
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:HyperV ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:HyperV ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Remove-Package
:: ------------------------------------------------------------------------------------

:InternetExplorer11
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-InternetExplorer11
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-InternetExplorer11
cls
reg query "%key%" | findstr /c:InternetExplorer
if %errorlevel% EQU 0 goto removeinternetexplorer
if %errorlevel% EQU 1 goto not-found

:removeinternetexplorer
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:InternetExplorer ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:InternetExplorer ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:LegacyComponents
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-LegacyComponents
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-LegacyComponents
cls
reg query "%key%" | findstr /c:Legacy-Components
if %errorlevel% EQU 0 goto removelegacycomponents
if %errorlevel% EQU 1 goto not-found

:removelegacycomponents
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Legacy-Components ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Legacy-Components ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:MediaFeatures
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-MediaFeatures
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-MediaFeatures
cls
reg query "%key%" | findstr /c:MediaPlayback
if %errorlevel% EQU 0 goto removemediaplayback
if %errorlevel% EQU 1 goto not-found

:removemediaplayback
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:MediaPlayback ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:MediaPlayback ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Remove-Package
:: ------------------------------------------------------------------------------------

:MessageQueue
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-MessageQueue
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-MessageQueue
cls
reg query "%key%" | findstr /c:MSMQ
if %errorlevel% EQU 0 goto removemsqm
if %errorlevel% EQU 1 goto not-found

:removemsqm
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:MSMQ ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:MSMQ ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:PrinttoPDF
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-PrinttoPDF
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-PrinttoPDF
cls
reg query "%key%" | findstr /c:PrintToPDFServices
if %errorlevel% EQU 0 goto removeprinttopdfservices
if %errorlevel% EQU 1 goto not-found

:removeprinttopdfservices
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:PrintToPDFServices ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:PrintToPDFServices ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:MultiPointConnector
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-MultiPointConnector
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-MultiPointConnector
cls
reg query "%key%" | findstr /c:MultiPoint
if %errorlevel% EQU 0 goto removemultipoint
if %errorlevel% EQU 1 goto not-found

:removemultipoint
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:MultiPoint ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:MultiPoint ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:PrintandDocument
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-PrintandDocument
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-PrintandDocument
cls
reg query "%key%" | findstr /c:Printer /c:Printing
if %errorlevel% EQU 0 goto removeprinting
if %errorlevel% EQU 1 goto not-found

:removeprinting
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Printer /c:Printing ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Printer /c:Printing ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Remove-Package
:: ------------------------------------------------------------------------------------

:RASConnectionManager
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-RASConnectionManager
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-RASConnectionManager
cls
reg query "%key%" | findstr /c:RasCMAK
if %errorlevel% EQU 0 goto removerascmak
if %errorlevel% EQU 1 goto not-found

:removerascmak
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:RasCMAK ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:RasCMAK ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:DifferentialCompressionAPI
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-DifferentialCompressionAPI
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-DifferentialCompressionAPI
cls
reg query "%key%" | findstr /c:RDC
if %errorlevel% EQU 0 goto removerdc
if %errorlevel% EQU 1 goto not-found

:removerdc
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:RDC ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:RDC ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:RIPListener
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-RIPListener
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-RIPListener
cls
reg query "%key%" | findstr /c:RasRip
if %errorlevel% EQU 0 goto removerasrip
if %errorlevel% EQU 1 goto not-found

:removerasrip
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:RasRip ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:RasRip ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:ServicesforNFS
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-ServicesforNFS
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-ServicesforNFS
cls
reg query "%key%" | findstr /c:NFS-ClientSKU
if %errorlevel% EQU 0 goto removenfsclientsku
if %errorlevel% EQU 1 goto not-found

:removenfsclientsku
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:NFS-ClientSKU ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:NFS-ClientSKU ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:SimpleNetwork
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-SimpleNetwork
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-SimpleNetwork
cls
reg query "%key%" | findstr /c:SNMP
if %errorlevel% EQU 0 goto removesnmp
if %errorlevel% EQU 1 goto not-found

:removesnmp
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:SNMP ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:SNMP ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:SimpleTCPIP
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-SimpleTCPIP
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-SimpleTCPIP
cls
reg query "%key%" | findstr /c:SimpleTCP
if %errorlevel% EQU 0 goto removesimpletcp
if %errorlevel% EQU 1 goto not-found

:removesimpletcp
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:SimpleTCP ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:SimpleTCP ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:FileSharingSupport
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-FileSharingSupport
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-FileSharingSupport
cls
reg query "%key%" | findstr /c:SMB1
if %errorlevel% EQU 0 goto removesmb1
if %errorlevel% EQU 1 goto not-found

:removesmb1
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:SMB1 ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:SMB1 ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:TelnetClient
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-TelnetClient
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-TelnetClient
cls
reg query "%key%" | findstr /c:Telnet /c:TFTP
if %errorlevel% EQU 0 goto removetelnetclient
if %errorlevel% EQU 1 goto not-found

:removetelnetclient
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Telnet /c:TFTP ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Telnet /c:TFTP ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:IdentifyFoundation
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-IdentifyFoundation
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-IdentifyFoundation
cls
reg query "%key%" | findstr /c:Identity-Foundation
if %errorlevel% EQU 0 goto removeidentityfoundation
if %errorlevel% EQU 1 goto not-found

:removeidentityfoundation
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Identity-Foundation ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Identity-Foundation ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:Powershell2.0
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-Powershell2.0
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-Powershell2.0
cls
reg query "%key%" | findstr /c:PowerShell-V2
if %errorlevel% EQU 0 goto removepowershellv2
if %errorlevel% EQU 1 goto not-found

:removepowershellv2
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:PowerShell-V2 ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:PowerShell-V2 ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:TIFFIFilter
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-TIFFIFilter
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-TIFFIFilter
cls
reg query "%key%" | findstr /c:WinOcr
if %errorlevel% EQU 0 goto removewinocr
if %errorlevel% EQU 1 goto not-found

:removewinocr
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:WinOcr ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:WinOcr ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:XPSServices
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-XPSServices
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-XPSServices
cls
reg query "%key%" | findstr /c:XPSServices
if %errorlevel% EQU 0 goto removexpservices
if %errorlevel% EQU 1 goto not-found

:removexpservices
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:XPSServices ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:XPSServices ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto Remove-Package
:: ------------------------------------------------------------------------------------

:XPSViewer
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-XPSViewer
if %errorlevel% EQU 2 goto Remove-Package
: --------------------------------------------------

:Remove-XPSViewer
cls
reg query "%key%" | findstr /c:Xps-Foundation
if %errorlevel% EQU 0 goto removexpsfoundation
if %errorlevel% EQU 1 goto not-found

:removexpsfoundation
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Xps-Foundation ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Xps-Foundation ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
echo.The operation completed successfully.
pause
goto :question
:: ------------------------------------------------------------------------------------

:not-found
echo.App or Feature not found.
pause
goto :Remove-Package

:Enable-WindowsOptionalFeature
cls
powershell.exe -ExecutionPolicy Bypass -Command "& '%~dp0data\scripts\Enable-WindowsOptionalFeature.ps1'"
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue Enable Windows Features program? (Yes/No) "
if %errorlevel% EQU 1 goto Enable-WindowsOptionalFeature
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Disable-WindowsOptionalFeature
cls
powershell.exe -ExecutionPolicy Bypass -Command "& '%~dp0data\scripts\Disable-WindowsOptionalFeature.ps1'"
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue Disable Windows Features program? (Yes/No) "
if %errorlevel% EQU 1 goto Disable-WindowsOptionalFeature
if %errorlevel% EQU 2 goto :question

:User Account Management
:UserAccountManagement
cls
echo.User Account Management
echo.
echo.You are signing in with username: %username%
echo.
echo.ID	Option
echo.
echo.1	View list user accounts
echo.2	Create a new user
echo.3	Delete user account
echo.4	Enable user account
echo.5	Disable user account
echo.6	Change password
echo.7	Delete password
echo.8	Return Main menu
echo.
choice /c:12345678 /n /m "Select ID for continue : "
if %errorlevel% EQU 1 goto list-user-accounts
if %errorlevel% EQU 2 goto create-a-new-user
if %errorlevel% EQU 3 goto delete-user-account
if %errorlevel% EQU 4 goto enable-user-account
if %errorlevel% EQU 5 goto disable-user-account
if %errorlevel% EQU 6 goto change-password
if %errorlevel% EQU 7 goto delete-password
if %errorlevel% EQU 8 goto :question
:: ------------------------------------------------------------------------------------

:list-user-accounts
cls
echo.List user accounts
net user
pause
goto UserAccountManagement
:: ------------------------------------------------------------------------------------

:create-a-new-user
cls
choice /c:YN /n /m "Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto username
if %errorlevel% EQU 2 goto UserAccountManagement

:username
cls
echo.Create a new user
echo.
echo.You can not create a new user already in the list of user accounts below:
echo.
wmic useraccount where domain='%computername%' get Name,Status
set /p usr=Type a name for the new user :
if [!usr!]==[] goto username
:: --------------------------------------------------

:password
set /p pwd=Type a password for the new user (can be left blank) :
:: --------------------------------------------------

echo.
pause
net user /add "%usr%" %pwd%
net localgroup administrators /add "%usr%"
goto user-account-information

:user-account-information
cls
echo.Name of the new user is: %usr%
echo.Password of the new user is: %pwd%
echo.
echo.You must sign out and sign in with your new user account to complete this operation.
choice /c YN /n /m "Would you like to sign out now? (Yes/No) "
if %errorlevel% EQU 1 goto signout
if %errorlevel% EQU 2 goto UserAccountManagement
:: ------------------------------------------------------------------------------------

:delete-user-account
cls
echo.Delete user account
echo.
echo.Name
for /f "delims=" %%a in ('net localgroup Administrators^|more +6^|find /v "The command completed successfully."') do (
	echo.%%a
)
echo.
echo.WARNING: You can not delete Administrator and %username% account.
set /p usr1=Type username for continue if not press M to return Menu :
if [!usr1!]==[] goto enable-user-account
if [!usr1!]==[M] goto UserAccountManagement
net user "%usr1%" /del
pause
goto UserAccountManagement
:: ------------------------------------------------------------------------------------

:enable-user-account
cls
echo.Enable user account
echo.
wmic useraccount where Status='Degraded' get Name
set /p usr2=Type username for continue if not press M to return Menu :
if [!usr2!]==[] goto enable-user-account
if [!usr2!]==[M] goto UserAccountManagement
net user "%usr2%" /active:yes
pause
goto UserAccountManagement
:: ------------------------------------------------------------------------------------

:disable-user-account
cls
echo.Disable user account
echo.
wmic useraccount where Status='OK' get Name
echo.WARNING: You can not disable the user account that is logged on: %username%
set /p usr3=Type username for continue if not press M to return Menu :
if [!usr3!]==[] goto disable-user-account
if [!usr3!]==[M] goto UserAccountManagement
net user "%usr3%" /active:no
pause
goto UserAccountManagement
:: ------------------------------------------------------------------------------------

:change-password
cls
echo.Change password
echo.
wmic useraccount where Status='OK' get Name
set /p usr4=Type username for continue if not press M to return Menu :
if [!usr4!]==[] goto change-password
if [!usr4!]==[M] goto UserAccountManagement
net user "%usr4%" *
pause
goto UserAccountManagement
:: ------------------------------------------------------------------------------------

:delete-password
cls
echo.Delete password
echo.
wmic useraccount where Status='OK' get Name
set /p usr5=Type username for continue if not press M to return Menu :
if [!usr5!]==[] goto delete-password
if [!usr5!]==[M] goto UserAccountManagement
net user "%usr5%" ""
:: ------------------------------------------------------------------------------------

:signout
shutdown /l
cls
echo Would you like to exit?
set /p f=
if "%f%" == "yes" goto :exit
if "%f%" == "no" goto :question

:Resetupdate
cls
set b=0

:bits
set /a b=%b%+1
if %b% equ 3 (
   goto end1
) 
net stop bits
echo Checking the bits service status.
sc query bits | findstr /I /C:"STOPPED" 
if not %errorlevel%==0 ( 
    goto bits 
) 
goto loop2

:end1
cls
echo.
echo Failed to reset Windows Update due to bits service failing to stop
echo Please run the script as administartor by right clicking the WuReset file or your BITS service isn't responding.
echo.
pause
goto Start


:loop2
set w=0

:wuauserv
set /a w=%w%+1
if %w% equ 3 (
   goto end2
) 
net stop wuauserv
echo Checking the wuauserv service status.
sc query wuauserv | findstr /I /C:"STOPPED" 
if not %errorlevel%==0 ( 
    goto wuauserv 
) 
goto loop3

:end2
cls
echo.
echo Failed to reset Windows Update due to wuauserv service failing to stop.
echo.
pause
goto Start



:loop3
set app=0

:appidsvc
set /a app=%app%+1
if %app% equ 3 (
   goto end3
) 
net stop appidsvc
echo Checking the appidsvc service status.
sc query appidsvc | findstr /I /C:"STOPPED" 
if not %errorlevel%==0 ( 
    goto appidsvc 
) 
goto loop4

:end3
cls
echo.
echo Failed to reset Windows Update due to appidsvc service failing to stop.
echo.
pause
goto Start


:loop4
set c=0

:cryptsvc
set /a c=%c%+1
if %c% equ 3 (
   goto end4
) 
net stop cryptsvc
echo Checking the cryptsvc service status.
sc query cryptsvc | findstr /I /C:"STOPPED" 
if not %errorlevel%==0 ( 
    goto cryptsvc 
) 
goto Reset

:end4
cls
echo.
echo Failed to reset Windows Update due to cryptsvc service failing to stop.
echo.
pause
goto Start

:Reset
Ipconfig /flushdns
del /s /q /f "%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr*.dat"
del /s /q /f "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat" 

cd /d %windir%\system32

if exist "%SYSTEMROOT%\winsxs\pending.xml.bak" del /s /q /f "%SYSTEMROOT%\winsxs\pending.xml.bak" 
if exist "%SYSTEMROOT%\winsxs\pending.xml" ( 
    takeown /f "%SYSTEMROOT%\winsxs\pending.xml" 
    attrib -r -s -h /s /d "%SYSTEMROOT%\winsxs\pending.xml" 
    ren "%SYSTEMROOT%\winsxs\pending.xml" pending.xml.bak 
) 
  
if exist "%SYSTEMROOT%\SoftwareDistribution.bak" rmdir /s /q "%SYSTEMROOT%\SoftwareDistribution.bak"
if exist "%SYSTEMROOT%\SoftwareDistribution" ( 
    attrib -r -s -h /s /d "%SYSTEMROOT%\SoftwareDistribution" 
    ren "%SYSTEMROOT%\SoftwareDistribution" SoftwareDistribution.bak 
) 
 
if exist "%SYSTEMROOT%\system32\Catroot2.bak" rmdir /s /q "%SYSTEMROOT%\system32\Catroot2.bak" 
if exist "%SYSTEMROOT%\system32\Catroot2" ( 
    attrib -r -s -h /s /d "%SYSTEMROOT%\system32\Catroot2" 
    ren "%SYSTEMROOT%\system32\Catroot2" Catroot2.bak 
) 
  
if exist "%SYSTEMROOT%\WindowsUpdate.log.bak" del /s /q /f "%SYSTEMROOT%\WindowsUpdate.log.bak" 
if exist "%SYSTEMROOT%\WindowsUpdate.log" ( 
    attrib -r -s -h /s /d "%SYSTEMROOT%\WindowsUpdate.log" 
    ren "%SYSTEMROOT%\WindowsUpdate.log" WindowsUpdate.log.bak 
) 
  
sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)
sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)

regsvr32.exe /s atl.dll 
regsvr32.exe /s urlmon.dll 
regsvr32.exe /s mshtml.dll 
regsvr32.exe /s shdocvw.dll 
regsvr32.exe /s browseui.dll 
regsvr32.exe /s jscript.dll 
regsvr32.exe /s vbscript.dll 
regsvr32.exe /s scrrun.dll 
regsvr32.exe /s msxml.dll 
regsvr32.exe /s msxml3.dll 
regsvr32.exe /s msxml6.dll 
regsvr32.exe /s actxprxy.dll 
regsvr32.exe /s softpub.dll 
regsvr32.exe /s wintrust.dll 
regsvr32.exe /s dssenh.dll 
regsvr32.exe /s rsaenh.dll 
regsvr32.exe /s gpkcsp.dll 
regsvr32.exe /s sccbase.dll 
regsvr32.exe /s slbcsp.dll 
regsvr32.exe /s cryptdlg.dll 
regsvr32.exe /s oleaut32.dll 
regsvr32.exe /s ole32.dll 
regsvr32.exe /s shell32.dll 
regsvr32.exe /s initpki.dll 
regsvr32.exe /s wuapi.dll 
regsvr32.exe /s wuaueng.dll 
regsvr32.exe /s wuaueng1.dll 
regsvr32.exe /s wucltui.dll 
regsvr32.exe /s wups.dll 
regsvr32.exe /s wups2.dll 
regsvr32.exe /s wuweb.dll 
regsvr32.exe /s qmgr.dll 
regsvr32.exe /s qmgrprxy.dll 
regsvr32.exe /s wucltux.dll 
regsvr32.exe /s muweb.dll 
regsvr32.exe /s wuwebv.dll
regsvr32 /s wudriver.dll
netsh winsock reset
netsh winsock reset proxy

:Start
net start bits
net start wuauserv
net start appidsvc
net start cryptsvc
echo Task completed sucessfully!
echo Please restart your computer and check for the updates again.
set /p f=
if "%f%" == "yes" goto :prompt
if "%f%" == "no" goto :question

:debloat
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:PPIProjection ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:PPIProjection ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Cortana ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Cortana ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:ContactSupport ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:ContactSupport ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Internet-Browser ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Internet-Browser ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Holographic ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Holographic ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
) ELSE (
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
)
for /f %%a in ('dir /b /s ^| findstr /c:OneDriveSetup.exe') do (
	takeown /f %%a
	icacls %%a /grant %username%:F
	start /wait %%a /uninstall
	del /s /q %%a
	goto removeonedrive
)
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:OneDrive ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:OneDrive ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:QuickAssist ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:QuickAssist ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:ContentDeliveryManager ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:ContentDeliveryManager ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:SnippingTool ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:SnippingTool ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:InternetExplorer ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:InternetExplorer ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:MediaPlayback ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:MediaPlayback ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:PrintToPDFServices ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:PrintToPDFServices ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:RDC ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:RDC ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:SMB1 ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:SMB1 ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:XPSServices ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:XPSServices ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
cls
for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /c:Xps-Foundation ') do (
	reg delete "%%a\Owners" /f
	reg add "%%a" /v "Visibility" /t REG_DWORD /d 1 /f
)
for /f "tokens=4" %%a in ('dism /online /get-packages ^| findstr /c:Xps-Foundation ') do (				
	dism /online /remove-package /packagename:"%%a" /norestart
)
reg add "HKCU\Control Panel\International\Geo" /v "Nation" /t REG_SZ /d 251 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowSuggestedAppsInWindowsInkWorkspace" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d 0 /f
cls
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
cls
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f
cls
net stop PlugPlay
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlay" /v "DelayedAutoStart" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 0x00000FF /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 0x00000FF /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AutoPlay" /v Enabled /t REG_DWORD /d 0 /f
cls
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f
cls
taskkill /f /im OneDrive.exe
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f
cls
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
cls
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
cls
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v "PreventLibrarySharing" /t REG_DWORD /d 1 /f
cls
echo Would you like to exit?
set /p f=
if "%f%" == "yes" goto :exit
if "%f%" == "no" goto :exit

:scan
cls 
start sfc /scannow
echo Would you like to exit?
set /p f=
if "%f%" == "yes" goto :exit
if "%f%" == "no" goto :question

:drive
cls
md DriversBackup
Dism /Online /Export-Driver /Destination:%~dp0\DriversBackup
cls
echo Would you like to exit?
set /p f=
if "%f%" == "yes" goto :exit
if "%f%" == "no" goto :question

:disk
cls
DISM.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
echo Would you like to exit?
set /p f=
if "%f%" == "yes" goto :exit
if "%f%" == "no" goto :question

:optimize
bcdedit /set disabledynamictick yes > nul
bcdedit /set useplatformtick yes > nul
bcdedit /set tscsyncpolicy enhanced > nul
bcdedit /set tpmbootentropy ForceDisable > nul
bcdedit /set hypervisorlaunchtype off > nul
bcdedit /set quietboot yes > nul
bcdedit /timeout 0 > nul
bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set nx alwaysoff > nul
bcdedit /set bootux disabled > nul
bcdedit /set bootmenupolicy legacy > nul
bcdedit /set x2apicpolicy disable > nul
bcdedit /set uselegacyapicmode yes > nul
bcdedit /set disabledynamictick yes > nul
bcdedit /set useplatformtick yes > nul
bcdedit /set tscsyncpolicy enhanced > nul
bcdedit /set tpmbootentropy ForceDisable > nul
bcdedit /set hypervisorlaunchtype off > nul
bcdedit /set quietboot yes > nul
bcdedit /timeout 0 > nul
bcdedit /set allowedinmemorysettings 0x0 > nul
bcdedit /set isolatedcontext No > nul
bcdedit /set nx alwaysoff > nul
bcdedit /set bootux disabled > nul
bcdedit /set bootmenupolicy legacy > nul
bcdedit /set x2apicpolicy disable > nul
bcdedit /set uselegacyapicmode yes > nul

Set-Service AppVClient -StartupType Disabled

Set-Service ShellHWDetection -StartupType Disabled

Set-Service bthserv -StartupType Disabled

Set-Service BTAGService -StartupType Disabled

Set-Service lfsvc -StartupType Disabled

Set-Service MapsBroker -StartupType Disabled

Set-Service PimIndexMaintenanceSvc -StartupType Disabled

Set-Service PhoneSvc -StartupType Disabled

Set-Service icssvc -StartupType Disabled" && PowerShell -Command "Set-Service TapiSrv -StartupType Disabled

Set-Service LanmanServer -StartupType Disabled

Set-Service Spooler -StartupType Disabled

Set-Service PrintNotify -StartupType Disabled

Set-Service Fax -StartupType Disabled

Set-Service QWAVE -StartupType Disabled

Set-Service RemoteAccess -StartupType Disabled

Set-Service SCardSvr -StartupType Disabled

Set-Service ScDeviceEnum -StartupType Disabled

Set-Service Themes -StartupType Disabled

Set-Service SSDPSRV -StartupType Disabled

Set-Service HvHost -StartupType Disabled

Set-Service vmickvpexchange -StartupType Disabled

Set-Service vmicguestinterface -StartupType Disabled

Set-Service vmicshutdown -StartupType Disabled

Set-Service vmicheartbeat -StartupType Disabled

Set-Service vmicvmsession -StartupType Disabled

Set-Service vmicrdv -StartupType Disabled

Set-Service vmictimesync -StartupType Disabled

Set-Service vmicvss -StartupType Disabled

Set-Service stisvc -StartupType Disabled

Set-Service wisvc -StartupType Disabled

Set-Service WSearch -StartupType Disabled

Set-Service XblAuthManager -StartupType Disabled

Set-Service XblGameSave -StartupType Disabled

Set-Service XboxNetApiSvc -StartupType Disabled

Set-Service DiagTrack -StartupType Disabled

Set-Service DPS -StartupType Disabled

Set-Service WdiServiceHost -StartupType Disabled

Set-Service WdiSystemHost -StartupType Disabled

Set-Service WerSvc -StartupType Disabled

Set-Service diagsvc -StartupType Disabled
cls
sc stop DoSvc > nul
sc config DoSvc start= disabled > nul
cls
sc stop diagsvc > nul
sc config diagsvc start= disabled > nul
cls
sc stop DPS > nul 
sc config DPS start= disabled > nul
cls
sc stop dmwappushservice > nul
sc config dmwappushservice start= disabled > nul
cls
sc stop MapsBroker > nul
sc config MapsBroker start= disabled > nul
cls
sc stop lfsvc > nul
sc config lfsvc start= disabled > nul
cls
sc stop CscService > nul
sc config CscService start= disabled > nul
cls 
sc stop SEMgrSvc > nul
sc config SEMgrSvc start= disabled > nul
cls
sc stop PhoneSvc > nul
sc config PhoneSvc start= disabled > nul
cls
sc stop RemoteRegistry > nul
sc config RemoteRegistry start= disabled > nul
cls
sc stop RetailDemo > nul
sc config RetailDemo start= disabled > nul
cls
sc stop SysMain > nul
sc config SysMain start= disabled > nul
cls
sc stop WalletService > nul
sc config WalletService start= disabled > nul
cls
sc stop WSearch > nul
sc config WSearch start= disabled > nul
cls
sc stop W32Time > nul
sc config W32Time start= disabled > nul
cls
sc stop AJRouter > nul
sc config AJRouter start= disabled > nul
cls
sc stop tzautoupdate > nul
sc config tzautoupdate start= disabled > nul
cls
sc stop BITS > nul
sc config BITS start= disabled > nul
cls
sc stop KeyIso > nul
sc config KeyIso start= disabled > nul
cls
sc stop DiagTrack > nul
sc config DiagTrack start= disabled > nul
cls 
sc stop CDPSvc > nul
sc config CDPSvc start= disabled > nul
cls
sc stop DusmSvc > nul
sc config DusmSvc start= disabled > nul
cls
sc stop DoSvc > nul
sc config DoSvc start= disabled > nul
cls
sc stop diagsvc > nul
sc config diagsvc start= disabled > nul
cls
sc stop DPS > nul
sc config DPS start= disabled > nul
cls
sc stop WdiServiceHost > nul
sc config WdiServiceHost start= disabled > nul
cls
sc stop WdiSystemHost > nul
sc config WdiSystemHost start= disabled > nul
cls
sc stop dmwappushservice > nul
sc config dmwappushservice start= disabled > nul
cls
sc stop DisplayEnhancementService > nul
sc config DisplayEnhancementService start= disabled > nul
cls
sc stop MapsBroker > nul
sc config MapsBroker start= disabled > nul
cls
sc stop fhsvc > nul
sc config fhsvc start= disabled > nul
cls
sc stop lfsvc > nul
sc config lfsvc start= disabled > nul
cls
sc stop HomeGroupListener > nul
sc config HomeGroupListener start= disabled > nul
cls
sc stop HomeGroupProvider > nul
sc config HomeGroupProvider start= disabled > nul
cls
sc stop NgcSvc > nul
sc config NgcSvc start= disabled > nul
cls
sc stop NgcCtnrSvc > nul
sc config NgcCtnrSvc start= disabled > nul
cls
sc stop SmsRouter > nul
sc config SmsRouter start= disabled > nul
cls
sc stop CscService > nul
sc config CscService start= disabled > nul
cls
sc stop SEMgrSvc > nul
sc config SEMgrSvc start= disabled > nul
cls
sc stop pla > nul
sc config pla start= disabled > nul
cls
sc stop PhoneSvc > nul
sc config PhoneSvc start= disabled > nul
cls
sc stop WpcMonSvc > nul
sc config WpcMonSvc start= disabled > nul
cls
sc stop RasAuto > nul
sc config RasAuto start= disabled > nul
cls
sc stop RasMan > nul
sc config RasMan start= disabled > nul 
cls
sc stop SessionEnv > nul
sc config SessionEnv start= disabled > nul
cls
sc stop TermService > nul
sc config TermService start= disabled > nul
cls
sc stop TermService > nul
sc config TermService start= disabled > nul
cls
sc stop RpcLocator > nul
sc config RpcLocator start= disabled > nul
cls
sc stop RemoteRegistry > nul
sc config RemoteRegistry start= disabled > nul
cls 
sc stop RetailDemo > nul
sc config RetailDemo start= disabled > nul
cls
sc stop SysMain > nul 
sc config SysMain start= disabled > nul
cls
sc stop WalletService > nul
sc config WalletService start= disabled > nul
cls
sc stop WerSvc > nul
sc config WerSvc start= disabled > nul

sc stop WSearch > nul
sc config WSearch start= disabled > nul
 
sc stop W32Time > nul 
sc config W32Time start= disabled > nul

rem **This is the advanced service disabler entry**
:advanced
cls
sc stop AJRouter > nul
sc config AJRouter start= disabled > nul

sc stop AppXSvc > nul
sc config AppXSvc start= disabled > nul

sc stop ALG > nul
sc config ALG start= disabled > nul

sc stop AppMgmt > nul
sc config AppMgmt start= disabled > nul

sc stop tzautoupdate > nul
sc config tzautoupdate start= disabled > nul

sc stop AssignedAccessManagerSvc > nul 
sc config AssignedAccessManagerSvc start= disabled > nul

sc stop BITS > nul
sc config BITS start= disabled > nul

sc stop BDESVC > nul
sc config BDESVC start= disabled > nul

sc stop wbengine > nul
sc config wbengine start= disabled > nul
cls
sc stop BTAGService > nul
sc config BTAGService start= disabled > nul

sc stop bthserv > nul
sc config bthserv start= disabled > nul

sc stop BthHFSrv > nul
sc config BthHFSrv start= disabled > nul

sc stop PeerDistSvc > nul
sc config PeerDistSvc start= disabled > nul

sc stop KeyIso > nul
sc config KeyIso start= disabled > nul

sc stop CertPropSvc > nul 
sc config CertPropSvc start= disabled > nul

sc stop ClipSVC > nul
sc config ClipSVC start= disabled > nul

sc stop DiagTrack > nul
sc config DiagTrack start= disabled > nul

sc stop VaultSvc > nul
sc config VaultSvc start= disabled > nul

sc stop CDPSvc > nul 
sc config CDPSvc start= disabled > nul 

sc stop DusmSvc > nul
sc config DusmSvc start= disabled > nul
 
sc stop DoSvc > nul
sc config DoSvc start= disabled > nul

sc stop diagsvc > nul
sc config diagsvc start= disabled > nul

sc stop DPS > nul
sc config DPS start= disabled > nul

sc stop WdiServiceHost > nul
sc config WdiServiceHost start= disabled > nul

sc stop WdiSystemHost > nul
sc config WdiSystemHost start= disabled > nul

sc stop TrkWks > nul
sc config TrkWks start= disabled > nul

sc stop MSDTC > nul
sc config MSDTC start= disabled > nul

sc stop dmwappushservice > nul 
sc config dmwappushservice start= disabled > nul

sc stop DisplayEnhancementService > nul
sc config DisplayEnhancementService start= disabled > nul

sc stop MapsBroker > nul
sc config MapsBroker start= disabled > nul

sc stop fdPHost > nul
sc config fdPHost start= disabled > nul

sc stop FDResPub > nul
sc config FDResPub start= disabled > nul

sc stop EFS > nul
sc config EFS start= disabled > nul

sc stop EntAppSvc > nul
sc config EntAppSvc start= disabled > nul

sc stop fhsvc > nul
sc config fhsvc start= disabled > nul

sc stop lfsvc > nul
sc config lfsvc start= disabled > nul

sc stop HomeGroupListener > nul
sc config HomeGroupListener start= disabled > nul

sc stop HomeGroupProvider > nul
sc config HomeGroupProvider start= disabled > nul

sc stop HvHost > nul
sc config HvHost start= disabled > nul

sc stop hns > nul
sc config hns start= disabled > nul

sc stop vmickvpexchange > nul
sc config vmickvpexchange start= disabled > nul

sc stop vmicguestinterface > nul
sc config vmicguestinterface start= disabled > nul

sc stop vmicshutdown > nul
sc config vmicshutdown start= disabled > nul

sc stop vmicheartbeat > nul
sc config vmicheartbeat start= disabled > nul

sc stop vmicvmsession > nul
sc config vmicvmsession start= disabled > nul
 
sc stop vmicrdv > nul
sc config vmicrdv start= disabled > nul

sc stop vmictimesync > nul
sc config vmictimesync start= disabled > nul

sc stop vmicvss > nul
sc config vmicvss start= disabled > nul

sc stop IEEtwCollectorService > nul
sc config IEEtwCollectorService start= disabled > nul

sc stop iphlpsvc > nul
sc config iphlpsvc start= disabled > nul 

sc stop IpxlatCfgSvc > nul
sc config IpxlatCfgSvc start= disabled > nul
 
sc stop PolicyAgent > nul
sc config PolicyAgent start= disabled > nul

sc stop irmon > nul
sc config irmon start= disabled > nul

sc stop SharedAccess > nul
sc config SharedAccess start= disabled > nul

sc stop lltdsvc > nul
sc config lltdsvc start= disabled > nul

sc stop diagnosticshub.standardcollector.service > nul
sc config diagnosticshub.standardcollector.service start= disabled > nul

sc stop wlidsvc > nul
sc config wlidsvc start= disabled > nul

sc stop AppVClient > nul
sc config AppVClient start= disabled > nul

sc stop NgcSvc > nul
sc config NgcSvc start= disabled > nul

sc stop NgcCtnrSvc > nul
sc config NgcCtnrSvc start= disabled > nul

sc stop swprv > nul
sc config swprv start= disabled > nul

sc stop smphost > nul
sc config smphost start= disabled > nul

sc stop InstallService > nul
sc config InstallService start= disabled > nul
  
sc stop SmsRouter > nul
sc config SmsRouter start= disabled > nul

sc stop MSiSCSI > nul
sc config MSiSCSI start= disabled > nul

sc stop NaturalAuthentication > nul
sc config NaturalAuthentication start= disabled > nul

sc stop CscService > nul
sc config CscService start= disabled > nul

sc stop defragsvc > nul
sc config defragsvc start= disabled > nul

sc stop SEMgrSvc > nul
sc config SEMgrSvc start= disabled > nul

sc stop PNRPsvc > nul
sc config PNRPsvc start= disabled > nul

sc stop p2psvc > nul
sc config p2psvc start= disabled > nul

sc stop p2pimsvc > nul
sc config p2pimsvc start= disabled > nul

sc stop pla > nul
sc config pla start= disabled > nul

sc stop PhoneSvc > nul
sc config PhoneSvc start= disabled > nul

sc stop WPDBusEnum > nul
sc config WPDBusEnum start= disabled > nul

sc stop Spooler > nul
sc config Spooler start= disabled > nul

sc stop PrintNotify > nul
sc config PrintNotify start= disabled > nul

sc stop PcaSvc > nul
sc config PcaSvc start= disabled > nul

sc stop WpcMonSvc > nul
sc config WpcMonSvc start= disabled > nul

sc stop QWAVE > nul
sc config QWAVE start= disabled > nul

sc stop RasAuto > nul
sc config RasAuto start= disabled > nul
 
sc stop RasMan > nul
sc config RasMan start= disabled > nul

sc stop SessionEnv > nul
sc config SessionEnv start= disabled > nul

sc stop TermService > nul
sc config TermService start= disabled > nul

sc stop UmRdpService > nul 
sc config UmRdpService start= disabled > nul

sc stop RpcLocator > nul
sc config RpcLocator start= disabled > nul

sc stop RemoteRegistry > nul
sc config RemoteRegistry start= disabled > nul

sc stop RetailDemo > nul
sc config RetailDemo start= disabled > nul

sc stop RemoteAccess > nul
sc config RemoteAccess start= disabled > nul
 
sc stop RmSvc > nul 
sc config RmSvc start= disabled > nul

sc stop SNMPTRAP > nul
sc config SNMPTRAP start= disabled > nul

sc stop seclogon > nul
sc config seclogon start= disabled > nul

sc stop wscsvc > nul
sc config wscsvc start= disabled > nul

sc stop SamSs > nul
sc config SamSs start= disabled > nul

sc stop SensorDataService > nul
sc config SensorDataService start= disabled > nul

sc stop SensrSvc > nul
sc config SensrSvc start= disabled > nul

sc stop SensorService > nul
sc config SensorService start= disabled > nul

sc stop LanmanServer > nul
sc config LanmanServer start= disabled > nul

sc stop shpamsvc > nul
sc config shpamsvc start= disabled > nul

sc stop ShellHWDetection > nul
sc config ShellHWDetection start= disabled > nul

sc stop SCardSvr > nul
sc config SCardSvr start= disabled > nul

sc stop ScDeviceEnum > nul
sc config ScDeviceEnum start= disabled > nul

sc stop SCPolicySvc > nul
sc config SCPolicySvc start= disabled > nul

sc stop SharedRealitySvc > nul
sc config SharedRealitySvc start= disabled > nul

sc stop StorSvc > nul
sc config StorSvc start= disabled > nul

sc stop TieringEngineService > nul
sc config TieringEngineService start= disabled > nul

sc stop SysMain > nul
sc config SysMain start= disabled > nul

sc stop SgrmBroker > nul
sc config SgrmBroker start= disabled > nul

sc stop lmhosts > nul
sc config lmhosts start= disabled > nul

sc stop TapiSrv > nul
sc config TapiSrv start= disabled > nul

sc stop Themes > nul
sc config Themes start= disabled > nul

sc stop tiledatamodelsvc > nul
sc config tiledatamodelsvc start= disabled > nul

sc stop TabletInputService > nul
sc config TabletInputService start= disabled > nul

sc stop UsoSvc > nul
sc config UsoSvc start= disabled > nul

sc stop UevAgentService > nul
sc config UevAgentService start= disabled > nul

sc stop VSS > nul
sc config VSS start= disabled > nul

sc stop WalletService > nul
sc config WalletService start= disabled > nul

sc stop wmiApSrv > nul
sc config wmiApSrv start= disabled > nul

sc stop TokenBroker > nul
sc config TokenBroker start= disabled > nul

sc stop WebClient > nul
sc config WebClient start= disabled > nul

sc stop WFDSConMgrSvc > nul
sc config WFDSConMgrSvc start= disabled > nul

sc stop SDRSVC > nul
sc config SDRSVC start= disabled > nul
 
sc stop WbioSrvc > nul
sc config WbioSrvc start= disabled > nul

sc stop FrameServer > nul
sc config FrameServer start= disabled > nul
 
sc stop wcncsvc > nul
sc config wcncsvc start= disabled > nul

sc stop Sense > nul
sc config Sense start= disabled > nul

sc stop WdNisSvc > nul
sc config WdNisSvc start= disabled > nul

sc stop WinDefend > nul
sc config WinDefend start= disabled > nul

sc stop SecurityHealthService > nul
sc config SecurityHealthService start= disabled > nul

sc stop WEPHOSTSVC > nul
sc config WEPHOSTSVC start= disabled > nul

sc stop WerSvc > nul
sc config WerSvc start= disabled > nul

sc stop Wecsvc > nul
sc config Wecsvc start= disabled > nul

sc stop FontCache > nul
sc config FontCache start= disabled > nul
 
sc stop StiSvc > nul
sc config StiSvc start= disabled > nul

sc stop wisvc > nul
sc config wisvc start= disabled > nul

sc stop LicenseManager > nul
sc config LicenseManager start= disabled > nul

sc stop icssvc > nul
sc config icssvc start= disabled > nul

sc stop WMPNetworkSvc > nul
sc config WMPNetworkSvc start= disabled > nul

sc stop FontCache3.0.0.0 > nul
sc config FontCache3.0.0.0 start= disabled > nul

sc stop WpnService > nul
sc config WpnService start= disabled > nul

sc stop perceptionsimulation > nul
sc config perceptionsimulation start= disabled > nul

sc stop spectrum > nul 
sc config spectrum start= disabled > nul
 
sc stop WinRM > nul
sc config WinRM start= disabled > nul

sc stop WSearch > nul
sc config WSearch start= disabled > nul

sc stop SecurityHealthService > nul
sc config SecurityHealthService start= disabled > nul

sc stop W32Time > nul
sc config W32Time start= disabled > nul

sc stop wuauserv > nul
sc config wuauserv start= disabled > nul

sc stop WaaSMedicSvc > nul
sc config WaaSMedicSvc start= disabled > nul

sc stop LanmanWorkstation > nul
sc config LanmanWorkstation start= disabled > nul

sc stop XboxGipSvc > nul
sc config XboxGipSvc start= disabled > nul

sc stop xbgm > nul
sc config xbgm start= disabled > nul

sc stop XblAuthManager > nul
sc config XblAuthManager start= disabled > nul

sc stop XblGameSave > nul
sc config XblGameSave start= disabled > nul
  
sc stop XboxNetApiSvc > nul
sc config XboxNetApiSvc start= disabled > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /v Start /t REG_DWORD /d 00000004 /f > nul 

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\OneSyncSvc" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v Start /t REG_DWORD /d 00000004 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnUserService" /v Start /t REG_DWORD /d 00000004 /f > nul
netsh int tcp set supplemental Internet congestionprovider=ctcp > nul

netsh int tcp set heuristics disabled > nul

netsh int tcp set global autotuninglevel=disabled > nul

netsh int tcp set global chimney=disabled > nul

netsh int tcp set global rss=enabled > nul

netsh int tcp set global rsc=disabled > nul

netsh int tcp set global ecncapability=disabled > nul

netsh int tcp set global timestamps=disabled > nul

netsh int tcp set global initialRto=3000 > nul

powershell -Command "Set-NetTCPSetting -SettingName InternetCustom -MinRto 300" > nul

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 10 /f > nul

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f > nul

powershell -Command "Disable-NetAdapterLso -Name *" > nul

powershell -Command "Set-NetOffloadGlobalSetting -PacketCoalescingFilter disabled" > nul

powershell -Command "Disable-NetAdapterChecksumOffload -Name * -IpIPv4 -TcpIPv4 -TcpIPv6 -UdpIPv4 -UdpIPv6" > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider /v LocalPriority /t REG_DWORD /d 4 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider /v HostPriority /t REG_DWORD /d 5 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider /v DnsPriority /t REG_DWORD /d 6 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider /v NetbtPriority /t REG_DWORD /d 7 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v MaxUserPort /t REG_DWORD /d 65534 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v GlobalMaxTcpWindowSize /t REG_DWORD /d 256960 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v EnableWsd /t REG_DWORD /d 0 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v Tcp1323Opts /t REG_DWORD /d 1 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v TcpMaxDupAcks /t REG_DWORD /d 2 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v TcpWindowSize /t REG_DWORD /d 256960 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v DefaultTTL /t REG_DWORD /d 64 /f > nul 

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v DisableTaskOffload /t REG_DWORD /d 0 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v DisableDynamicDiscovery /t REG_DWORD /d 0 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v EnablePMTUDiscovery /t REG_DWORD /d 1 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v EnablePMTUBDetect /t REG_DWORD /d 0 /f > nul

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v SackOpts /t REG_DWORD /d 1 /f > nul

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v MaxConnectionsPerServer /t REG_DWORD /d 8 /f > nul

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v MaxConnectionsPer1_0Server /t REG_DWORD /d 8 /f > nul 

reg add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v MaxConnectionsPerServer /t REG_DWORD /d 8 /f > nul

reg add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v MaxConnectionsPer1_0Server /t REG_DWORD /d 8 /f > nul

reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched /v TimerResolution /t REG_DWORD /d 1 /f > nul

reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched /v NonBestEffortLimit /t REG_DWORD /d 0 /f > nul

reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched /v MaxOutstandingSends /t REG_DWORD /d 0 /f > nul

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 00000000 /f > nul

REG ADD HKey_Local_Machine\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\ /v TcpAckFrequency /t REG_DWORD /d 0 /f

REG ADD HKey_Local_Machine\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\ /v TCPNoDelay /t REG_DWORD /d 0 /f
cls
taskkill /f /im explorer.exe
cls
start explorer.exe
cls
regsvr32 actxprxy.dll
cls
netsh advfirewall firewall add rule name="StopNetworkThrottling" dir=in action=block remoteip=173.194.55.0/24,206.111.0.0/16 enable=yes
cls
netsh advfirewall firewall add rule name="NetworkTweak" dir=in action=block remoteip=173.194.55.0/24,206.111.0.0/16 enable=yes
cls
ipconfig /flushdns
cls
ipconfig /registerdns
cls
ipconfig /release
cls
ipconfig /renew
cls
netsh winsock reset
netsh advfirewall firewall add rule name="Block Windows Telemetry" dir=in action=block remoteip=134.170.30.202,137.116.81.24,157.56.106.189,184.86.53.99,2.22.61.43,2.22.61.66,204.79.197.200,23.218.212.69,65.39.117.23,65.55.108.23,64.4.54.254 enable=yes > nul
FreeMem=Space(128000000)
cls
-GameTime.MaxSimFps 60+ -GameTime.ForceSimRate 60+
cls
netsh interface ipv4 set subinterface "wireless network Connection" mtu=1492 store=persistent
mystring=(80000000)

fsutil behavior query memoryusage
cls
fsutil behavior set memoryusage 2
cls
bcdedit /set increaseuserva 8000
del /s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q %temp%\*.*
rd /s /q %temp%
del /s /f /q C:\WINDOWS\SoftwareDistribution\Download
md %temp%
cd/
@echo
del *.log /a /s /q /f
for /f "tokens=1,2*" %%V IN ('bcdedit') do set adminTest=%%V
if (%adminTest%)==(Access) exit
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
install_wim_tweak /o /c Windows-Defender /r
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" 
sc delete DiagTrack
sc delete dmwappushservice
sc delete WerSvc
sc delete OneSyncSvc
sc delete MessagingService
sc delete wercplsupport
sc delete PcaSvc
sc config wlidsvc start=demand
sc delete wisvc
sc delete RetailDemo
sc delete diagsvc
sc delete shpamsvc 
sc delete TermService
sc delete UmRdpService
sc delete SessionEnv
sc delete TroubleshootingSvc
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete %I /f)
sc delete diagnosticshub.standardcollector.service
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
install_wim_tweak /o /c Windows-Defender /r
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*"
ipconfig /flushdns
powercfg.exe /hibernate off
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl /v IRQ8Priority /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v HibernateEnabledDefault /t REG_DWORD /d 0000000 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f >nul 2>&1
bcdedit /deletevalue useplatformclock
bcdedit /set disabledynamictick yes
bcdedit /set useplatformtick yes
bcdedit /timeout 0
bcdedit /set nx optout
bcdedit /set bootux disabled
bcdedit /set bootmenupolicy standard
bcdedit /set hypervisorlaunchtype off
bcdedit /set tpmbootentropy ForceDisable
bcdedit /set quietboot yes
bcdedit /set {globalsettings} custom:16000067 true
bcdedit /set {globalsettings} custom:16000069 true
bcdedit /set {globalsettings} custom:16000068 true
bcdedit /set linearaddress57 OptOut
bcdedit /set increaseuserva 268435328
bcdedit /set firstmegabytepolicy UseAll
bcdedit /set avoidlowmemory 0x8000000
bcdedit /set nolowmem Yes
bcdedit /set allowedinmemorysettings 0x0
bcdedit /set isolatedcontext No
bcdedit /set vsmlaunchtype Off
bcdedit /set vm No
bcdedit /set configaccesspolicy Default
bcdedit /set MSI Default
bcdedit /set usephysicaldestination No
bcdedit /set usefirmwarepcisettings No
RD /S /Q %temp%
MKDIR %temp%
takeown /f "%temp%" /r /d y
takeown /f "C:\Windows\Temp" /r /d y
RD /S /Q C:\Windows\Temp
MKDIR C:\Windows\Temp
takeown /f "C:\Windows\Temp" /r /d y
takeown /f %temp% /r /d y
md %temp%
deltree /y c:\windows\tempor~1
deltree /y c:\windows\temp
deltree /y c:\windows\tmp
deltree /y c:\windows\ff*.tmp
deltree /y c:\windows\history
deltree /y c:\windows\cookies
deltree /y c:\windows\recent
deltree /y c:\windows\spool\printers
del c:\WIN386.SWP
schtasks /delete /F /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /delete /F /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /delete /F /TN "\Microsoft\Windows\Autochk\Proxy"
schtasks /delete /F /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /delete /F /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
schtasks /delete /F /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /delete /F /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
schtasks /delete /F /TN "\Microsoft\Windows\PI\Sqm-Tasks"
schtasks /delete /F /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
schtasks /delete /F /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
schtasks /delete /f /tn "\Microsoft\Windows\application experience\Microsoft compatibility appraiser"
schtasks /delete /f /tn "\Microsoft\Windows\application experience\aitagent"
schtasks /delete /f /tn "\Microsoft\Windows\application experience\programdataupdater"
schtasks /delete /f /tn "\Microsoft\Windows\autochk\proxy"
schtasks /delete /f /tn "\Microsoft\Windows\customer experience improvement program\consolidator"
schtasks /delete /f /tn "\Microsoft\Windows\customer experience improvement program\kernelceiptask"
schtasks /delete /f /tn "\Microsoft\Windows\customer experience improvement program\usbceip"
schtasks /delete /f /tn "\Microsoft\Windows\diskdiagnostic\Microsoft-Windows-diskdiagnosticdatacollector"
schtasks /delete /f /tn "\Microsoft\Windows\maintenance\winsat"
schtasks /delete /f /tn "\Microsoft\Windows\media center\activateWindowssearch"
schtasks /delete /f /tn "\Microsoft\Windows\media center\configureinternettimeservice"
schtasks /delete /f /tn "\Microsoft\Windows\media center\dispatchrecoverytasks"
schtasks /delete /f /tn "\Microsoft\Windows\media center\ehdrminit"
schtasks /delete /f /tn "\Microsoft\Windows\media center\installplayready"
schtasks /delete /f /tn "\Microsoft\Windows\media center\mcupdate"
schtasks /delete /f /tn "\Microsoft\Windows\media center\mediacenterrecoverytask"
schtasks /delete /f /tn "\Microsoft\Windows\media center\objectstorerecoverytask"
schtasks /delete /f /tn "\Microsoft\Windows\media center\ocuractivate"
schtasks /delete /f /tn "\Microsoft\Windows\media center\ocurdiscovery"
schtasks /delete /f /tn "\Microsoft\Windows\media center\pbdadiscovery">nul 2>&1
schtasks /delete /f /tn "\Microsoft\Windows\media center\pbdadiscoveryw1"
schtasks /delete /f /tn "\Microsoft\Windows\media center\pbdadiscoveryw2"
schtasks /delete /f /tn "\Microsoft\Windows\media center\pvrrecoverytask"
schtasks /delete /f /tn "\Microsoft\Windows\media center\pvrscheduletask"
schtasks /delete /f /tn "\Microsoft\Windows\media center\registersearch"
schtasks /delete /f /tn "\Microsoft\Windows\media center\reindexsearchroot"
schtasks /delete /f /tn "\Microsoft\Windows\media center\sqlliterecoverytask"
schtasks /delete /f /tn "\Microsoft\Windows\media center\updaterecordpath"
echo Would you like to exit?
set /p l=
if "%l%" == "yes" goto :exit
if "%l%" == "no" goto :question
cls

:info
cls
echo The optimizations, Are From Everytingtech,Trimors,Warxen. Sub To Him. They Make Optimizations.
echo This take 2 Days To Complete. For The Optimization.
echo Would you like to exit?
set /p f=
if "%f%" == "yes" goto :exit
if "%f%" == "no" goto :question
cls

:restore
cls
Wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Boost CPU Performance", 100, 12
echo System Restore Point Successfully Would You Like To Use It?

echo Would you like to exit?
set /p f=
if "%f%" == "yes" goto :exit
if "%f%" == "no" goto :question
cls

:restore-Pc
cls
echo.WARNING: The Computer needs to reboot and take some time to complete this process.
choice /c YN /n /m "Are you sure? (Y/N): "
if %errorlevel% EQU 1 powershell.exe -ExecutionPolicy Bypass -Command "& '%~dp0data\scripts\Restore-Computer.ps1'"
if %errorlevel% EQU 2 goto Menu
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto :prompt
if %errorlevel% EQU 2 goto :question

:revert
cls
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "On" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 0 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 1 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl /v IRQ8Priority /t REG_DWORD /d 0 /f
install_wim_tweak /o /c Windows-Defender /r
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 1 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /enable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /enable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /enable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /enable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /enable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /enable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /enable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /enable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /enable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /enable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /enable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /enable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /enable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /enable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /enable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /enable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /enable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /enable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /enable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /enable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /enable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /enable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /enable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /enable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /enable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /enable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /enable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /enable
bcdedit /set useplatformclock yes
bcdedit /set disabledynamictick no
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 1 /f >nul 2>&1
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl /v IRQ8Priority /t REG_DWORD /d 0 /f
taskkill /f /im explorer.exe
pause
start explorer.exe
echo Windows 11 Optimizations Applied!
echo Would you like to exit?
set /p d=
if "%d%" == "yes" goto :exit
if "%d%" == "no" goto :question
cls


:restore
cls
Wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Restore Point", 100, 12
echo System Restore Point Successfully created!
echo Would you like to exit?
set /p f=
if "%f%" == "yes" goto :exit
if "%f%" == "no" goto :question
cls

:revert
cls
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "On" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 0 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 1 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl /v IRQ8Priority /t REG_DWORD /d 0 /f
install_wim_tweak /o /c Windows-Defender /r
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 1 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /enable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /enable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /enable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /enable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /enable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /enable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /enable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /enable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /enable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /enable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /enable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /enable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /enable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /enable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /enable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /enable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /enable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /enable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /enable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /enable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /enable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /enable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /enable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /enable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /enable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /enable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /enable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /enable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /enable
bcdedit /set useplatformclock yes
bcdedit /set disabledynamictick no
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 1 /f >nul 2>&1
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl /v IRQ8Priority /t REG_DWORD /d 0 /f
taskkill /f /im explorer.exe
pause
start explorer.exe
echo Windows 10 Debloat Successfully Reverted!
echo Would you like to exit?
set /p g=
if "%g%" == "yes" goto :exit
if "%g%" == "no" goto :question
cls

:restart
cls
shutdown /r -t 300
echo Would you like to exit?
set /p f=
if "%f%" == "yes" goto :exit
if "%f%" == "no" goto :question
cls

:exit 
cls
exit
cls
