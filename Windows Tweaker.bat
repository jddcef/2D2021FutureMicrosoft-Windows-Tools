echo off
color 03
title Windows Tweaker
cls

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
bcdedit /deletevalue {current} safeboot
bcdedit /deletevalue {current} safebootalternateshell
bcdedit /deletevalue {current} removememory
bcdedit /deletevalue {current} truncatememory
bcdedit /deletevalue {current} useplatformclock
bcdedit /deletevalue {default} safeboot
bcdedit /deletevalue {default} safebootalternateshell
bcdedit /deletevalue {default} removememory
bcdedit /deletevalue {default} truncatememory
bcdedit /deletevalue {default} useplatformclock
bcdedit /set {bootmgr} displaybootmenu no
bcdedit /set {current} advancedoptions false
bcdedit /set {current} bootems no
bcdedit /set {current} bootmenupolicy legacy
bcdedit /set {current} bootstatuspolicy IgnoreAllFailures
bcdedit /set {current} disabledynamictick yes
bcdedit /set {current} lastknowngood yes
bcdedit /set {current} recoveryenabled no
bcdedit /set {default} advancedoptions false
bcdedit /set {default} bootems no
bcdedit /set {default} bootmenupolicy legacy
bcdedit /set {default} bootstatuspolicy IgnoreAllFailures
bcdedit /set {default} disabledynamictick yes
bcdedit /set {default} lastknowngood yes
bcdedit /set {default} recoveryenabled no

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Discord" /t REG_SZ /d "%LocalAppData%\Discord\app-1.0.9002\Discord.exe --start-minimized" /f
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /t REG_SZ /d "\"%ProgramFiles% (x86)\Microsoft OneDrive\OneDrive.exe\" /background" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Malwarebytes Windows Firewall Control" /t REG_SZ /d "\"%ProgramFiles%\Malwarebytes\Windows Firewall Control\wfc.exe"\" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\System32\userinit.exe," /f
reg add "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /v "PSUAMain" /t REG_SZ /d "\"%ProgramFiles% (x86)\Panda Security\Panda Security Protection\PSUAMain.exe\" /LaunchSysTray" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /t REG_MULTI_SZ /d "autocheck autochk *" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /t REG_MULTI_SZ /d "" /f

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

sc config WerSvc start= disabled

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

reg delete "HKCU\Software\Classes\ms-settings\shell\open" /f
reg delete "HKCU\Software\Microsoft\Command Processor" /v "AutoRun" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "Load" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKCU\Software\Policies" /f
reg delete "HKLM\Software\Microsoft\Command Processor" /v "AutoRun" /f
reg delete "HKLM\Software\Microsoft\Policies" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
reg delete "HKLM\Software\Policies" /f
reg delete "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /f
reg delete "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Policies" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
reg delete "HKLM\Software\WOW6432Node\Policies" /f
reg delete "HKLM\System\CurrentControlSet\Control\Keyboard Layout" /v "Scancode Map" /f
reg delete "HKLM\System\CurrentControlSet\Control\SafeBoot" /v "AlternateShell" /f
reg delete "HKLM\System\CurrentControlSet\Control\SecurePipeServers\winreg" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "Execute" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /f
reg delete "HKLM\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /v "StartupPrograms" /f
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
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d "0" /f
install_wim_tweak /o /c Windows-Defender /r
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
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
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
cls
echo Windows Optimization Has Been Applied! Would you like to exit? (Yes/No)
set /p l=
if "%l%" == "yes" goto :exit
if "%l%" == "no" goto :exit
cls

:exit
exit
cls
exit
