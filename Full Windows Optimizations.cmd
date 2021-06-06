echo off
color F6
title All In One Optimization Script
mode con: cols=82 lines=21

:last verification
cls
timeout 1 > nul
cls
echo Are You Sure Do You Want To Do? [Disable,Remove,Optimize]
echo Do You Want To Continue? Type "Yes" To Contiune Or "No" To Cancel.
set /p a=
if "%a%" == "Yes" goto :Full Windows Boost
if "%a%" == "No" goto :Exit
cls

:Exit
cls
echo Ok, You Changed You Mind. LOL
timeout 2 > nul

echo Exiting...
timeout 1 > nul
exit

:Full Windows Boost
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
rem **This is the standard service disabler entry**
:standard
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
echo Disabled Unnecessary Services.
timeout 2 > nul
cls
echo 2. Network Boost.
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

taskkill /f /im explorer.exe

start explorer.exe

regsvr32 actxprxy.dll

netsh advfirewall firewall add rule name="StopThrottling" dir=in action=block remoteip=173.194.55.0/24,206.111.0.0/16 enable=yes

netsh advfirewall firewall add rule name="YouTubeTweak" dir=in action=block remoteip=173.194.55.0/24,206.111.0.0/16 enable=yes
echo Network Is Optimized!
timeout 2 > nul
cls

echo Windows Telemetry And Bloatware Removal 
timeout 2 > nul
cls
netsh advfirewall firewall add rule name="Block Windows Telemetry" dir=in action=block remoteip=134.170.30.202,137.116.81.24,157.56.106.189,184.86.53.99,2.22.61.43,2.22.61.66,204.79.197.200,23.218.212.69,65.39.117.23,65.55.108.23,64.4.54.254 enable=yes > nul
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
sc delete diagnosticshub.standardcollector.service
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
echo Good Telemetry Is Disabled!
timeout 2 > nul
cls

echo Windows Optimizations
timeout 2 > nul
cls
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
powercfg.exe /hibernate off
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl /v IRQ8Priority /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v HibernateEnabledDefault /t REG_DWORD /d 0000000 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f >nul 2>&1
taskkill /f /im explorer.exe
pause
start explorer.exe
echo Windows Is Now Optimized!
timeout 2 > nul
cls

echo Debloat
timeout 2 > nul
cls
setlocal enabledelayedexpansion
for /f "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set "del=%%a"
)
:main
call :colortext F0 "This script is"
call :colortext FA " SEMI-REVERSIBLE"
call :colortext F0 " and will allow you to choose apps you want to remove." && echo .
echo Keep in mind that not every app can come back, are you sure you want to continue?
set /p con=
if /i "%con%" == "no" cls && echo Exiting. && timeout 1 >nul && cls && echo Exiting.. && timeout 1 >nul && cls && echo Exiting... && timeout 1 >nul && cls && exit
if /i "%con%" == "yes" (
       goto debloat
) else (
     cls && echo Misspell detected.
     timeout 2 >nul
     cls && echo Returning. && timeout 1 >nul && cls && echo Returning.. && timeout 1 >nul && cls && echo Returning... && timeout 1 >nul && cls
     goto :exit
)

debloat
cls
call :colortext FC "Remove" && echo  3D Builder?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.3DBuilder* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  3D Print?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Print3D* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  3D Viewer?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Alarms App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Bing News?
set /p con=
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Calculator App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsCalculator* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Camera App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsCamera* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Cortana (App only)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.549981C3F5F10* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Feedback Hub?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Get Help?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage" && cls  
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Get Started?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Maps App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Messaging?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Advertising Client?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Advertising.Xaml* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Edge?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftEdge.Stable* | Remove-AppxPackage" && cd %PROGRAMFILES(X86)%\Microsoft\Edge\Application\8*\Installer && setup --uninstall --force-uninstall --system-level && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Office (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage" > nul && PowerShell -Command "Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.Office.Desktop* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Mail and Calendar?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *microsoft.windowscommunicationsapps* | Remove-AppxPackage"  && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Mixed Reality Portal?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MixedReality.Portal* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Pay?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Wallet* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft People?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.People* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft OneNote?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Office.OneNote* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Snip and Sketch?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.ScreenSketch* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Solitare Collection?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Sticky Notes App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Store?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsStore* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Store Purchase (breaks MS Store)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.StorePurchaseApp* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Zune Video and Music Apps?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Photos App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Windows.Photos* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Remote Desktop?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.RemoteDesktop* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Sound Recording App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Weather App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Xbox App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.XboxApp* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Xbox Extras?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.XboxGameOverlay* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.XboxIdentityProvider* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage" && reg delete "HKEY_CURRENT_USER\System\GameConfigStore\Parents" /f >nul && reg delete "HKEY_CURRENT_USER\System\GameConfigStore\Children" /f >nul && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Your Phone?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext F6 "Preinstalled" && echo  Bloatware
timeout 3 >nul
cls && cls
call :colortext FC "Remove" && echo  Adobe Photoshop Express (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *AdobeSystemsIncorporated.AdobePhotoshopExpress* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Remove Candy Crush (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *CandyCrush* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Remove Duolingo (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Duolingo-LearnLanguagesforFree* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Remove Facebook (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Facebook* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Remove Flipboard (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Flipboard* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Intel Graphics Control Panel (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *AppUp.IntelGraphicsControlPanel* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  LinkedIn (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *7EE7776C.LinkedInforWindows* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Uninstall" && echo  Microsoft OneDrive?
set /p con= 
if /i "%con%" == "yes" cls && %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall >nul && %SystemRoot%\System32\OneDriveSetup.exe /uninstall >nul && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Mirkat (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Mirkat.Mirkat* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  MS Paint (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MSPaint* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Network Speed Test (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.NetworkSpeedTest* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Spotify (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Spotify* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Realtek Audio Console (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *RealtekSemiconductorCorp.RealtekAudioControl* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Skype (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Twitter (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Twitter* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls
cls
echo Booster
timeout 2 > nul
cls
FreeMem=Space(128000000)

-GameTime.MaxSimFps 60+ -GameTime.ForceSimRate 60+

netsh interface ipv4 set subinterface "wireless network Connection" mtu=1492 store=persistent
cls
echo Your Windows 10 Is Boosted To Max Performance.
timeout 2 > nul
cls

echo Boost Responsive 
timeout 2 > nul
cls
mystring=(80000000)

fsutil behavior query memoryusage

fsutil behavior set memoryusage 2

bcdedit /set increaseuserva 8000

echo Windows 10 Has Boost Responsive.
timeout 2 > nul
cls

echo Now The Last Step Is Clean Cache Folders [Free Disk Space]
timeout 2 > nul
cls
del /s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q %temp%\*.*
rd /s /q %temp%
del /s /f /q C:\WINDOWS\SoftwareDistribution\Download
md %temp%
for /f "tokens=1,2*" %%V IN ('bcdedit') do set adminTest=%%V
if (%adminTest%)==(Access) exit
for /f "tokens=*" %%G in ('wevtutil.exe el') do (call :wevtutil "%%G")

:wevtutil
echo clearing %1
wevtutil.exe cl %1
cls

echo Thank You For Using All in One Optimization Script.
timeout 3 > nul
cls
echo Bye Bye.
timeout 1 > nul
cls
exit

