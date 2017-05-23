@ECHO off &SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
ECHO Checking for Administrator elevation...
ECHO.
openfiles > NUL 2>&1
IF NOT ERRORLEVEL 1 (
        ECHO Elevation found! Proceeding...
) ELSE (
        ECHO You are not running as Administrator...
        ECHO This batch cannot do it's job without elevation!
        ECHO.
        ECHO Right-click and select ^'Run as Administrator^' and try again...
        ECHO.
        ECHO Press any key to exit...
        PAUSE > NUL
        exit
)

FOR /F "TOKENS=4-7 DELIMS=[.] " %%i IN ('ver') DO (IF %%i==Version (SET winversion=%%j%%k) ELSE (SET winversion=%%i%%j))
FOR /F "TOKENS=1,* DELIMS==" %%u IN ('WMIC OS GET CAPTION /VALUE') DO IF /I "%%u"=="Caption" SET winedition=%%v
SET winedition=%winedition:~10%

TITLE WINDOWS GAMING TWEAKS BY rype

:HOME
CLS
CALL :XTITLE WINDOWS GAMING TWEAKS BY rype
ECHO Your Windows Edition: %winedition%
ECHO.
ECHO Select:
ECHO.
CALL :XMENU Service Tweaks 
CALL :XMENU System Tweaks
CALL :XMENU Network Tweaks
IF %winversion% == 100 (CALL :XMENU Remove Windows 10 Apps) ELSE (CALL :XMENU N/A)
CALL :XMENU PowerConfig Tweaks
CALL :XMENU Disable Graphiccard Sound
IF %winversion% == 100 (CALL :XMENU Remove OneDrive) ELSE (CALL :XMENU N/A)
CALL :XMENU Remove Telemetry (Microsoft Anti-Spy)
CALL :XMENU Automatic Tweaks and Anti-Spy
ECHO.


SET /p web=Type option:
IF "%web%"=="1" GOTO :SVCMENU
IF "%web%"=="2" GOTO :SYSTWEAK
IF "%web%"=="3" GOTO :NETTWEAK
IF %winversion% == 100 (IF "%web%"=="4" GOTO :RMWINAPPS)
IF "%web%"=="5" GOTO :POWERTWEAK
IF "%web%"=="6" GOTO :DISGRAPHIXSOUND
IF %winversion% == 100 (IF "%web%"=="7" GOTO :RMONEDRIVE)
IF "%web%"=="8" GOTO :RMTELEMETRY
IF "%web%"=="9" GOTO :AUTOTWEAKS
GOTO :HOME


:SVCMENU
CALL :XTITLE SERVICE TWEAKS BY Black Viper - www.blackviper.com
ECHO.
ECHO Select:
ECHO.
CALL :XMENU Safe
CALL :XMENU Tweaked
CALL :XMENU Default
ECHO.


SET /p web=Type option:
IF "%web%"=="1" GOTO :SVCSAFE
IF "%web%"=="2" GOTO :SVCTWEAKED
IF "%web%"=="3" GOTO :SVCDEFAULT

:SYSTWEAK
CALL :XTITLE GENERAL SYSTEM TWEAKS
IF %winversion% GEQ 61 (
	CALL :XECHO OS compatibility tweaks - crash, data collection, timeouts, game priority
	FOR %%I IN (AitAgent ProgramDataUpdater) DO SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\%%I" /DISABLE >nul 2>&1
	FOR %%I IN (Autochk\Proxy Maintenance\WinSAT WindowsBackup\ConfigNotification DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector) DO SCHTASKS /Change /TN "\Microsoft\Windows\%%I" /DISABLE >nul 2>&1
	FOR %%I IN (Consolidator KernelCeipTask UsbCeip) DO SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\%%I" /DISABLE >nul 2>&1
	REG ADD "HKCU\Control Panel\Desktop" /F /v HungAppTimeout /T REG_SZ /D 5000 >nul 2>&1
	REG ADD "HKCU\Control Panel\Desktop" /F /v LowLevelHooksTimeout /T REG_SZ /D 5000 >nul 2>&1
	REG ADD "HKCU\Control Panel\Desktop" /F /v WaitToKillAppTimeout /T REG_SZ /D 20000 >nul 2>&1
	REG ADD "HKCU\Software\Microsoft\InputPersonalization" /F /v RestrictImplicitInkCollection /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKCU\Software\Microsoft\InputPersonalization" /F /v RestrictImplicitTextCollection /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /F /v EnableWebContentEvaluation /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKCU\Software\Policies\Microsoft\Windows\AppCompat" /F /v DisablePCA /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /F /v DisableMFUTracking /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Affinity" /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Background Only" /T REG_SZ /D "False" >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "GPU Priority" /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Priority" /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Scheduling Category" /T REG_SZ /D "High" >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "SFIO Priority" /T REG_SZ /D "High" >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /F /v CrashDumpEnabled /T REG_DWORD /D 3 >nul 2>&1
	REG ADD "HKLM\SYSTEM\ControlSet001\Control\CrashControl" /F /v CrashDumpEnabled /T REG_DWORD /D 3 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /F /v DontVerifyRandomDrivers /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /F /v IRQ8Priority /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /F /v CountOperations /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /F /v "DisablePagingExecutive" /T REG_DWORD /D 1 >nul 2>&1
	REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\App Management" /F /v COMClassStore >nul 2>&1
	DEL /F /Q "%WINDIR%\SYSTEM32\mss32.dll" >nul 2>&1
	DEL /F /Q "%WINDIR%\SysWOW64\mss32.dll" >nul 2>&1
	SC config "AeLookupSvc" start= demand >nul 2>&1
	SC start "AeLookupSvc" >nul 2>&1 
	
	CALL :XECHO OS visual fx tweaks - less animations
	REG ADD "HKCU\Control Panel\Desktop\WindowMetrics" /F /v VisualFXSetting /T REG_DWORD /D 3 >nul 2>&1
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /F /v VisualFXSetting /T REG_DWORD /D 3 >nul 2>&1
	REG ADD "HKCU\Control Panel\Desktop" /F /v UserPreferencesMask /T REG_BINARY /D 9812038010000000 >nul 2>&1
	FOR %%I IN (CompositionPolicy ListBoxSmoothScrolling TooltipAnimation TaskbarAnimations SelectionFade MenuAnimation ListviewWatermark ListviewShadow ListviewAlphaSelect DropShadow CursorShadow ControlAnimations ComboBoxAnimation AnimateMinMax) DO REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\%%I" /F /v DefaultApplied /T REG_DWORD /D 0 >nul 2>&1
	FOR %%I IN (ThumbnailsOrIcon Themes FontSmoothing DragFullWindows) DO REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\%%I" /F /v DefaultApplied /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKCU\Control Panel\Desktop\WindowMetrics" /F /v MinAnimate /T REG_SZ /D 0 >nul 2>&1
	REG ADD "HKCU\Software\Microsoft\Windows\DWM" /F /v Max3DWindows /T REG_DWORD /D 4 >nul 2>&1
)
GOTO :HOME


:NETTWEAK
CALL :XTITLE GENERAL NETWORK TWEAKS
CALL :XECHO HW network driver tweaks - flow control, buffers, offload processing
FOR /F "tokens=3*" %%I IN ('REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /F "ServiceName" /S^|FINDSTR /I /L "ServiceName"') DO (
FOR /F %%A IN ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}" /F "%%I" /D /E /S ^|FINDSTR /I /L /V "Linkage"^|FINDSTR /I /L "\\Class\\"') DO SET "REGPATH=%%A" >nul 2>&1
	FOR %%n IN (#FlowControl #InterruptModeration #LsoV1IPv4 #LsoV2IPv4 #LsoV2IPv6 #PMARPOffload #PMNSOffload #PriorityVLANTag #WakeOnMagicPacket #WakeOnPattern AdaptiveIFS ITR MasterSlave WaitAutoNegComplete) DO (
		SET opt=%%n
		SET opt=!opt:#=*!
		REG QUERY "!REGPATH!" /V !opt! >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V !opt! /T REG_SZ /D 0 >nul 2>&1 )
	FOR %%m IN () DO (
		SET opt=%%m
		SET opt=!opt:#=*!
		REG QUERY "!REGPATH!" /V !opt! >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V !opt! /T REG_SZ /D 1 >nul 2>&1 )
	FOR %%o IN (#IPChecksumOffloadIPv4 #TCPChecksumOffloadIPv4 #TCPChecksumOffloadIPv6 #UDPChecksumOffloadIPv4 #UDPChecksumOffloadIPv6) DO (
		SET opt=%%o
		SET opt=!opt:#=*!
		REG QUERY "!REGPATH!" /V !opt! >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V !opt! /T REG_SZ /D 3 >nul 2>&1 )
	REG QUERY "!REGPATH!" /V "*JumboPacket" >nul 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "*JumboPacket" /T REG_SZ /D 1514 >nul 2>&1
	REG QUERY "!REGPATH!" /V "WolShutdownLinkSpeed" >nul 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "WolShutdownLinkSpeed" /T REG_SZ /D 2 >nul 2>&1
	REG QUERY "!REGPATH!" /V "*SSIdleTimeout" >nul 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "*SSIdleTimeout" /T REG_SZ /D 60 >nul 2>&1
	REG QUERY "!REGPATH!" /V "LogLinkStateEvent" >nul 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "LogLinkStateEvent" /T REG_SZ /D 16 >nul 2>&1
)
:: Speedguide.net tweaks
IF %winversion% GEQ 51 (
	CALL :XECHO Disable Nagle's Algorithm
	FOR /F "tokens=3*" %%I IN ('REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /F "ServiceName" /S^|FINDSTR /I /L "ServiceName"') DO (
		REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%I" /F /v TcpAckFrequency /T REG_DWORD /D 1 >nul 2>&1
		REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%I" /F /v TCPNoDelay /T REG_DWORD /D 1 >nul 2>&1
		REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%I" /F /v TcpDelAckTicks /T REG_DWORD /D 0 >nul 2>&1
	)
	SET /A _tcpservpri_=3 &FOR %%I IN (LocalPriority HostsPriority DnsPriority NetbtPriority Class) DO (SET /A _tcpservpri_+=1 &REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /F /v %%I /T REG_DWORD /D !_tcpservpri_! >nul 2>&1)
) 
IF %winversion% GEQ 61 (
	CALL :XECHO Network Throttling Index Gaming Tweak
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /F /v NetworkThrottlingIndex /T REG_DWORD /D 0xFFFFFFFF >nul 2>&1
	CALL :XECHO System Responsiveness Gaming Tweak
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /F /v SystemResponsiveness /T REG_DWORD /D 0 >nul 2>&1
	CALL :XECHO Turn off LargeSystemCache
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /F /v LargeSystemCache /T REG_DWORD /D 0 >nul 2>&1
	CALL :XECHO Other Common Fixes
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /F /v autodisconnect /T REG_DWORD /D 0xFFFFFFFF >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\lanmanworkstation\parameters" /F /v KeepConn /T REG_DWORD /D 0x7D00 >nul 2>&1
	CALL :XECHO Set QoS to 0%
	REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /F /v NonBestEffortLimit /T REG_DWORD /D 0 >nul 2>&1
)
IF %winversion% == 61 (
	NETSH int tcp SET heuristics wsh=disabled 
	NETSH int ip SET global taskoffload=enabled
	FOR %%I IN ("autotuninglevel=normal" "chimney=disabled" "congestionprovider=ctcp" "netdma=disabled" "rss=disable" "timestamps=disabled") DO NETSH int tcp SET global %%~I >nul 2>&1
	FOR %%I IN (tcp udp) DO netsh int ipv4 SET dynamicport %%I start=32767 num=32767 >nul 2>&1
	FOR %%I IN (MaxNegativeCacheTtl NegativeCacheTime NegativeSOACacheTime NetFailureCacheTime) DO REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /F /v %%I /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /F /v TCPNoDelay /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /F /v NetworkThrottlingIndex /T REG_DWORD /D 0xFFFFFFFF >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /F /v SystemResponsiveness /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /F /v DisableBandwidthThrottling /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /F /v DisableLargeMtu /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v DefaultTTL /T REG_DWORD /D 0x40 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v DisableLargeMtu /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v DisableTaskOffload /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v EnableConnectionRateLimiting /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v EnableTCPA /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v EnableWsd /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /F /v StrictTimeWaitSeqCheck /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /F /v Tcp1323Opts /T REG_DWORD /D 3 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /F /v TcpCreateAndConnectTcbRateLimitDepth /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v TCPMaxDataRetransmissions /T REG_DWORD /D 5 >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /F /v TcpTimedWaitDelay /T REG_DWORD /D 0x3c >nul 2>&1
)
IF %winversion% == 100 (
	CALL :XECHO Receive Window Auto-Tuning Level SET to normal
	powershell "Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal" >nul 2>&1
	CALL :XECHO Disable Windows Scaling heuristics
	powershell "Set-NetTCPSetting -SettingName InternetCustom -ScalingHeuristics Disabled" >nul 2>&1
	CALL :XECHO Congestion Control Provider SET to CTCP
	powershell "Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider CTCP" >nul 2>&1
	CALL :XECHO Disable TCP Chimney Offload
	powershell "Set-NetOffloadGlobalSetting -Chimney Disabled" >nul 2>&1
	CALL :XECHO Disable ECN Capability
	powershell "Set-NetTCPSetting -SettingName InternetCustom -EcnCapability Disabled" >nul 2>&1
	CALL :XECHO Disable TCP 1323 Timestamps
	powershell "Set-NetTCPSetting -SettingName InternetCustom -Timestamps Disabled" >nul 2>&1
	CALL :XECHO Enable Direct Cache Access (DCA)
	netsh int tcp SET global dca=enabled >nul 2>&1
	CALL :XECHO Enable Checksum Offload
	powershell "Enable-NetAdapterChecksumOffload -Name *" >nul 2>&1
	CALL :XECHO Enable Receive-Side Scaling State (RSS)
	powershell "Enable-NetAdapterRss -Name *" >nul 2>&1
	CALL :XECHO Disable Receive Segment Coalescing State (RSC)
	powershell "Disable-NetAdapterRsc -Name *" >nul 2>&1
	CALL :XECHO Disable Large Send Offload (LSO)
	powershell "Disable-NetAdapterLso -Name *" >nul 2>&1
	CALL :XECHO Max SYN Retransmissions SET to 2
	powershell "Set-NetTCPSetting -SettingName InternetCustom -MaxSynRetransmissions 2" >nul 2>&1
	CALL :XECHO Disable Non Sack Rtt Resiliency
	powershell "Set-NetTCPSetting -SettingName InternetCustom -NonSackRttResiliency disabled" >nul 2>&1
	CALL :XECHO Initial RTO and Min RTO
	powershell "Set-NetTCPSetting -SettingName InternetCustom -InitialRto 2000" >nul 2>&1
	powershell "SET-NetTCPSetting -SettingName InternetCustom -MinRto 300" >nul 2>&1
	ECHO.
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Ndu" /F /v Start /T REG_DWORD /D 4 >nul 2>&1
	FOR %%I IN ("Microsoft Kernel Debug Network Adapter" "WAN Miniport" "Teredo Tunneling") DO powershell "Get-PnpDevice | Where-Object { $_.FriendlyName -match '%%I' } | Disable-PnpDevice -Confirm:$false"  >nul 2>&1
)
PAUSE
GOTO :HOME


:RMWINAPPS
CALL :XTITLE REMOVE WINDOWS APPS
ECHO.
ECHO  	 Question:
ECHO.
CALL :XMENU Permanently Remove Apps 
CALL :XMENU Uninstall Apps 
ECHO.
SET /p web=Type option:
IF "%web%"=="1" GOTO :PRA
IF "%web%"=="2" GOTO :UA
:PRA
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *BingFinance* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *BingNews* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *BingSports* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *BingWeather* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *Getstarted* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *MicrosoftOfficeHub* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *MicrosoftSolitaireCollection* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *Office.OneNote* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *People* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *SkypeApp* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *Windows.Photos* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *WindowsAlarms* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *WindowsCalculator* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *WindowsCamera* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *windowscommunicationsapps* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *WindowsMaps* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *WindowsPhone* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *WindowsSoundRecorder* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *XboxApp* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *ZuneMusic* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *ZuneVideo* | remove-appxprovisionedpackage -online"
powershell "Get-appxprovisionedpackage -online | Where DisplayName -like *3DBuilder* | remove-appxprovisionedpackage -online"
PAUSE
GOTO :HOME
:UA
powershell "Get-AppxPackage *BingFinance* | Remove-AppxPackage"
powershell "Get-AppxPackage *BingNews* | Remove-AppxPackage"
powershell "Get-AppxPackage *BingSports* | Remove-AppxPackage"
powershell "Get-AppxPackage *BingWeather* | Remove-AppxPackage"
powershell "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
powershell "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage"
powershell "Get-AppxPackage *MicrosoftSolitaireCollection* | Remove-AppxPackage"
powershell "Get-AppxPackage *Office.OneNote* | Remove-AppxPackage"
powershell "Get-AppxPackage *People* | Remove-AppxPackage"
powershell "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
powershell "Get-AppxPackage *Windows.Photos* | Remove-AppxPackage"
powershell "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
powershell "Get-AppxPackage *WindowsCalculator* | Remove-AppxPackage"
powershell "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
powershell "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
powershell "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
powershell "Get-AppxPackage *WindowsPhone* | Remove-AppxPackage"
powershell "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"
powershell "Get-AppxPackage *XboxApp* | Remove-AppxPackage"
powershell "Get-AppxPackage *ZuneMusic* | Remove-AppxPackage"
powershell "Get-AppxPackage *ZuneVideo* | Remove-AppxPackage"
powershell "Get-AppxPackage *3DBuilder* | Remove-AppxPackage"
PAUSE
GOTO :HOME



::::::::::::::::::::::::::
:: POWERSETTINGS TWEAKS ::
::::::::::::::::::::::::::
:POWERTWEAK
CALL :XTITLE POWERCONFIG TWEAKS
CALL :XECHO Backup Stock Settings 
powercfg /qh > powerconfig.txt

CALL :XECHO Activate High Performance Scheme
powercfg -setactive scheme_min

CALL :XECHO Processor performance increase threshold / Schwellenwert zum Erhöhen der Prozessorleistung
ECHO Optimized Value: 0%
powercfg -attributes SUB_PROCESSOR 06cadf0e-64ed-448a-8927-ce7bf90eb35d -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 06cadf0e-64ed-448a-8927-ce7bf90eb35d 0


CALL :XECHO Processor performance decrease threshold / Schwellenwert zum Reduzieren der Prozessorleistung
ECHO Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR 12a0ab44-fe28-4fa9-b3bd-4b64f44960a6 -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 12a0ab44-fe28-4fa9-b3bd-4b64f44960a6 100


CALL :XECHO Processor performance decrease policy / Prozessorleistung - Reduzierungsrichtlinie
ECHO Optimized Value: Rocket
powercfg -attributes SUB_PROCESSOR 40fbefc7-2e9d-4d25-a185-0cfd8574bac6 -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 40fbefc7-2e9d-4d25-a185-0cfd8574bac6 2
powercfg -setactive scheme_current

CALL :XECHO Processor performance increase policy / Prozessorleistung - Erhöhungsrichtlinie
ECHO Optimized Value: Ideal
powercfg -attributes SUB_PROCESSOR 465e1f50-b610-473a-ab58-00d1077dc418 -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 465e1f50-b610-473a-ab58-00d1077dc418 0

CALL :XECHO Processor idle demote threshold / Prozessorleerlauf - Schwellenwert für Herabstufung
ECHO Optimized Value: 0%
powercfg -attributes SUB_PROCESSOR 4b92d758-5a24-4851-a470-815d78aee119 -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 4b92d758-5a24-4851-a470-815d78aee119 0


CALL :XECHO Processor idle promote threshold / Prozessorleerlauf - Schwellenwert für Heraufstufung
ECHO Optimized Value: 0%
powercfg -attributes SUB_PROCESSOR 7b224883-b3cc-4d79-819f-8374152cbe7c -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 7b224883-b3cc-4d79-819f-8374152cbe7c 0


CALL :XECHO Processor performance core parking over utilization threshold / Prozessorleistung: Parken von Kernen - Schwellenwert für übermäßige Kernnutzung
ECHO Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR 943c8cb6-6f93-4227-ad87-e9a3feec08d1 -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 943c8cb6-6f93-4227-ad87-e9a3feec08d1 100

CALL :XECHO Processor performance boost mode / Leistungssteigerungsmodus für Prozessoren
ECHO Optimized Value: Enabled
powercfg -attributes SUB_PROCESSOR be337238-0d82-4146-a960-4f3749d470c7 -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor be337238-0d82-4146-a960-4f3749d470c7 1

CALL :XECHO Processor idle disable / Prozessorleerlauf deaktivieren
ECHO Optimized Value: idle disabled
powercfg -attributes SUB_PROCESSOR 5d76a2ca-e8c0-402f-a133-2158492d58ad -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad 1

CALL :XECHO Allow Throttle States / Drosselungszustände zulassen
ECHO Optimized Value: Disabled
powercfg -attributes SUB_PROCESSOR 3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb 0

CALL :XECHO Upper bound for processor performance throttling / Maximum processor state / Drosselungszustände zulassen
ECHO Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR bc5038f7-23e0-4960-96da-33abaf5935ec -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor bc5038f7-23e0-4960-96da-33abaf5935ec 100

CALL :XECHO Lower bound for processor performance throttling / Minimum processor state / Drosselungszustände zulassen
ECHO Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR 893dee8e-2bef-41e0-89c6-b55d0929964c -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 893dee8e-2bef-41e0-89c6-b55d0929964c 100

CALL :XECHO Core-Parking
ECHO Processor performance core parking min cores
powercfg -attributes SUB_PROCESSOR 0cc5b647-c1df-4637-891a-dec35c318583 -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 0cc5b647-c1df-4637-891a-dec35c318583 100

ECHO Core-Parking for Skylake
ECHO Processor performance autonomous mode / Autonomer Modus für die Prozessorleistung
powercfg -attributes SUB_PROCESSOR 8baa4a8a-14c6-4451-8e8b-14bdbd197537 -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 8baa4a8a-14c6-4451-8e8b-14bdbd197537 1
ECHO Processor energy performance preference policy / Richtlinie für die bevorzugte Prozessorenergieeffizienz
powercfg -attributes SUB_PROCESSOR 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 0
ECHO Processor duty cycling / Prozessor-Aussetzbetrieb
powercfg -attributes SUB_PROCESSOR 4e4450b3-6179-4e91-b8f1-5bb9938f81a1 -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 4e4450b3-6179-4e91-b8f1-5bb9938f81a1 0
ECHO Processor autonomous activity window / Fenster für die autonome Prozessoraktivität
powercfg -attributes SUB_PROCESSOR cfeda3d0-7697-4566-a922-a9086cd49dfa -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor cfeda3d0-7697-4566-a922-a9086cd49dfa 30000

CALL :XECHO Save new settings
powercfg -setactive scheme_current
GOTO :HOME


:DISGRAPHIXSOUND 
FOR %%I IN ("NVIDIA High Definition Audio") DO powershell "Get-PnpDevice | Where-Object { $_.FriendlyName -match '%%I' } | Disable-PnpDevice -Confirm:$false"  >nul 2>&1
GOTO :HOME



::::::::::::::::::::::::::::::::
:: REMOVE MICROSOFT ONEDRIVE  ::
::::::::::::::::::::::::::::::::
:RMONEDRIVE
CALL :XTITLE Uninstalling OneDrive
SET x86="%SYSTEMROOT%\System32\OneDriveSetup.exe"
SET x64="%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe"
taskkill /f /im OneDrive.exe > NUL 2>&1
ping 127.0.0.1 -n 5 > NUL 2>&1 
IF exist %x64% (
%x64% /uninstall
) ELSE (
%x86% /uninstall
)
ping 127.0.0.1 -n 8 > NUL 2>&1 
rd "%USERPROFILE%\OneDrive" /Q /S > NUL 2>&1
rd "C:\OneDriveTemp" /Q /S > NUL 2>&1
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S > NUL 2>&1
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S > NUL 2>&1 
ECHO.
ECHO Removeing OneDrive from the Explorer Side Panel.
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1
GOTO :HOME

:8 
GOTO :HOME



:::::::::::::::::::::::::::::::::
:: REMOVE MICROSOFT TELEMETRY  ::
:::::::::::::::::::::::::::::::::
:RMTELEMETRY
CALL :XTITLE EDITING HOSTS FILE
FOR %%I IN (adnxs.com c.msn.com g.msn.com h1.msn.com msedge.net ads.msn.com adnexus.net
ac3.msn.com c.atdmt.com m.adnxs.com rad.msn.com so.2mdn.net ads1.msn.com ec.atdmt.com flex.msn.com rad.live.com
ui.skype.com msftncsi.com a-msedge.net a.rad.msn.com b.rad.msn.com cdn.atdmt.com m.hotmail.com ads1.msads.net
a.ads1.msn.com a.ads2.msn.com apps.skype.com b.ads1.msn.com view.atdmt.com watson.live.com aidps.atdmt.com 
preview.msn.com static.2mdn.net a.ads2.msads.net b.ads2.msads.net db3aqu.atdmt.com secure.adnxs.com www.msftncsi.com 
cs1.wpc.v0cdn.net live.rads.msn.com ad.doubleclick.net bs.serving-sys.com a-0001.a-msedge.net pricelist.skype.com 
stats-microsoft.com a-0002.a-msedge.net a-0003.a-msedge.net a-0004.a-msedge.net a-0005.a-msedge.net a-0006.a-msedge.net
a-0007.a-msedge.net a-0008.a-msedge.net a-0009.a-msedge.net choice.microsoft.com watson.microsoft.com feedback.windows.com 
aka-cdn-ns.adtech.de cds26.ams9.msecn.net lb1.www.ms.akadns.net corp.sts.microsoft.com az361816.vo.msecnd.net 
az512334.vo.msecnd.net telemetry.microsoft.com msntest.serving-sys.com secure.flashtalking.com telemetry.appex.bing.net 
pre.footprintpredict.com vortex.data.microsoft.com statsfe2.ws.microsoft.com statsfe1.ws.microsoft.com df.telemetry.microsoft.com 
feedback.microsoft-hohm.com oca.telemetry.microsoft.com sqm.telemetry.microsoft.com telemetry.urs.microsoft.com 
survey.watson.microsoft.com compatexchange.cloudapp.net s.gateway.messenger.live.com vortex-win.data.microsoft.com feedback.search.microsoft.com 
schemas.microsoft.akadns.net watson.telemetry.microsoft.com choice.microsoft.com.nsatc.net wes.df.telemetry.microsoft.com sqm.df.telemetry.microsoft.com 
settings-win.data.microsoft.com redir.metaservices.microsoft.com i1.services.social.microsoft.com vortex-sandbox.data.microsoft.com 
diagnostics.support.microsoft.com watson.ppe.telemetry.microsoft.com msnbot-65-55-108-23.search.msn.com telecommand.telemetry.microsoft.com 
settings-sandbox.data.microsoft.com sls.update.microsoft.com.akadns.net fe2.update.microsoft.com.akadns.net vortex-bn2.metron.live.com.nsatc.net 
vortex-cy2.metron.live.com.nsatc.net oca.telemetry.microsoft.com.nsatc.net sqm.telemetry.microsoft.com.nsatc.net reports.wes.df.telemetry.microsoft.com 
corpext.msitadfs.glbdns2.microsoft.com services.wes.df.telemetry.microsoft.com watson.telemetry.microsoft.com.nsatc.net statsfe2.update.microsoft.com.akadns.net 
i1.services.social.microsoft.com.nsatc.net telecommand.telemetry.microsoft.com.nsatc.net telemetry.appex.bing.com) DO ( 
	FIND /C /I "%%I" %WINDIR%\system32\drivers\etc\hosts > NUL 2>&1
	IF !ERRORLEVEL! neq 0 (
		CALL :XECHOF Add %%I to hosts
		ECHO ^0.0.0.0 %%I>>%WINDIR%\system32\drivers\etc\hosts
	)
)	
pause
GOTO :HOME


:AUTOTWEAKS
CALL :SVCTWEAKED
CALL :SYSTWEAK
CALL :POWERTWEAK
CALL :NETTWEAK
CALL :RMONEDRIVE
CALL :RMTELEMETRY
CALL :XDONE
GOTO :HOME




:::::::::::::::::::::::::::::::::
:: WINDOWS SVC BY Black Viper  ::
:::::::::::::::::::::::::::::::::
:SVCSAFE
IF %winversion% == 100 (
	ECHO.
	ECHO Select:
	ECHO.
	ECHO 1. DESKTOP
	ECHO 2. LAPTOP or TABLET
	ECHO.


	SET /p web=Type option:
	IF "%web%"=="1" GOTO :SVCSAFEDESK
	IF "%web%"=="2" GOTO :SVCSAFELAPTAB
)
IF %winversion% == 61 (
	::Automatic
	FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS Dnscache FDResPub gpsvc 
	MMCSS NlaSvc nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer 
	ShellHWDetection sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv 
	AudioEndpointBuilder WinDefend EventLog MpsSvc FontCache Winmgmt wuauserv LanmanWorkstation) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
	::Manual
	FOR %%I IN (AxInstSV SensrSvc AeLookupSvc AppIDSvc Appinfo ALG BITS BDESVC wbengine KeyIso 
	COMSysApp Browser VaultSvc WdiServiceHost WdiSystemHost defragsvc MSDTC EFS EapHost Fax fdPHost 
	hkmsvc HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect PolicyAgent KtmRm lltdsvc 
	clr_optimization_v2.0.50727 swprv Netman netprofm PNRPsvc p2psvc p2pimsvc pla IPBusEnum PNRPAutoReg 
	WPDBusEnum wercplsupport PcaSvc ProtectedStorage QWAVE RasAuto RasMan SessionEnv TermService 
	UmRdpService seclogon SstpSvc sppuinotify SSDPSRV TabletInputService TapiSrv THREADORDER TBS upnphost 
	vds VSS WebClient SDRSVC WbioSrvc idsvc WcsPlugInService wudfsvc WerSvc Wecsvc StiSvc msiserver 
	ehRecvr ehSched TrustedInstaller FontCache3.0.0.0 WinRM W32Time WinHttpAutoProxySvc dot3svc Wlansvc 
	wmiApSrv WwanSvc) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
	::Disabled
	FOR %%I IN (AppMgmt bthserv PeerDistSvc CertPropSvc TrkWks SharedAccess iphlpsvc Mcx2Svc MSiSCSI 
	NetTcpPortSharing Netlogon napagent CscService WPCSvc RpcLocator RemoteRegistry RemoteAccess 
	SCardSvr SCPolicySvc SNMPTRAP StorSvc wcncsvc WMPNetworkSvc WSearch) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
)
GOTO :HOME
:SVCTWEAKED
IF %winversion% == 100 (
	::Automatic
	FOR %%I IN (BITS BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_????? DiagTrack 
	CoreMessagingRegistrar CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache gpsvc 
	LSM NlaSvc nsi Power Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection 
	sppsvc SysMain OneSyncSvc_????? SENS SystemEventsBroker Schedule Themes tiledatamodelsvc 
	UserManager ProfSvc AudioSrv AudioEndpointBuilder Wcmsvc WinDefend SecurityHealthService 
	EventLog MpsSvc FontCache Winmgmt WpnService WSearch LanmanWorkstation) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
	::Manual
	FOR %%I IN (AxInstSV AppReadiness AppIDSvc Appinfo AppXSVC BDESVC wbengine ClipSVC KeyIso 
	COMSysApp Browser PimIndexMaintenanceSvc_????? VaultSvc DsSvc DeviceAssociationService 
	DeviceInstall DmEnrollmentSvc DsmSVC DevicesFlowUserSvc_????? DevQueryBroker WdiServiceHost 
	WdiSystemHost MSDTC embeddedmode EFS EntAppSvc EapHost fhsvc fdPHost FDResPub HomeGroupListener 
	HomeGroupProvider hidserv IKEEXT UI0Detect PolicyAgent KtmRm lltdsvc MessagingService_????? 
	diagnosticshub.standardcollector.service wlidsvc NgcSvc NgcCtnrSvc swprv smphost NcbService 
	Netman NcaSVC netprofm NetSetupSvc defragsvc PNRPsvc p2psvc p2pimsvc PerfHost pla PlugPlay 
	PNRPAutoReg WPDBusEnum PrintNotify wercplsupport QWAVE RmSvc RasAuto RasMan seclogon SstpSvc 
	svsvc SSDPSRV StateRepository WiaRpc StorSvc TieringEngineService lmhosts TapiSrv TimeBroker 
	TokenBroker UsoSvc upnphost UserDataSvc_????? UnistoreSvc_????? vds VSS WalletService SDRSVC 
	WbioSrvc Sense WdNisSvc wudfsvc WEPHOSTSVC WerSvc Wecsvc StiSvc msiserver LicenseManager 
	TrustedInstaller WpnUserService_????? W32Time wuauserv WinHttpAutoProxySvc dot3svc WlanSvc 
	wmiApSrv XboxGipSvc) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
	::Disabled
	FOR %%I IN (AJRouter ALG AppMgmt tzautoupdate BthHFSrv bthserv PeerDistSvc CertPropSvc 
	NfsClnt dmwappushsvc MapsBroker lfsvc HvHost vmickvpexchange vmicguestinterface vmicshutdown 
	vmicheartbeat vmicvmsession vmicrdv vmictimesync vmicvss irmon SharedAccess iphlpsvc IpxlatCfgSvc 
	wlpasvc AppVClient MSiSCSI SmsRouter NaturalAuthentication Netlogon NcdAutoSetup CscService 
	SEMgrSvc PhoneSvc SessionEnv TermService UmRdpService RpcLocator RemoteRegistry RetailDemo 
	RemoteAccess SensorDataService SensrSvc SensorService shpamsvc SCardSvr ScDeviceEnum SCPolicySvc 
	SNMPTRAP TabletInputService UevAgentService WebClient WFDSConSvc FrameServer wcncsvc wisvc 
	WMPNetworkSvc icssvc WinRM WwanSvc XblAuthManager XblGameSave XboxNetApiSvc) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
)
IF %winversion% == 61 (
	::Automatic
	FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp Dnscache gpsvc MMCSS NlaSvc 
	nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection 
	sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv AudioEndpointBuilder WinDefend 
	EventLog MpsSvc FontCache Winmgmt wuauserv LanmanWorkstation) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
	::Manual
	FOR %%I IN (AeLookupSvc AppIDSvc Appinfo BITS wbengine KeyIso COMSysApp Browser defragsvc 
	MSDTC EapHost HomeGroupListener HomeGroupProvider IKEEXT PolicyAgent KtmRm clr_optimization_v2.0.50727 
	swprv Netman netprofm pla ProtectedStorage RasAuto RasMan seclogon SstpSvc sppuinotify SSDPSRV TapiSrv 
	THREADORDER upnphost vds VSS SDRSVC wudfsvc Wecsvc StiSvc msiserver TrustedInstaller FontCache3.0.0.0 
	W32Time dot3svc Wlansvc wmiApSrv) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
	::Disabled
	FOR %%I IN (AxInstSV SensrSvc ALG AppMgmt BDESVC bthserv PeerDistSvc CertPropSvc VaultSvc DPS WdiServiceHost 
	WdiSystemHost TrkWks EFS Fax fdPHost FDResPub hkmsvc hidserv UI0Detect SharedAccess iphlpsvc lltdsvc Mcx2Svc 
	MSiSCSI NetTcpPortSharing Netlogon napagent CscService WPCSvc PNRPsvc p2psvc p2pimsvc IPBusEnum PNRPAutoReg 
	WPDBusEnum wercplsupport PcaSvc QWAVE SessionEnv TermService UmRdpService RpcLocator RemoteRegistry RemoteAccess 
	SCardSvr SCPolicySvc SNMPTRAP StorSvc TabletInputService TBS WebClient WbioSrvc idsvc WcsPlugInService wcncsvc 
	WerSvc ehRecvr ehSched WMPNetworkSvc WinRM WSearch WinHttpAutoProxySvc WwanSvc) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
)
GOTO :HOME
:SVCDEFAULT
ECHO.
ECHO SET DEFAULT SERVICES FOR %winedition%
PAUSE
IF %winversion% == 100 (
	IF "%winedition%" == "Windows 10 Home" (
		::Automatic
		FOR %%I IN (BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_????? DiagTrack CoreMessagingRegistrar 
		CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache MapsBroker gpsvc iphlpsvc LSM NlaSvc nsi 
		Power Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection sppsvc SysMain 
		OneSyncSvc_????? SENS SystemEventsBroker Schedule Themes tiledatamodelsvc UserManager ProfSvc 
		AudioSrv AudioEndpointBuilder Wcmsvc WinDefend SecurityHealthService EventLog MpsSvc FontCache 
		Winmgmt WpnService WSearch WlanSvc LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
		::Manual
		FOR %%I IN (AxInstSV AJRouter AppReadiness AppIDSvc Appinfo ALG AppXSVC BITS BDESVC wbengine BthHFSrv 
		bthserv CertPropSvc ClipSVC KeyIso COMSysApp Browser PimIndexMaintenanceSvc_????? VaultSvc DsSvc 
		DeviceAssociationService DeviceInstall DmEnrollmentSvc DsmSVC DevicesFlowUserSvc_????? DevQueryBroker 
		WdiServiceHost WdiSystemHost MSDTC dmwappushsvc embeddedmode EFS EntAppSvc EapHost Fax fhsvc fdPHost 
		FDResPub lfsvc HomeGroupListener HomeGroupProvider hidserv HvHost vmickvpexchange vmicguestinterface 
		vmicshutdown vmicheartbeat vmicvmsession vmicrdv vmictimesync vmicvss IKEEXT irmon UI0Detect SharedAccess 
		IpxlatCfgSvc PolicyAgent KtmRm lltdsvc wlpasvc MessagingService_????? diagnosticshub.standardcollector.service 
		wlidsvc MSiSCSI NgcSvc NgcCtnrSvc swprv smphost SmsRouter NaturalAuthentication Netlogon NcdAutoSetup NcbService 
		Netman NcaSVC netprofm NetSetupSvc defragsvc SEMgrSvc PNRPsvc p2psvc p2pimsvc PerfHost pla PhoneSvc PlugPlay 
		PNRPAutoReg WPDBusEnum PrintNotify wercplsupport QWAVE RmSvc RasAuto RasMan SessionEnv TermService UmRdpService 
		RpcLocator RetailDemo seclogon SstpSvc SensorDataService SensrSvc SensorService ScDeviceEnum SCPolicySvc SNMPTRAP 
		svsvc SSDPSRV StateRepository WiaRpc StorSvc TieringEngineService lmhosts TapiSrv TimeBroker TokenBroker 
		TabletInputService UsoSvc upnphost UserDataSvc_????? UnistoreSvc_????? vds VSS WalletService WebClient 
		WFDSConSvc SDRSVC WbioSrvc FrameServer wcncsvc WdNisSvc wudfsvc WEPHOSTSVC WerSvc Wecsvc StiSvc wisvc msiserver 
		LicenseManager WMPNetworkSvc icssvc TrustedInstaller WpnUserService_????? WinRM W32Time wuauserv WinHttpAutoProxySvc 
		dot3svc wmiApSrv workfolderssvc WwanSvc XboxGipSvc XblAuthManager XblGameSave XboxNetApiSvc) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
		::Disabled
		FOR %%I IN (tzautoupdate NetTcpPortSharing RemoteRegistry RemoteAccess shpamsvc SCardSvr) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
	)
	IF "%winedition%" == "Windows 10 Pro" (
		::Automatic
		FOR %%I IN (BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_????? DiagTrack CoreMessagingRegistrar 
		CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache MapsBroker gpsvc iphlpsvc LSM NlaSvc nsi Power
		Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection sppsvc SysMain OneSyncSvc_????? 
		SENS SystemEventsBroker Schedule Themes tiledatamodelsvc UserManager ProfSvc AudioSrv AudioEndpointBuilder 
		Wcmsvc WinDefend SecurityHealthService EventLog MpsSvc FontCache Winmgmt WpnService WSearch WlanSvc LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
		::Manual
		FOR %%I IN (AxInstSV AJRouter AppReadiness AppIDSvc Appinfo ALG AppMgmt AppXSVC BITS BDESVC wbengine BthHFSrv 
		bthserv PeerDistSvc CertPropSvc ClipSVC KeyIso COMSysApp Browser PimIndexMaintenanceSvc_????? VaultSvc DsSvc 
		DeviceAssociationService DeviceInstall DmEnrollmentSvc DsmSVC DevicesFlowUserSvc_????? DevQueryBroker WdiServiceHost 
		WdiSystemHost MSDTC dmwappushsvc embeddedmode EFS EntAppSvc EapHost Fax fhsvc fdPHost FDResPub lfsvc HomeGroupListener 
		HomeGroupProvider hidserv HvHost vmickvpexchange vmicguestinterface vmicshutdown vmicheartbeat vmicvmsession vmicrdv 
		vmictimesync vmicvss IKEEXT irmon UI0Detect SharedAccess IpxlatCfgSvc PolicyAgent KtmRm lltdsvc wlpasvc MessagingService_????? 
		diagnosticshub.standardcollector.service wlidsvc MSiSCSI NgcSvc NgcCtnrSvc swprv smphost SmsRouter NaturalAuthentication 
		Netlogon NcdAutoSetup NcbService Netman NcaSVC netprofm NetSetupSvc CscService defragsvc SEMgrSvc PNRPsvc p2psvc p2pimsvc 
		PerfHost pla PhoneSvc PlugPlay PNRPAutoReg WPDBusEnum PrintNotify wercplsupport QWAVE RmSvc RasAuto RasMan SessionEnv 
		TermService UmRdpService RpcLocator RetailDemo seclogon SstpSvc SensorDataService SensrSvc SensorService ScDeviceEnum 
		SCPolicySvc SNMPTRAP svsvc SSDPSRV StateRepository WiaRpc StorSvc TieringEngineService lmhosts TapiSrv TimeBroker TokenBroker 
		TabletInputService UsoSvc upnphost UserDataSvc_????? UnistoreSvc_????? vds VSS WalletService WebClient WFDSConSvc SDRSVC 
		WbioSrvc FrameServer wcncsvc Sense WdNisSvc wudfsvc WEPHOSTSVC WerSvc Wecsvc StiSvc wisvc msiserver LicenseManager 
		WMPNetworkSvc icssvc TrustedInstaller WpnUserService_????? WinRM W32Time wuauserv WinHttpAutoProxySvc dot3svc wmiApSrv 
		workfolderssvc WwanSvc XboxGipSvc XblAuthManager XblGameSave XboxNetApiSvc) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
		::Disabled
		FOR %%I IN (tzautoupdate AppVClient NetTcpPortSharing RemoteRegistry RemoteAccess shpamsvc SCardSvr UevAgentService) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
	)
)
IF %winversion% == 61 (
	IF "%winedition%" == "Windows 7 Starter" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc
		MMCSS NlaSvc nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection
		sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv AudioEndpointBuilder WinDefend EventLog
		MpsSvc FontCache Winmgmt WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
		::Manual
		FOR %%I IN (AxInstSV AeLookupSvc AppIDSvc Appinfo ALG BITS BDESVC wbengine bthserv CertPropSvc KeyIso 
		COMSysApp Browser VaultSvc WdiServiceHost WdiSystemHost defragsvc MSDTC EFS EapHost Fax fdPHost hkmsvc 
		HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect PolicyAgent KtmRm lltdsvc clr_optimization_v2.0.50727 
		MSiSCSI swprv Netlogon napagent Netman netprofm WPCSvc PNRPsvc p2psvc p2pimsvc pla IPBusEnum PNRPAutoReg 
		WPDBusEnum wercplsupport PcaSvc ProtectedStorage QWAVE RasAuto RasMan SessionEnv TermService RpcLocator 
		RemoteRegistry seclogon SstpSvc SCardSvr SCPolicySvc SNMPTRAP sppuinotify SSDPSRV TabletInputService 
		TapiSrv THREADORDER TBS upnphost vds VSS WebClient SDRSVC WbioSrvc idsvc WcsPlugInService wcncsvc wudfsvc 
		WerSvc Wecsvc StiSvc msiserver WMPNetworkSvc TrustedInstaller FontCache3.0.0.0 WinRM W32Time WinHttpAutoProxySvc 
		dot3svc Wlansvc wmiApSrv WwanSvc) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
	)
	IF "%winedition%" == "Windows 7 Home Basic" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc 
		MMCSS NlaSvc nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection 
		sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv AudioEndpointBuilder WinDefend EventLog 
		MpsSvc FontCache Winmgmt WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
		::Manual
		FOR %%I IN (AxInstSV SensrSvc AeLookupSvc AppIDSvc Appinfo ALG BITS BDESVC wbengine bthserv CertPropSvc 
		KeyIso COMSysApp Browser VaultSvc WdiServiceHost WdiSystemHost defragsvc MSDTC EFS EapHost Fax fdPHost 
		hkmsvc HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect PolicyAgent KtmRm lltdsvc clr_optimization_v2.0.50727 
		MSiSCSI swprv Netlogon napagent Netman netprofm WPCSvc PNRPsvc p2psvc p2pimsvc pla IPBusEnum PNRPAutoReg WPDBusEnum 
		wercplsupport PcaSvc ProtectedStorage QWAVE RasAuto RasMan SessionEnv TermService RpcLocator RemoteRegistry seclogon 
		SstpSvc SCardSvr SCPolicySvc SNMPTRAP sppuinotify SSDPSRV TabletInputService TapiSrv THREADORDER TBS upnphost vds 
		VSS WebClient SDRSVC WbioSrvc idsvc WcsPlugInService wcncsvc wudfsvc WerSvc Wecsvc StiSvc msiserver WMPNetworkSvc 
		TrustedInstaller FontCache3.0.0.0 WinRM W32Time WinHttpAutoProxySvc dot3svc Wlansvc wmiApSrv WwanSvc) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
	)
	IF "%winedition%" == "Windows 7 Home Premium" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc MMCSS 
		NlaSvc nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection sppsvc SysMain 
		SENS Schedule lmhosts Themes ProfSvc AudioSrv AudioEndpointBuilder WinDefend EventLog MpsSvc FontCache Winmgmt 
		WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
		::Manual
		FOR %%I IN (AxInstSV SensrSvc AeLookupSvc AppIDSvc Appinfo ALG BITS BDESVC wbengine bthserv CertPropSvc KeyIso 
		COMSysApp Browser VaultSvc WdiServiceHost WdiSystemHost defragsvc MSDTC EFS EapHost Fax fdPHost hkmsvc HomeGroupListener 
		HomeGroupProvider hidserv IKEEXT UI0Detect PolicyAgent KtmRm lltdsvc clr_optimization_v2.0.50727 MSiSCSI swprv Netlogon 
		napagent Netman netprofm WPCSvc PNRPsvc p2psvc p2pimsvc pla IPBusEnum PNRPAutoReg WPDBusEnum wercplsupport PcaSvc 
		ProtectedStorage QWAVE RasAuto RasMan SessionEnv TermService RpcLocator RemoteRegistry seclogon SstpSvc SCardSvr SCPolicySvc 
		SNMPTRAP sppuinotify SSDPSRV TabletInputService TapiSrv THREADORDER TBS upnphost vds VSS WebClient SDRSVC WbioSrvc idsvc 
		WcsPlugInService wcncsvc wudfsvc WerSvc Wecsvc StiSvc msiserver ehRecvr ehSched WMPNetworkSvc TrustedInstaller 
		FontCache3.0.0.0 WinRM W32Time WinHttpAutoProxySvc dot3svc Wlansvc wmiApSrv WwanSvc) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess Mcx2Svc NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
	)
	IF "%winedition%" == "Windows 7 Professional" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc 
		clr_optimization_v2.0.50727 MMCSS NlaSvc nsi CscService PlugPlay Power Spooler RpcSs RpcEptMapper SamSs 
		wscsvc LanmanServer ShellHWDetection sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv 
		AudioEndpointBuilder WinDefend EventLog MpsSvc FontCache Winmgmt WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
		::Manual
		FOR %%I IN (AxInstSV SensrSvc AeLookupSvc AppIDSvc Appinfo ALG AppMgmt BITS BDESVC wbengine bthserv 
		PeerDistSvc CertPropSvc KeyIso COMSysApp Browser VaultSvc WdiServiceHost WdiSystemHost defragsvc MSDTC
		EFS EapHost Fax fdPHost hkmsvc HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect PolicyAgent 
		KtmRm lltdsvc MSiSCSI swprv Netlogon napagent Netman netprofm WPCSvc PNRPsvc p2psvc p2pimsvc pla IPBusEnum 
		PNRPAutoReg WPDBusEnum wercplsupport PcaSvc ProtectedStorage QWAVE RasAuto RasMan SessionEnv TermService 
		UmRdpService RpcLocator RemoteRegistry seclogon SstpSvc SCardSvr SCPolicySvc SNMPTRAP sppuinotify SSDPSRV 
		StorSvc TabletInputService TapiSrv THREADORDER TBS upnphost vds VSS WebClient SDRSVC WbioSrvc idsvc 
		WcsPlugInService wcncsvc wudfsvc WerSvc Wecsvc StiSvc msiserver ehRecvr ehSched WMPNetworkSvc TrustedInstaller 
		FontCache3.0.0.0 WinRM W32Time WinHttpAutoProxySvc dot3svc Wlansvc wmiApSrv WwanSvc) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess Mcx2Svc NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
	)
	IF "%winedition%" == "Windows 7 Ultimate" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc 
		MMCSS NlaSvc nsi CscService PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection 
		sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv AudioEndpointBuilder WinDefend EventLog MpsSvc 
		FontCache Winmgmt WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
		::Manual
		FOR %%I IN (AxInstSV SensrSvc AeLookupSvc AppIDSvc Appinfo ALG AppMgmt BITS BDESVC wbengine bthserv 
		PeerDistSvc CertPropSvc KeyIso COMSysApp Browser VaultSvc WdiServiceHost WdiSystemHost defragsvc MSDTC 
		EFS EapHost Fax fdPHost hkmsvc HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect PolicyAgent 
		KtmRm lltdsvc clr_optimization_v2.0.50727 MSiSCSI swprv Netlogon napagent Netman netprofm WPCSvc PNRPsvc 
		p2psvc p2pimsvc pla IPBusEnum PNRPAutoReg WPDBusEnum wercplsupport PcaSvc ProtectedStorage QWAVE RasAuto 
		RasMan SessionEnv TermService UmRdpService RpcLocator RemoteRegistry seclogon SstpSvc SCardSvr SCPolicySvc 
		SNMPTRAP sppuinotify SSDPSRV TabletInputService TapiSrv THREADORDER TBS upnphost vds VSS WebClient SDRSVC 
		WbioSrvc idsvc WcsPlugInService wcncsvc wudfsvc WerSvc Wecsvc StiSvc msiserver ehRecvr ehSched WMPNetworkSvc 
		TrustedInstaller FontCache3.0.0.0 WinRM W32Time WinHttpAutoProxySvc dot3svc Wlansvc wmiApSrv WwanSvc) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess Mcx2Svc NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
	)
	IF "%winedition%" == "Windows 7 Enterprise" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc 
		clr_optimization_v2.0.50727 MMCSS NlaSvc nsi CscService PlugPlay Power Spooler RpcSs RpcEptMapper SamSs 
		wscsvc LanmanServer ShellHWDetection sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv 
		AudioEndpointBuilder WinDefend EventLog MpsSvc FontCache Winmgmt WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
		::Manual
		FOR %%I IN (AxInstSV SensrSvc AeLookupSvc AppIDSvc Appinfo ALG AppMgmt BITS BDESVC wbengine bthserv 
		PeerDistSvc CertPropSvc KeyIso COMSysApp Browser VaultSvc WdiServiceHost WdiSystemHost defragsvc MSDTC 
		EFS EapHost Fax fdPHost hkmsvc HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect PolicyAgent 
		KtmRm lltdsvc MSiSCSI swprv Netlogon napagent Netman netprofm WPCSvc PNRPsvc p2psvc p2pimsvc pla IPBusEnum 
		PNRPAutoReg WPDBusEnum wercplsupport PcaSvc ProtectedStorage QWAVE RasAuto RasMan SessionEnv TermService 
		UmRdpService RpcLocator RemoteRegistry seclogon SstpSvc SCardSvr SCPolicySvc SNMPTRAP sppuinotify SSDPSRV 
		StorSvc TabletInputService TapiSrv THREADORDER TBS upnphost vds VSS WebClient SDRSVC WbioSrvc idsvc 
		WcsPlugInService wcncsvc wudfsvc WerSvc Wecsvc StiSvc msiserver ehRecvr ehSched WMPNetworkSvc 
		TrustedInstaller FontCache3.0.0.0 WinRM W32Time WinHttpAutoProxySvc dot3svc Wlansvc wmiApSrv WwanSvc) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess Mcx2Svc NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
	)
)
GOTO :HOME

:SVCSAFEDESK
::Automatic
FOR %%I IN (BITS BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_????? DiagTrack
CoreMessagingRegistrar CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache gpsvc 
iphlpsvc LSM NlaSvc nsi Power Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer 
ShellHWDetection sppsvc SysMain OneSyncSvc_????? SENS SystemEventsBroker Schedule Themes 
tiledatamodelsvc UserManager ProfSvc AudioSrv AudioEndpointBuilder Wcmsvc WinDefend 
SecurityHealthService EventLog MpsSvc FontCache Winmgmt WpnService WSearch LanmanWorkstation) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
::Manual
FOR %%I IN (AxInstSV AJRouter AppReadiness AppIDSvc Appinfo AppMgmt AppXSVC BDESVC wbengine 
BthHFSrv bthserv CertPropSvc ClipSVC KeyIso COMSysApp Browser PimIndexMaintenanceSvc_????? 
VaultSvc DsSvc DeviceAssociationService DeviceInstall DmEnrollmentSvc DsmSVC DevicesFlowUserSvc_????? 
DevQueryBroker WdiServiceHost WdiSystemHost MSDTC embeddedmode EFS EntAppSvc EapHost fhsvc fdPHost 
FDResPub HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect IpxlatCfgSvc PolicyAgent 
KtmRm lltdsvc wlpasvc MessagingService_????? diagnosticshub.standardcollector.service wlidsvc 
NgcSvc NgcCtnrSvc swprv smphost NaturalAuthentication Netlogon NcdAutoSetup NcbService Netman 
NcaSVC netprofm NetSetupSvc defragsvc PNRPsvc p2psvc p2pimsvc PerfHost pla PlugPlay PNRPAutoReg 
WPDBusEnum PrintNotify wercplsupport QWAVE RmSvc RasAuto RasMan SessionEnv TermService UmRdpService 
seclogon SstpSvc svsvc SSDPSRV StateRepository WiaRpc StorSvc TieringEngineService lmhosts TapiSrv 
TimeBroker TokenBroker UsoSvc upnphost UserDataSvc_????? UnistoreSvc_????? vds VSS WalletService 
WebClient SDRSVC WbioSrvc wcncsvc Sense WdNisSvc wudfsvc WEPHOSTSVC WerSvc Wecsvc StiSvc msiserver
LicenseManager TrustedInstaller WpnUserService_????? W32Time wuauserv WinHttpAutoProxySvc dot3svc 
WlanSvc wmiApSrv XboxGipSvc) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
::Disabled
FOR %%I IN (ALG tzautoupdate PeerDistSvc NfsClnt dmwappushsvc MapsBroker lfsvc HvHost 
vmickvpexchange vmicguestinterface vmicshutdown vmicheartbeat vmicvmsession vmicrdv 
vmictimesync vmicvss irmon SharedAccess AppVClient MSiSCSI SmsRouter CscService SEMgrSvc 
PhoneSvc RpcLocator RemoteRegistry RetailDemo RemoteAccess SensorDataService SensrSvc 
SensorService shpamsvc SCardSvr ScDeviceEnum SCPolicySvc SNMPTRAP TabletInputService 
UevAgentService WFDSConSvc FrameServer wisvc WMPNetworkSvc icssvc WinRM WwanSvc 
XblAuthManager XblGameSave XboxNetApiSvc) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
GOTO :HOME
:SVCSAFELAPTAB
::Automatic
FOR %%I IN (BITS BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_????? DiagTrack 
CoreMessagingRegistrar CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache gpsvc 
iphlpsvc LSM NlaSvc nsi Power Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer 
ShellHWDetection sppsvc SysMain OneSyncSvc_????? SENS SystemEventsBroker Schedule Themes 
tiledatamodelsvc UserManager ProfSvc AudioSrv AudioEndpointBuilder Wcmsvc WinDefend 
SecurityHealthService EventLog MpsSvc FontCache Winmgmt WpnService WSearch WlanSvc LanmanWorkstation) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
::Manual
FOR %%I IN (AxInstSV AJRouter AppReadiness AppIDSvc Appinfo AppMgmt AppXSVC BDESVC 
wbengine BthHFSrv bthserv CertPropSvc ClipSVC KeyIso COMSysApp Browser PimIndexMaintenanceSvc_????? 
VaultSvc DsSvc DeviceAssociationService DeviceInstall DmEnrollmentSvc DsmSVC DevicesFlowUserSvc_????? 
DevQueryBroker WdiServiceHost WdiSystemHost MSDTC embeddedmode EFS EntAppSvc EapHost fhsvc fdPHost 
FDResPub HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect IpxlatCfgSvc PolicyAgent 
KtmRm lltdsvc wlpasvc MessagingService_????? diagnosticshub.standardcollector.service wlidsvc NgcSvc 
NgcCtnrSvc swprv smphost NaturalAuthentication Netlogon NcdAutoSetup NcbService Netman NcaSVC netprofm 
NetSetupSvc defragsvc PNRPsvc p2psvc p2pimsvc PerfHost pla PlugPlay PNRPAutoReg WPDBusEnum PrintNotify 
wercplsupport QWAVE RmSvc RasAuto RasMan SessionEnv TermService UmRdpService seclogon SstpSvc 
SensorDataService SensrSvc SensorService svsvc SSDPSRV StateRepository WiaRpc StorSvc TieringEngineService 
lmhosts TapiSrv TimeBroker TokenBroker TabletInputService UsoSvc upnphost UserDataSvc_????? UnistoreSvc_????? 
vds VSS WalletService WebClient WFDSConSvc SDRSVC WbioSrvc wcncsvc Sense WdNisSvc wudfsvc WEPHOSTSVC WerSvc 
Wecsvc StiSvc msiserver LicenseManager TrustedInstaller WpnUserService_????? W32Time wuauserv WinHttpAutoProxySvc 
dot3svc wmiApSrv XboxGipSvc) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
::Disabled
FOR %%I IN (ALG tzautoupdate PeerDistSvc NfsClnt dmwappushsvc MapsBroker lfsvc HvHost vmickvpexchange 
vmicguestinterface vmicshutdown vmicheartbeat vmicvmsession vmicrdv vmictimesync vmicvss irmon SharedAccess 
AppVClient MSiSCSI SmsRouter CscService SEMgrSvc PhoneSvc RpcLocator RemoteRegistry RetailDemo RemoteAccess 
shpamsvc SCardSvr ScDeviceEnum SCPolicySvc SNMPTRAP UevAgentService FrameServer wisvc WMPNetworkSvc icssvc 
WinRM WwanSvc XblAuthManager XblGameSave XboxNetApiSvc) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
GOTO :HOME



::::::::::::::::::::::::::::::::::::::
:: BATCH SCRIPT INTERNAL FUNCTIONS  ::
::::::::::::::::::::::::::::::::::::::
:XWAIT
PING -n %1 127.0.0.1 >nul 2>&1
GOTO :eof
::END.XWAIT

:XDONE
ECHO/
ECHO/===========================================================
ECHO/DONE: %* 
ECHO/
IF DEFINED _TRACE ECHO Press any key to quit &PAUSE >nul &EXIT
CALL :XWAIT 20 &EXIT
GOTO :eof
::END.XDONE

:XERR
CLS
ECHO/
ECHO/ERROR: %* 
PAUSE
IF NOT DEFINED _TRACE EXIT
GOTO :eof
::END.XERR

:XECHO
ECHO/
IF NOT "%1_"=="_" ECHO/%_nline%:%*
IF DEFINED _TRACE ECHO/ &PAUSE
SET /A _nline+=1
CALL :XWAIT 2
GOTO :eof
::END.XECHO

:XECHOF
ECHO/
IF NOT "%1_"=="_" ECHO/%_nline%:%*
IF DEFINED _TRACE ECHO/ &PAUSE
SET /A _nline+=1
CALL :XWAIT 1
GOTO :eof
::END.XECHOF

:XMENU
ECHO/
IF NOT "%1_"=="_" ECHO/%_nline%. %*
IF DEFINED _TRACE ECHO/ &PAUSE
SET /A _nline+=1
GOTO :eof
::END.XMENU

:XTITLE
ECHO/
IF NOT "%1_"=="_" ECHO/===========================================================
IF NOT "%1_"=="_" ECHO/   %*
IF NOT "%1_"=="_" ECHO/===========================================================
SET /A _nline=1
GOTO :eof
::END.XTITLE