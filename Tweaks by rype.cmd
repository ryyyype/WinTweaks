@echo off &SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
echo Checking for Administrator elevation...
echo.
openfiles > NUL 2>&1
if %errorlevel%==0 (
        echo Elevation found! Proceeding...
) else (
        echo You are not running as Administrator...
        echo This batch cannot do it's job without elevation!
        echo.
        echo Right-click and select ^'Run as Administrator^' and try again...
        echo.
        echo Press any key to exit...
        pause > NUL
        exit
)

FOR /f "tokens=4-7 delims=[.] " %%i IN ('ver') DO (IF %%i==Version (SET winversion=%%j%%k) ELSE (SET winversion=%%i%%j))
FOR /F "TOKENS=1,* DELIMS==" %%u IN ('WMIC OS GET CAPTION /VALUE') DO IF /I "%%u"=="Caption" SET winedition=%%v
SET winedition=%winedition:~10%

title WINDOWS GAMING TWEAKS BY rype

:home
cls
call :xtitle WINDOWS GAMING TWEAKS BY rype
echo.
echo Select:
echo.
echo 1. Service Tweaks 
echo 2. System Tweaks
echo 3. Network Tweaks
IF %winversion% == 100 (echo 4. Remove Windows 10 Apps)
echo 5. PowerConfig Tweaks
echo 6. N/A
echo 7. N/A
echo 8. N/A
echo 9. N/A
echo.


set /p web=Type option:
if "%web%"=="1" goto :SVCMENU
if "%web%"=="2" goto :SYSTWEAK
if "%web%"=="3" goto :NETTWEAK
IF %winversion% == 100 (if "%web%"=="4" goto :RMWINAPPS)
if "%web%"=="5" goto :POWERTWEAK
if "%web%"=="6" goto :6
if "%web%"=="7" goto :7
if "%web%"=="8" goto :8
if "%web%"=="9" goto :9
goto home


:SVCMENU
CALL :XTITLE SERVICE TWEAKS BY Black Viper - www.blackviper.com
echo.
echo Select:
echo.
echo 1. Safe
echo 2. Tweaked
echo 3. Default
echo.


set /p web=Type option:
if "%web%"=="1" goto :SVCSAFE
if "%web%"=="2" goto :SVCTWEAKED
if "%web%"=="3" goto :SVCDEFAULT

pause
goto home

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
goto home


:NETTWEAK
@ECHO off
CALL :XTITLE GENERAL NETWORK TWEAKS
CALL :XECHO HW network driver tweaks - flow control, buffers, offload processing
FOR /F "tokens=3*" %%I IN ('REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /F "ServiceName" /S^|FINDSTR /I /L "ServiceName"') DO (
FOR /F %%A IN ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}" /F "%%I" /D /E /S ^|FINDSTR /I /L /V "Linkage"^|FINDSTR /I /L "\\Class\\"') DO SET "REGPATH=%%A" >nul 2>&1
	FOR %%n IN (#FlowControl #InterruptModeration #LsoV1IPv4 #LsoV2IPv4 #LsoV2IPv6 #PMARPOffload #PMNSOffload #PriorityVLANTag #WakeOnMagicPacket #WakeOnPattern AdaptiveIFS ITR MasterSlave WaitAutoNegComplete) DO (
		SET opt=%%n
		SET opt=!opt:#=*!
		REG QUERY "!REGPATH!" /V !opt! >nul 2>&1
		If NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V !opt! /T REG_SZ /D 0 >nul 2>&1 )
	FOR %%m IN () DO (
		SET opt=%%m
		SET opt=!opt:#=*!
		REG QUERY "!REGPATH!" /V !opt! >nul 2>&1
		If NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V !opt! /T REG_SZ /D 1 >nul 2>&1 )
	FOR %%o IN (#IPChecksumOffloadIPv4 #TCPChecksumOffloadIPv4 #TCPChecksumOffloadIPv6 #UDPChecksumOffloadIPv4 #UDPChecksumOffloadIPv6) DO (
		SET opt=%%o
		SET opt=!opt:#=*!
		REG QUERY "!REGPATH!" /V !opt! >nul 2>&1
		If NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V !opt! /T REG_SZ /D 3 >nul 2>&1 )
	REG QUERY "!REGPATH!" /V "*JumboPacket" >nul 2>&1
	If NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "*JumboPacket" /T REG_SZ /D 1514 >nul 2>&1
	REG QUERY "!REGPATH!" /V "WolShutdownLinkSpeed" >nul 2>&1
	If NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "WolShutdownLinkSpeed" /T REG_SZ /D 2 >nul 2>&1
	REG QUERY "!REGPATH!" /V "*SSIdleTimeout" >nul 2>&1
	If NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "*SSIdleTimeout" /T REG_SZ /D 60 >nul 2>&1
	REG QUERY "!REGPATH!" /V "LogLinkStateEvent" >nul 2>&1
	If NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "LogLinkStateEvent" /T REG_SZ /D 16 >nul 2>&1
)
::REM Speedguide.net tweaks
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
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /F /v NetworkThrottlingIndex /T REG_DWORD /D 0xffffffff >nul 2>&1
	CALL :XECHO System Responsiveness Gaming Tweak
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /F /v SystemResponsiveness /T REG_DWORD /D 0 >nul 2>&1
	CALL :XECHO Turn off LargeSystemCache
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /F /v LargeSystemCache /T REG_DWORD /D 0 >nul 2>&1
	CALL :XECHO Other Common Fixes
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /F /v autodisconnect /T REG_DWORD /D 0xffffffff >nul 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\lanmanworkstation\parameters" /F /v KeepConn /T REG_DWORD /D 0x7D00 >nul 2>&1
	CALL :XECHO Set QoS to 0%
	REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /F /v NonBestEffortLimit /T REG_DWORD /D 0 >nul 2>&1
)
IF %winversion% == 61 (
	NETSH int tcp set heuristics wsh=disabled &NETSH int ip set global taskoffload=enabled
	FOR %%I IN ("autotuninglevel=normal" "chimney=disabled" "congestionprovider=ctcp" "netdma=disabled" "rss=disable" "timestamps=disabled") DO NETSH int tcp set global %%~I >nul 2>&1
	FOR %%I IN (tcp udp) DO netsh int ipv4 set dynamicport %%I start=32767 num=32767 >nul 2>&1
	FOR %%I IN (MaxNegativeCacheTtl NegativeCacheTime NegativeSOACacheTime NetFailureCacheTime) DO REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /F /v %%I /T REG_DWORD /D 0 >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /F /v TCPNoDelay /T REG_DWORD /D 1 >nul 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /F /v NetworkThrottlingIndex /T REG_DWORD /D 0xffffffff >nul 2>&1
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
	CALL :XECHO Receive Window Auto-Tuning Level set to normal
	powershell "Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal" >nul 2>&1
	CALL :XECHO Disable Windows Scaling heuristics
	powershell "Set-NetTCPSetting -SettingName InternetCustom -ScalingHeuristics Disabled" >nul 2>&1
	CALL :XECHO Congestion Control Provider set to CTCP
	powershell "Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider CTCP" >nul 2>&1
	CALL :XECHO Disable TCP Chimney Offload
	powershell "Set-NetOffloadGlobalSetting -Chimney Disabled" >nul 2>&1
	CALL :XECHO Disable ECN Capability
	powershell "Set-NetTCPSetting -SettingName InternetCustom -EcnCapability Disabled" >nul 2>&1
	CALL :XECHO Disable TCP 1323 Timestamps
	powershell "Set-NetTCPSetting -SettingName InternetCustom -Timestamps Disabled" >nul 2>&1
	CALL :XECHO Enable Direct Cache Access (DCA)
	netsh int tcp set global dca=enabled >nul 2>&1
	CALL :XECHO Enable Checksum Offload
	powershell "Enable-NetAdapterChecksumOffload -Name *" >nul 2>&1
	CALL :XECHO Enable Receive-Side Scaling State (RSS)
	powershell "Enable-NetAdapterRss -Name *" >nul 2>&1
	CALL :XECHO Disable Receive Segment Coalescing State (RSC)
	powershell "Disable-NetAdapterRsc -Name *" >nul 2>&1
	CALL :XECHO Disable Large Send Offload (LSO)
	powershell "Disable-NetAdapterLso -Name *" >nul 2>&1
	CALL :XECHO Max SYN Retransmissions set to 2
	powershell "Set-NetTCPSetting -SettingName InternetCustom -MaxSynRetransmissions 2" >nul 2>&1
	CALL :XECHO Disable Non Sack Rtt Resiliency
	powershell "Set-NetTCPSetting -SettingName InternetCustom -NonSackRttResiliency disabled" >nul 2>&1
	CALL :XECHO Initial RTO and Min RTO
	powershell "Set-NetTCPSetting -SettingName InternetCustom -InitialRto 2000" >nul 2>&1
	powershell "set-NetTCPSetting -SettingName InternetCustom -MinRto 300" >nul 2>&1
	ECHO.
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Ndu" /F /v Start /T REG_DWORD /D 4 >nul 2>&1
)
pause
goto home


:RMWINAPPS
@echo off
echo. 
echo     Remove One Drive? (y/n)
echo.
set /p web=Type option:
if "%web%"=="y" goto :y_od
if "%web%"=="n" goto :n_od

:y_od
echo.
echo Uninstalling OneDrive
set x86="%SYSTEMROOT%\System32\OneDriveSetup.exe"
set x64="%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe"
taskkill /f /im OneDrive.exe > NUL 2>&1
ping 127.0.0.1 -n 5 > NUL 2>&1 
if exist %x64% (
%x64% /uninstall
) else (
%x86% /uninstall
)
ping 127.0.0.1 -n 8 > NUL 2>&1 
rd "%USERPROFILE%\OneDrive" /Q /S > NUL 2>&1
rd "C:\OneDriveTemp" /Q /S > NUL 2>&1
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S > NUL 2>&1
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S > NUL 2>&1 
echo.
echo Removeing OneDrive from the Explorer Side Panel.
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > NUL 2>&1
goto :2nd_part
:n_od
goto :2nd_part

:2nd_part
echo.
echo  	 Question:
echo.
echo 1. Permanently Remove Apps 
echo 2. Uninstall Apps 
echo.
set /p web=Type option:
if "%web%"=="1" goto :PRA
if "%web%"=="2" goto :UA
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
pause
goto dh
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
pause
:dh
echo.
echo  	 Disable Hibernation? (y/n)
echo.
set /p web=Type option:
if "%web%"=="y" goto :y_dh
if "%web%"=="n" goto :n_dh
:y_dh
@echo on
powercfg -h off
@echo off
goto 3rd_part
:n_dh
goto 3rd_part

:3rd_part
goto home


:POWERTWEAK
CALL :XTITLE POWERCONFIG TWEAKS
CALL :Xecho Backup Stock Settings 
powercfg /qh > powerconfig.txt

CALL :Xecho Activate High Performance Scheme
Powercfg -setactive scheme_min

CALL :Xecho Processor performance increase threshold / Schwellenwert zum Erhöhen der Prozessorleistung
echo Optimized Value: 0%
powercfg -attributes SUB_PROCESSOR 06cadf0e-64ed-448a-8927-ce7bf90eb35d -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 06cadf0e-64ed-448a-8927-ce7bf90eb35d 0


CALL :Xecho Processor performance decrease threshold / Schwellenwert zum Reduzieren der Prozessorleistung
echo Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR 12a0ab44-fe28-4fa9-b3bd-4b64f44960a6 -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 12a0ab44-fe28-4fa9-b3bd-4b64f44960a6 100


CALL :Xecho Processor performance decrease policy / Prozessorleistung - Reduzierungsrichtlinie
echo Optimized Value: Rocket
powercfg -attributes SUB_PROCESSOR 40fbefc7-2e9d-4d25-a185-0cfd8574bac6 -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 40fbefc7-2e9d-4d25-a185-0cfd8574bac6 2
Powercfg -setactive scheme_current

CALL :Xecho Processor performance increase policy / Prozessorleistung - Erhöhungsrichtlinie
echo Optimized Value: Ideal
powercfg -attributes SUB_PROCESSOR 465e1f50-b610-473a-ab58-00d1077dc418 -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 465e1f50-b610-473a-ab58-00d1077dc418 0

CALL :Xecho Processor idle demote threshold / Prozessorleerlauf - Schwellenwert für Herabstufung
echo Optimized Value: 0%
powercfg -attributes SUB_PROCESSOR 4b92d758-5a24-4851-a470-815d78aee119 -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 4b92d758-5a24-4851-a470-815d78aee119 0


CALL :Xecho Processor idle promote threshold / Prozessorleerlauf - Schwellenwert für Heraufstufung
echo Optimized Value: 0%
powercfg -attributes SUB_PROCESSOR 7b224883-b3cc-4d79-819f-8374152cbe7c -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 7b224883-b3cc-4d79-819f-8374152cbe7c 0


CALL :Xecho Processor performance core parking over utilization threshold / Prozessorleistung: Parken von Kernen - Schwellenwert für übermäßige Kernnutzung
echo Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR 943c8cb6-6f93-4227-ad87-e9a3feec08d1 -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 943c8cb6-6f93-4227-ad87-e9a3feec08d1 100

CALL :Xecho Processor performance boost mode / Leistungssteigerungsmodus für Prozessoren
echo Optimized Value: Enabled
powercfg -attributes SUB_PROCESSOR be337238-0d82-4146-a960-4f3749d470c7 -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor be337238-0d82-4146-a960-4f3749d470c7 1

CALL :Xecho Processor idle disable / Prozessorleerlauf deaktivieren
echo Optimized Value: idle disabled
powercfg -attributes SUB_PROCESSOR 5d76a2ca-e8c0-402f-a133-2158492d58ad -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad 1

CALL :Xecho Allow Throttle States / Drosselungszustände zulassen
echo Optimized Value: Disabled
powercfg -attributes SUB_PROCESSOR 3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb -ATTRIB_HIDE
powercfg -setacvalueindex scheme_current sub_processor 3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb 0

CALL :Xecho Upper bound for processor performance throttling / Maximum processor state / Drosselungszustände zulassen
echo Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR bc5038f7-23e0-4960-96da-33abaf5935ec -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor bc5038f7-23e0-4960-96da-33abaf5935ec 100

CALL :Xecho Lower bound for processor performance throttling / Minimum processor state / Drosselungszustände zulassen
echo Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR 893dee8e-2bef-41e0-89c6-b55d0929964c -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 893dee8e-2bef-41e0-89c6-b55d0929964c 100

CALL :Xecho Core-Parking
echo Processor performance core parking min cores
powercfg -attributes SUB_PROCESSOR 0cc5b647-c1df-4637-891a-dec35c318583 -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 0cc5b647-c1df-4637-891a-dec35c318583 100

echo Core-Parking for Skylake
echo Processor performance autonomous mode / Autonomer Modus für die Prozessorleistung
powercfg -attributes SUB_PROCESSOR 8baa4a8a-14c6-4451-8e8b-14bdbd197537 -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 8baa4a8a-14c6-4451-8e8b-14bdbd197537 1
echo Processor energy performance preference policy / Richtlinie für die bevorzugte Prozessorenergieeffizienz
powercfg -attributes SUB_PROCESSOR 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 0
echo Processor duty cycling / Prozessor-Aussetzbetrieb
powercfg -attributes SUB_PROCESSOR 4e4450b3-6179-4e91-b8f1-5bb9938f81a1 -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor 4e4450b3-6179-4e91-b8f1-5bb9938f81a1 0
echo Processor autonomous activity window / Fenster für die autonome Prozessoraktivität
powercfg -attributes SUB_PROCESSOR cfeda3d0-7697-4566-a922-a9086cd49dfa -ATTRIB_HIDE
Powercfg -setacvalueindex scheme_current sub_processor cfeda3d0-7697-4566-a922-a9086cd49dfa 30000

CALL :Xecho Save new settings
Powercfg -setactive scheme_current
goto home


:6 
goto home


:7 
goto home


:8 
goto home


:9 
goto home


:10
goto home

:::::::::::::::::::::::::::::::::
:: WINDOWS SVC BY Black Viper  ::
:::::::::::::::::::::::::::::::::
:SVCSAFE
IF %winversion% == 100 (
	echo.
	echo Select:
	echo.
	echo 1. DESKTOP
	echo 2. LAPTOP or TABLET
	echo.


	set /p web=Type option:
	if "%web%"=="1" goto :SVCSAFEDESK
	if "%web%"=="2" goto :SVCSAFELAPTAB
)
IF %winversion% == 61 (
	::Automatic
	FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS Dnscache FDResPub gpsvc 
	MMCSS NlaSvc nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer 
	ShellHWDetection sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv 
	AudioEndpointBuilder WinDefend EventLog MpsSvc FontCache Winmgmt wuauserv LanmanWorkstation) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
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
		If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
	::Disabled
	FOR %%I IN (AppMgmt bthserv PeerDistSvc CertPropSvc TrkWks SharedAccess iphlpsvc Mcx2Svc MSiSCSI 
	NetTcpPortSharing Netlogon napagent CscService WPCSvc RpcLocator RemoteRegistry RemoteAccess 
	SCardSvr SCPolicySvc SNMPTRAP StorSvc wcncsvc WMPNetworkSvc WSearch) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
)
goto home
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
		If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
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
		If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
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
		If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
)
IF %winversion% == 61 (
	::Automatic
	FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp Dnscache gpsvc MMCSS NlaSvc 
	nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection 
	sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv AudioEndpointBuilder WinDefend 
	EventLog MpsSvc FontCache Winmgmt wuauserv LanmanWorkstation) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
	::Manual
	FOR %%I IN (AeLookupSvc AppIDSvc Appinfo BITS wbengine KeyIso COMSysApp Browser defragsvc 
	MSDTC EapHost HomeGroupListener HomeGroupProvider IKEEXT PolicyAgent KtmRm clr_optimization_v2.0.50727 
	swprv Netman netprofm pla ProtectedStorage RasAuto RasMan seclogon SstpSvc sppuinotify SSDPSRV TapiSrv 
	THREADORDER upnphost vds VSS SDRSVC wudfsvc Wecsvc StiSvc msiserver TrustedInstaller FontCache3.0.0.0 
	W32Time dot3svc Wlansvc wmiApSrv) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
	::Disabled
	FOR %%I IN (AxInstSV SensrSvc ALG AppMgmt BDESVC bthserv PeerDistSvc CertPropSvc VaultSvc DPS WdiServiceHost 
	WdiSystemHost TrkWks EFS Fax fdPHost FDResPub hkmsvc hidserv UI0Detect SharedAccess iphlpsvc lltdsvc Mcx2Svc 
	MSiSCSI NetTcpPortSharing Netlogon napagent CscService WPCSvc PNRPsvc p2psvc p2pimsvc IPBusEnum PNRPAutoReg 
	WPDBusEnum wercplsupport PcaSvc QWAVE SessionEnv TermService UmRdpService RpcLocator RemoteRegistry RemoteAccess 
	SCardSvr SCPolicySvc SNMPTRAP StorSvc TabletInputService TBS WebClient WbioSrvc idsvc WcsPlugInService wcncsvc 
	WerSvc ehRecvr ehSched WMPNetworkSvc WinRM WSearch WinHttpAutoProxySvc WwanSvc) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
		If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
)
goto home
:SVCDEFAULT
IF %winversion% == 100 (
	ECHO.
	ECHO SET DEFAULT SERVICES FOR %winedition%
	PAUSE
	if %winedition% == "Windows 10 Home" (
		::Automatic
		FOR %%I IN (BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_????? DiagTrack CoreMessagingRegistrar 
		CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache MapsBroker gpsvc iphlpsvc LSM NlaSvc nsi 
		Power Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection sppsvc SysMain 
		OneSyncSvc_????? SENS SystemEventsBroker Schedule Themes tiledatamodelsvc UserManager ProfSvc 
		AudioSrv AudioEndpointBuilder Wcmsvc WinDefend SecurityHealthService EventLog MpsSvc FontCache 
		Winmgmt WpnService WSearch WlanSvc LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
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
			If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
		::Disabled
		FOR %%I IN (tzautoupdate NetTcpPortSharing RemoteRegistry RemoteAccess shpamsvc SCardSvr) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
	)
	if %winedition% == "Windows 10 Pro" (
		::Automatic
		FOR %%I IN (BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_????? DiagTrack CoreMessagingRegistrar 
		CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache MapsBroker gpsvc iphlpsvc LSM NlaSvc nsi Power
		Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection sppsvc SysMain OneSyncSvc_????? 
		SENS SystemEventsBroker Schedule Themes tiledatamodelsvc UserManager ProfSvc AudioSrv AudioEndpointBuilder 
		Wcmsvc WinDefend SecurityHealthService EventLog MpsSvc FontCache Winmgmt WpnService WSearch WlanSvc LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
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
			If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
		::Disabled
		FOR %%I IN (tzautoupdate AppVClient NetTcpPortSharing RemoteRegistry RemoteAccess shpamsvc SCardSvr UevAgentService) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
			If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
	)
)
IF %winversion% == 61 (
	
)
goto home

:SVCSAFEDESK
::Automatic
FOR %%I IN (BITS BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_????? DiagTrack
CoreMessagingRegistrar CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache gpsvc 
iphlpsvc LSM NlaSvc nsi Power Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer 
ShellHWDetection sppsvc SysMain OneSyncSvc_????? SENS SystemEventsBroker Schedule Themes 
tiledatamodelsvc UserManager ProfSvc AudioSrv AudioEndpointBuilder Wcmsvc WinDefend 
SecurityHealthService EventLog MpsSvc FontCache Winmgmt WpnService WSearch LanmanWorkstation) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
	If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
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
	If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
::Disabled
FOR %%I IN (ALG tzautoupdate PeerDistSvc NfsClnt dmwappushsvc MapsBroker lfsvc HvHost 
vmickvpexchange vmicguestinterface vmicshutdown vmicheartbeat vmicvmsession vmicrdv 
vmictimesync vmicvss irmon SharedAccess AppVClient MSiSCSI SmsRouter CscService SEMgrSvc 
PhoneSvc RpcLocator RemoteRegistry RetailDemo RemoteAccess SensorDataService SensrSvc 
SensorService shpamsvc SCardSvr ScDeviceEnum SCPolicySvc SNMPTRAP TabletInputService 
UevAgentService WFDSConSvc FrameServer wisvc WMPNetworkSvc icssvc WinRM WwanSvc 
XblAuthManager XblGameSave XboxNetApiSvc) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
	If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
goto home
:SVCSAFELAPTAB
::Automatic
FOR %%I IN (BITS BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_????? DiagTrack 
CoreMessagingRegistrar CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache gpsvc 
iphlpsvc LSM NlaSvc nsi Power Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer 
ShellHWDetection sppsvc SysMain OneSyncSvc_????? SENS SystemEventsBroker Schedule Themes 
tiledatamodelsvc UserManager ProfSvc AudioSrv AudioEndpointBuilder Wcmsvc WinDefend 
SecurityHealthService EventLog MpsSvc FontCache Winmgmt WpnService WSearch WlanSvc LanmanWorkstation) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
	If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >nul 2>&1)
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
	If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >nul 2>&1)
::Disabled
FOR %%I IN (ALG tzautoupdate PeerDistSvc NfsClnt dmwappushsvc MapsBroker lfsvc HvHost vmickvpexchange 
vmicguestinterface vmicshutdown vmicheartbeat vmicvmsession vmicrdv vmictimesync vmicvss irmon SharedAccess 
AppVClient MSiSCSI SmsRouter CscService SEMgrSvc PhoneSvc RpcLocator RemoteRegistry RetailDemo RemoteAccess 
shpamsvc SCardSvr ScDeviceEnum SCPolicySvc SNMPTRAP UevAgentService FrameServer wisvc WMPNetworkSvc icssvc 
WinRM WwanSvc XblAuthManager XblGameSave XboxNetApiSvc) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >nul 2>&1
	If NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >nul 2>&1)
goto home
::::::::::::::::::::::::::::::::::::::
:: BATCH SCRIPT INTERNAL FUNCTIONS  ::
::::::::::::::::::::::::::::::::::::::
:XWAIT
PING -n %1 127.0.0.1 >nul 2>&1
GOTO :eof
::END.XWAIT

:XDONE
echo/
echo/===========================================================
echo/DONE: %* 
echo/
IF DEFINED _TRACE echo Press any key to quit &PAUSE >nul &EXIT
CALL :XWAIT 20 &EXIT
GOTO :eof
::END.XDONE

:XERR
CLS
echo/
echo/ERROR: %* 
PAUSE
IF NOT DEFINED _TRACE EXIT
GOTO :eof
::END.XERR

:XECHO
echo/
IF NOT "%1_"=="_" echo/%_nline%:%*
IF DEFINED _TRACE echo/ &PAUSE
SET /A _nline+=1
CALL :XWAIT 2
GOTO :eof
::END.XECHO

:XTITLE
echo/
IF NOT "%1_"=="_" echo/===========================================================
IF NOT "%1_"=="_" echo/   %*
IF NOT "%1_"=="_" echo/===========================================================
SET /A _nline=1
GOTO :eof
::END.XTITLE