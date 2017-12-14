@ECHO off &SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
ECHO Checking for Administrator elevation...
ECHO.
openfiles >NUL 2>&1
IF NOT ERRORLEVEL 1 (
        ECHO Elevation found! Proceeding...
) ELSE (
        ECHO You are not running as Administrator...
        ECHO This batch cannot do it's job without elevation!
        ECHO.
        ECHO Right-click and select ^'Run as Administrator^' and try again...
        ECHO.
        ECHO Press any key to exit...
        PAUSE >NUL
        exit
)

COLOR 0A
MODE con lines=40 cols=59
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
CALL :XMENU PowerConfig Tweaks
CALL :XMENU Disable Graphiccard Sound
CALL :XMENU Disable Nvidia Telemetry
CALL :XMENU Uninstall razer Stats
IF %winversion% == 100 (CALL :XMENU Remove Windows 10 Apps) ELSE (CALL :XMENU N/A)
IF %winversion% == 100 (CALL :XMENU Remove OneDrive) ELSE (CALL :XMENU N/A)
IF %winversion% == 100 (CALL :XMENU Disable Telemetry) ELSE (CALL :XMENU N/A)
CALL :XMENU Windows Cleaner
CALL :XMENU Remove unused Drivers
CALL :XMENU Automatic Tweaks and Anti-Spy
ECHO.


SET /p web="Type option: "
IF "%web%"=="1" GOTO :SVCMENU
IF "%web%"=="2" GOTO :SYSTWEAK
IF "%web%"=="3" GOTO :NETTWEAK
IF "%web%"=="4" GOTO :POWERTWEAK
IF "%web%"=="5" GOTO :DISGRAPHIXSOUND
IF "%web%"=="6" GOTO :DISNVTELEMETRY
IF "%web%"=="7" GOTO :UNINSTALLRZSTATS
IF %winversion% == 100 (IF "%web%"=="8" GOTO :RMWINAPPS)
IF %winversion% == 100 (IF "%web%"=="9" GOTO :RMONEDRIVE)
IF %winversion% == 100 (IF "%web%"=="10" GOTO :RMTELEMETRY)
IF "%web%"=="11" GOTO :CLEANER
IF "%web%"=="12" GOTO :UNUSEDDRIVER
IF "%web%"=="13" GOTO :AUTOTWEAKS
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
IF %winversion% == 100 (
	CALL :XSVCTOKEN
)
SET /p web="Type option: "
IF "%web%"=="1" GOTO :SVCSAFE
IF "%web%"=="2" GOTO :SVCTWEAKED
IF "%web%"=="3" GOTO :SVCDEFAULT



::::::::::::::::::
:: Sytem tweaks ::
::::::::::::::::::
:SYSTWEAK
CALL :XTITLE GENERAL SYSTEM TWEAKS
::Windows 7
IF %winversion% == 61 (
	CALL :XECHO Disable Hibernate
	powercfg -h off >NUL 2>&1
	
	CALL :XECHO OS compatibility tweaks - crash, data collection, timeouts, game priority
	FOR %%I IN (AitAgent ProgramDataUpdater) DO SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\%%I" /DISABLE >NUL 2>&1
	FOR %%I IN (Autochk\Proxy Maintenance\WinSAT WindowsBackup\ConfigNotification DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector) DO SCHTASKS /Change /TN "\Microsoft\Windows\%%I" /DISABLE >NUL 2>&1
	FOR %%I IN (Consolidator KernelCeipTask UsbCeip) DO SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\%%I" /DISABLE >NUL 2>&1
	fsutil behavior set disable8dot3 1 >NUL 2>&1
	REG ADD "HKCU\Control Panel\Desktop" /F /v HungAppTimeout /T REG_SZ /D 4000 >NUL 2>&1
	REG ADD "HKCU\Control Panel\Desktop" /F /v LowLevelHooksTimeout /T REG_SZ /D 5000 >NUL 2>&1
	REG ADD "HKCU\Control Panel\Desktop" /F /v MenuShowDelay /T REG_SZ /D 0 >NUL 2>&1
	REG ADD "HKCU\Control Panel\Desktop" /F /v WaitToKillAppTimeout /T REG_SZ /D 5000 >NUL 2>&1
	REG ADD "HKCU\Software\Microsoft\InputPersonalization" /F /v RestrictImplicitInkCollection /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKCU\Software\Microsoft\InputPersonalization" /F /v RestrictImplicitTextCollection /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /F /v EnableWebContentEvaluation /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKCU\Software\Policies\Microsoft\Windows\AppCompat" /F /v DisablePCA /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /F /v DisableMFUTracking /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Affinity" /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Background Only" /T REG_SZ /D "False" >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "GPU Priority" /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Priority" /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Scheduling Category" /T REG_SZ /D "High" >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "SFIO Priority" /T REG_SZ /D "High" >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /F /v CrashDumpEnabled /T REG_DWORD /D 3 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /F /v CrashDumpEnabled /T REG_DWORD /D 3 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /F /v DontVerifyRandomDrivers /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /F /v CountOperations /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /F /v "DisablePagingExecutive" /T REG_DWORD /D 1 >NUL 2>&1
	SC config "AeLookupSvc" start= demand >NUL 2>&1
	SC start "AeLookupSvc" >NUL 2>&1 
	
	CALL :XECHO OS visual fx tweaks - less animations
	REG ADD "HKCU\Control Panel\Desktop\WindowMetrics" /F /v VisualFXSetting /T REG_DWORD /D 3 >NUL 2>&1
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /F /v VisualFXSetting /T REG_DWORD /D 3 >NUL 2>&1
	REG ADD "HKCU\Control Panel\Desktop" /F /v UserPreferencesMask /T REG_BINARY /D 9812038010000000 >NUL 2>&1
	FOR %%I IN (CompositionPolicy ListBoxSmoothScrolling TooltipAnimation TaskbarAnimations SelectionFade MenuAnimation ListviewWatermark ListviewShadow ListviewAlphaSelect DropShadow CursorShadow ControlAnimations ComboBoxAnimation AnimateMinMax) DO REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\%%I" /F /v DefaultApplied /T REG_DWORD /D 0 >NUL 2>&1
	FOR %%I IN (ThumbnailsOrIcon Themes FontSmoothing DragFullWindows) DO REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\%%I" /F /v DefaultApplied /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKCU\Control Panel\Desktop\WindowMetrics" /F /v MinAnimate /T REG_SZ /D 0 >NUL 2>&1
	REG ADD "HKCU\Software\Microsoft\Windows\DWM" /F /v Max3DWindows /T REG_DWORD /D 4 >NUL 2>&1
	
	CALL :XECHO Delete bad tweaks
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /V "IRQ8Priority" >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /F /V "IRQ8Priority" >NUL 2>&1
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V "DisablePagingExecutive" >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /F /V "DisablePagingExecutive" >NUL 2>&1
)
::Windows 10
IF %winversion% == 100 (
	CALL :XECHO Disable Hibernate
	powercfg -h off >NUL 2>&1
	
	CALL :XECHO File Explorer Opens At "This PC"
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /F /v LaunchTo /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Disable File Explorer Search Suggestions
	REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /F /v DisableSearchBoxSuggestions /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Remove Quick Access From File Explorer Navigation Pane
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /f /v HubMode /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Remove 3D-Objects, Music, Pictures and Video Folders
	::3D-Objects
	REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /F >NUL 2>&1
	::Music
	REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /F >NUL 2>&1
	REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /F >NUL 2>&1
	::Pictures
	REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /F >NUL 2>&1
	REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /F >NUL 2>&1
	::Video
	REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /F >NUL 2>&1
	REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /F >NUL 2>&1
	
	CALL :XECHO Remove Search Box From Taskbar
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /F /v SearchboxTaskbarMode /T REG_DWORD /D 0 >NUL 2>&1
	
	CALL :XECHO Remove Contacs From Taskbar
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /F /v PeopleBand /T REG_DWORD /D 0 >NUL 2>&1
	
	CALL :XECHO Disable 8.3 File Name Creation
	fsutil behavior set disable8dot3 1 >NUL 2>&1
	
	CALL :XECHO Speed Up Timeout Waiting Time For Applications
	REG ADD "HKCU\Control Panel\Desktop" /F /v HungAppTimeout /T REG_SZ /D 4000 >NUL 2>&1
	
	CALL :XECHO Speed Up Shut Down Time
	REG ADD "HKCU\Control Panel\Desktop" /F /v WaitToKillAppTimeout /T REG_SZ /D 5000 >NUL 2>&1
	
	CALL :XECHO Speed Up End Not Responding Services
	REG ADD "HKCU\Control Panel\Desktop" /F /v LowLevelHooksTimeout /T REG_SZ /D 5000 >NUL 2>&1
	
	CALL :XECHO Speed Up Menu Display Time
	REG ADD "HKCU\Control Panel\Desktop" /F /v MenuShowDelay /T REG_SZ /D 0 >NUL 2>&1
	
	CALL :XECHO Disable Restrict Implicit Ink Collection
	REG ADD "HKCU\Software\Microsoft\InputPersonalization" /F /v RestrictImplicitInkCollection /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Disable Restrict Implicit Text Collection
	REG ADD "HKCU\Software\Microsoft\InputPersonalization" /F /v RestrictImplicitTextCollection /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Disable Program Compatibility Assistant
	REG ADD "HKCU\Software\Policies\Microsoft\Windows\AppCompat" /F /v DisablePCA /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Disable Tracking App Usage
	REG ADD "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /F /v DisableMFUTracking /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Set Priority In Games
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Affinity" /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Background Only" /T REG_SZ /D "False" >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Clock Rate" /T REG_DWORD /D 10000 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "GPU Priority" /T REG_DWORD /D 8 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Priority" /T REG_DWORD /D 2 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "Scheduling Category" /T REG_SZ /D "High" >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /v "SFIO Priority" /T REG_SZ /D "High" >NUL 2>&1
	
	CALL :XECHO System Crash Dump Behavior (Small Dumps)
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /F /v CrashDumpEnabled /T REG_DWORD /D 3 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /F /v CrashDumpEnabled /T REG_DWORD /D 3 >NUL 2>&1
	
	CALL :XECHO Disable Random Driver Verification
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /F /v DontVerifyRandomDrivers /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Disable System And Process Level I/O Counters
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /F /v CountOperations /T REG_DWORD /D 0 >NUL 2>&1
	
	CALL :XECHO Disable Game Bar
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /F /v AppCaptureEnabled /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKCU\System\GameConfigStore" /F /v GameDVR_Enabled /T REG_DWORD /D 0 >NUL 2>&1
	
	CALL :XECHO Disable Windows Spotlight Features
	REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /F /v DisableWindowsSpotlightFeatures /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Disable User Tracking
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /v NoInstrumentation /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Disable Notification Center
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /v DisableNotificationCenter /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Disable Windows SmartScreen
	REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /F /v EnableSmartScreen /T REG_DWORD /D 0 >NUL 2>&1
	
	CALL :XECHO Disable "Turn on SmartScreen Filter"
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /F /v EnableWebContentEvaluation /T REG_DWORD /D 0 >NUL 2>&1
	
	CALL :XECHO Disable First Time Sign-in Animation	
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /F /v EnableFirstLogonAnimation /T REG_DWORD /D 0 >NUL 2>&1
	
	CALL :XECHO Disable Lock Screen
	REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /F /v NoLockScreen /T REG_DWORD /D 1 >NUL 2>&1
		
	CALL :XECHO Disable Biometrics
	REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /F /v Enabled /T REG_DWORD /D 0 >NUL 2>&1

	CALL :XECHO Disable Windows Update Feature
	REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /F /v NoAutoUpdate /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Disable Windows Update Delivery Optimization
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /F /v DODownloadMode /T REG_DWORD /D 0 >NUL 2>&1
	IF EXIST %ProgramFiles(x86)% (
		REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /F /v DODownloadMode /T REG_DWORD /D 0 >NUL 2>&1
	)
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /F /v SystemSettingsDownloadMode /T REG_DWORD /D 3 >NUL 2>&1
	
	CALL :XECHO Disable Automatic Driver Updates
	REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /F /v ExcludeWUDriversInQualityUpdate /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Disable Windows Startup Sound
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /F /v DisableStartupSound /T REG_DWORD /D 1 >NUL 2>&1
	
	CALL :XECHO Set Sound Scheme To No Sounds
	REG ADD "HKCU\AppEvents\Schemes" /F /v "" /T REG_SZ /D ".None" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	REG ADD "HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.Current" /F /v "" /T REG_SZ /D "" >NUL 2>&1
	
	CALL :XECHO Hide Mobile And Windows Insider In Options
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /v "SettingsPageVisibility" /T REG_SZ /D "hide:mobile-devices;windowsinsider" >NUL 2>&1
	
	CALL :XECHO Disable Scheduled Tasks 
	FOR %%I IN (ProgramDataUpdater Proxy Consolidator KernelCeipTask UsbCeip Microsoft-Windows-DiskDiagnosticDataCollector
				Microsoft-Windows-DiskDiagnosticResolver WinSAT "Microsoft Compatibility Appraiser") DO (
		powershell "Get-ScheduledTask -TaskName '%%I' | Disable-ScheduledTask" >NUL 2>&1 )
	
	CALL :XECHO Disable Windows Optional Features
	::BACKUP_WINDOWSOPTIONALFEATURES
	powershell "Get-WindowsOptionalFeature -Online | Where-Object {($_.State -eq 'Enabled') -and (($_.FeatureName -NotMatch 'NetFx*') -and ($_.FeatureName -NotMatch 'MicrosoftWindowsPowerShell*'))} | Format-Table" > %~dp0/BACKUP_WINDOWSOPTIONALFEATURES_"%DATE:~6,4%.%DATE:~3,2%.%DATE:~0,2%-%TIME:~0,2%.%TIME:~3,2%-%TIME:~6,2%".txt
	powershell "Get-WindowsOptionalFeature -Online | Where-Object {($_.State -eq 'Enabled') -and (($_.FeatureName -NotMatch 'NetFx*') -and ($_.FeatureName -NotMatch 'MicrosoftWindowsPowerShell*'))} | Disable-WindowsOptionalFeature -Online -NoRestart"
	
	CALL :XECHO Fixes For Some Shortcuts
	FTYPE InternetShortcut="C:\Windows\System32\rundll32.exe" "C:\Windows\System32\ieframe.dll",OpenURL %l >NUL 2>&1
	ASSOC .URL=InternetShortcut >NUL 2>&1
	::Export Default Associations
	dism /online /Export-DefaultAppAssociations:"%~dp0\assoc.xml" >NUL 2>&1
	::Edit assoc.xml
	SET assocURL="<Association Identifier=".url" ProgId="IE.AssocFile.URL" ApplicationName="Internet Browser" />"
	FIND /C /I %assocURL% %~dp0\assoc.xml >NUL 2>&1
	IF NOT ERRORLEVEL 1 (
		for /f "tokens=*" %%a in (%~dp0\assoc.xml) do (
			IF EXIST %~dp0\assoc2.xml (
				ECHO %%a >> %~dp0\assoc2.xml
			) ELSE (
				ECHO %%a > %~dp0\assoc2.xml
			)
			IF "%%a" == "<DefaultAssociations>" (
				ECHO ^%assocURL:~1,-3%^/^> >> "%~dp0\assoc2.xml"
			)
		)
	)
	::Import Default Associations
	dism /online /Import-DefaultAppAssociations:"%~dp0\assoc2.xml" >NUL 2>&1
	::Delete assoc.xml
	DEL /F /Q "%~dp0\assoc.xml" >NUL 2>&1
	DEL /F /Q "%~dp0\assoc2.xml" >NUL 2>&1
	
	CALL :XECHO OS Visual FX Tweaks - Less Animations
	REG ADD "HKCU\Control Panel\Desktop\WindowMetrics" /F /v VisualFXSetting /T REG_DWORD /D 3 >NUL 2>&1
	REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /F /v VisualFXSetting /T REG_DWORD /D 3 >NUL 2>&1
	REG ADD "HKCU\Control Panel\Desktop" /F /v UserPreferencesMask /T REG_BINARY /D 9012038010000000 >NUL 2>&1
	FOR %%I IN (ListviewAlphaSelect ListviewShadow TaskbarAnimations) DO REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /F /v %%I /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKCU\Control Panel\Desktop\WindowMetrics" /F /v MinAnimate /T REG_SZ /D 0 >NUL 2>&1
	REG ADD "HKCU\Software\Microsoft\Windows\DWM" /F /v EnableAeroPeek /T REG_DWORD /D 0 >NUL 2>&1
	
	CALL :XECHO Delete Bad Tweaks
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /V "IRQ8Priority" >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /F /V "IRQ8Priority" >NUL 2>&1
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V "DisablePagingExecutive" >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /F /V "DisablePagingExecutive" >NUL 2>&1
)
IF NOT DEFINED AUTOTWEAK GOTO :HOME
IF DEFINED AUTOTWEAK GOTO :POWERTWEAK



::::::::::::::::::::
:: Network tweaks ::
::::::::::::::::::::
:NETTWEAK
CALL :XTITLE GENERAL NETWORK TWEAKS
CALL :XECHO HW network driver tweaks - flow control, buffers, offload processing
FOR /F "tokens=3*" %%I IN ('REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /F "ServiceName" /S^|FINDSTR /I /L "ServiceName"') DO (
FOR /F %%A IN ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}" /F "%%I" /D /E /S ^|FINDSTR /I /L /V "Linkage"^|FINDSTR /I /L "\\Class\\"') DO SET "REGPATH=%%A" >NUL 2>&1
	FOR %%n IN (#FlowControl #InterruptModeration #LsoV1IPv4 #LsoV2IPv4 #LsoV2IPv6 #PMARPOffload #PMNSOffload 
				#WakeOnMagicPacket #WakeOnPattern AdaptiveIFS EEELinkAdvertisement EnablePME MasterSlave 
				WaitAutoNegComplete ULPMode ReduceSpeedOnPowerDown ITR EnableTss) DO (
		SET opt=%%n
		SET opt=!opt:#=*!
		REG QUERY "!REGPATH!" /V !opt! >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V !opt! /T REG_SZ /D 0 >NUL 2>&1 )
	FOR %%m IN (#PriorityVLANTag ) DO (
		SET opt=%%m
		SET opt=!opt:#=*!
		REG QUERY "!REGPATH!" /V !opt! >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V !opt! /T REG_SZ /D 1 >NUL 2>&1 )
	FOR %%o IN (#IPChecksumOffloadIPv4 #TCPChecksumOffloadIPv4 #TCPChecksumOffloadIPv6 #UDPChecksumOffloadIPv4 #UDPChecksumOffloadIPv6) DO (
		SET opt=%%o
		SET opt=!opt:#=*!
		REG QUERY "!REGPATH!" /V !opt! >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V !opt! /T REG_SZ /D 3 >NUL 2>&1 )
	REG QUERY "!REGPATH!" /V "*JumboPacket" >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "*JumboPacket" /T REG_SZ /D 1514 >NUL 2>&1
	REG QUERY "!REGPATH!" /V "WolShutdownLinkSpeed" >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "WolShutdownLinkSpeed" /T REG_SZ /D 2 >NUL 2>&1
	REG QUERY "!REGPATH!" /V "*SSIdleTimeout" >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "*SSIdleTimeout" /T REG_SZ /D 60 >NUL 2>&1
	REG QUERY "!REGPATH!" /V "LogLinkStateEvent" >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "LogLinkStateEvent" /T REG_SZ /D 16 >NUL 2>&1
	REG QUERY "!REGPATH!" /V "*TransmitBuffers" >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "*ReceiveBuffers" /T REG_SZ /D 96 >NUL 2>&1
	REG QUERY "!REGPATH!" /V "*TransmitBuffers" >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "!REGPATH!" /F /V "*TransmitBuffers" /T REG_SZ /D 96 >NUL 2>&1
)
:: Speedguide.net tweaks
IF %winversion% GEQ 61 (
	CALL :XECHO Disable Nagle's Algorithm
	FOR /F "tokens=3*" %%I IN ('REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /F "ServiceName" /S^|FINDSTR /I /L "ServiceName"') DO (
		REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%I" /F /v TcpAckFrequency /T REG_DWORD /D 1 >NUL 2>&1
		REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%I" /F /v TCPNoDelay /T REG_DWORD /D 1 >NUL 2>&1
		REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%I" /F /v TcpDelAckTicks /T REG_DWORD /D 0 >NUL 2>&1
	)
	CALL :XECHO Host Resolution Priority Tweak
	SET /A _tcpservpri_=3 &FOR %%I IN (LocalPriority HostsPriority DnsPriority NetbtPriority Class) DO (
	SET /A _tcpservpri_+=1 &REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /F /v %%I /T REG_DWORD /D !_tcpservpri_! >NUL 2>&1
	)
	CALL :XECHO Network Throttling Index Gaming Tweak
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /F /v NetworkThrottlingIndex /T REG_DWORD /D 0xFFFFFFFF >NUL 2>&1
	CALL :XECHO System Responsiveness Gaming Tweak
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /F /v SystemResponsiveness /T REG_DWORD /D 0 >NUL 2>&1
	CALL :XECHO Turn off LargeSystemCache
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /F /v LargeSystemCache /T REG_DWORD /D 0 >NUL 2>&1
	CALL :XECHO Other Common Fixes
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /F /v autodisconnect /T REG_DWORD /D 0xFFFFFFFF >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\lanmanworkstation\parameters" /F /v KeepConn /T REG_DWORD /D 0x7D00 >NUL 2>&1
	CALL :XECHO Set QoS to 0%
	REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /F /v NonBestEffortLimit /T REG_DWORD /D 0 >NUL 2>&1
)
IF %winversion% == 61 (
	NETSH int tcp SET heuristics wsh=disabled 
	NETSH int ip SET global taskoffload=enabled
	FOR %%I IN ("autotuninglevel=normal" "chimney=disabled" "congestionprovider=ctcp" "netdma=disabled" "rss=disable" "timestamps=disabled") DO NETSH int tcp SET global %%~I >NUL 2>&1
	FOR %%I IN (tcp udp) DO netsh int ipv4 SET dynamicport %%I start=32767 num=32767 >NUL 2>&1
	FOR %%I IN (MaxNegativeCacheTtl NegativeCacheTime NegativeSOACacheTime NetFailureCacheTime) DO REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /F /v %%I /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /F /v TCPNoDelay /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /F /v DisableBandwidthThrottling /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" /F /v DisableLargeMtu /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v DefaultTTL /T REG_DWORD /D 0x40 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v DisableLargeMtu /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v DisableTaskOffload /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v EnableConnectionRateLimiting /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v EnableTCPA /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v EnableWsd /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /F /v Tcp1323Opts /T REG_DWORD /D 3 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /F /v TcpCreateAndConnectTcbRateLimitDepth /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v TCPMaxDataRetransmissions /T REG_DWORD /D 5 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /F /v TcpTimedWaitDelay /T REG_DWORD /D 0x3c >NUL 2>&1
)
IF %winversion% == 100 (
	CALL :XECHO Receive Window Auto-Tuning Level set to normal
	powershell "Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal" >NUL 2>&1	
	CALL :XECHO Disable Windows Scaling heuristics
	powershell "Set-NetTCPSetting -SettingName InternetCustom -ScalingHeuristics Disabled" >NUL 2>&1
	CALL :XECHO Congestion Control Provider set to CTCP
	powershell "Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider CTCP" >NUL 2>&1
	CALL :XECHO Disable TCP Chimney Offload
	powershell "Set-NetOffloadGlobalSetting -Chimney Disabled" >NUL 2>&1
	CALL :XECHO Disable ECN Capability
	powershell "Set-NetTCPSetting -SettingName InternetCustom -EcnCapability Disabled" >NUL 2>&1
	CALL :XECHO Disable TCP 1323 Timestamps
	powershell "Set-NetTCPSetting -SettingName InternetCustom -Timestamps Disabled" >NUL 2>&1
	CALL :XECHO Enable Direct Cache Access
	netsh int tcp set global dca=enabled >NUL 2>&1
	CALL :XECHO Enable Checksum Offload
	powershell "Enable-NetAdapterChecksumOffload -Name *" >NUL 2>&1
	CALL :XECHO Enable Receive-Side Scaling State
	powershell "Enable-NetAdapterRss -Name *" >NUL 2>&1
	CALL :XECHO Disable Receive Segment Coalescing State
	powershell "Disable-NetAdapterRsc -Name *" >NUL 2>&1
	CALL :XECHO Disable Large Send Offload
	powershell "Disable-NetAdapterLso -Name *" >NUL 2>&1
	CALL :XECHO Max SYN Retransmissions set to 2
	powershell "Set-NetTCPSetting -SettingName InternetCustom -MaxSynRetransmissions 2" >NUL 2>&1
	CALL :XECHO Disable Non Sack Rtt Resiliency
	powershell "Set-NetTCPSetting -SettingName InternetCustom -NonSackRttResiliency disabled" >NUL 2>&1
	CALL :XECHO Initial RTO and Min RTO
	powershell "Set-NetTCPSetting -SettingName InternetCustom -InitialRto 2000" >NUL 2>&1
	powershell "SET-NetTCPSetting -SettingName InternetCustom -MinRto 300" >NUL 2>&1
	CALL :XECHO Internet Explorer Optimization	
	REG ADD "HKLM\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /F /v explorer.exe /T REG_DWORD /D 10 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /F /v explorer.exe /T REG_DWORD /D 10 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /F /v iexplorer.exe /T REG_DWORD /D 10 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /F /v iexplorer.exe /T REG_DWORD /D 10 >NUL 2>&1
	CALL :XECHO DNS Leak fix
	REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /F /v DisableSmartNameResolution /T REG_DWORD /D 1 >NUL 2>&1
	CALL :XECHO Disable Negative DNS Caching
	FOR %%I IN (MaxNegativeCacheTtl NegativeCacheTime NegativeSOACacheTime NetFailureCacheTime) DO REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /F /v %%I /T REG_DWORD /D 0 >NUL 2>&1
	CALL :XECHO Disable Connection Limits
	REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /F /v EnableConnectionRateLimiting /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /F /v TcpCreateAndConnectTcbRateLimitDepth /T REG_DWORD /D 0 >NUL 2>&1
	
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" /F /v "Do not use NLA" /T REG_SZ /D 1 >NUL 2>&1
	CALL :XECHO Disable Network Data Usage Monitoring
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Ndu" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1
	CALL :XECHO Disable Teredo Tunneling Adapter and other Adapter
	FOR %%I IN ("Microsoft Kernel Debug Network Adapter" "WAN Miniport" "WAN-Miniport" "Teredo Tunneling") DO powershell "Get-PnpDevice | Where-Object {$_.FriendlyName -match '%%I'} | Disable-PnpDevice -Confirm:$false"  >NUL 2>&1
	CALL :XECHO Disable some network adapter bindings
	FOR %%I IN (ms_msclient ms_lldp ms_lltdio ms_rspndr ms_server ms_pacer) DO powershell "Get-NetAdapter -physical | Where-Object {$_.Status -eq 'Up'} | Disable-NetAdapterBinding -ComponentID '%%I'"  >NUL 2>&1
)
IF NOT DEFINED AUTOTWEAK GOTO :HOME
IF DEFINED AUTOTWEAK GOTO :RMONEDRIVE


::::::::::::::::::::::::::
:: POWERSETTINGS TWEAKS ::
::::::::::::::::::::::::::
:POWERTWEAK
chcp 1252 >NUL 2>&1
CALL :XTITLE POWERCONFIG TWEAKS
CALL :XECHO Backup Stock Settings 
powercfg /qh > %~dp0/BACKUP_POWERCFG_"%DATE:~6,4%.%DATE:~3,2%.%DATE:~0,2%-%TIME:~0,2%.%TIME:~3,2%-%TIME:~6,2%".txt

CALL :XECHO Activate High Performance Scheme
powercfg -setactive scheme_min >NUL 2>&1

CALL :XECHO Processor performance increase threshold / Schwellenwert zum Erh"hen der Prozessorleistung
ECHO Optimized Value: 0%
powercfg -attributes SUB_PROCESSOR 06cadf0e-64ed-448a-8927-ce7bf90eb35d -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 06cadf0e-64ed-448a-8927-ce7bf90eb35d 0 >NUL 2>&1


CALL :XECHO Processor performance decrease threshold / Schwellenwert zum Reduzieren der Prozessorleistung
ECHO Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR 12a0ab44-fe28-4fa9-b3bd-4b64f44960a6 -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 12a0ab44-fe28-4fa9-b3bd-4b64f44960a6 100 >NUL 2>&1


CALL :XECHO Processor performance decrease policy / Prozessorleistung - Reduzierungsrichtlinie
ECHO Optimized Value: Rocket
powercfg -attributes SUB_PROCESSOR 40fbefc7-2e9d-4d25-a185-0cfd8574bac6 -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 40fbefc7-2e9d-4d25-a185-0cfd8574bac6 2 >NUL 2>&1

CALL :XECHO Processor performance increase policy / Prozessorleistung - Erh"hungsrichtlinie
ECHO Optimized Value: Ideal
powercfg -attributes SUB_PROCESSOR 465e1f50-b610-473a-ab58-00d1077dc418 -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 465e1f50-b610-473a-ab58-00d1077dc418 0 >NUL 2>&1

CALL :XECHO Processor idle demote threshold / Prozessorleerlauf - Schwellenwert f?r Herabstufung
ECHO Optimized Value: 0%
powercfg -attributes SUB_PROCESSOR 4b92d758-5a24-4851-a470-815d78aee119 -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 4b92d758-5a24-4851-a470-815d78aee119 0 >NUL 2>&1


CALL :XECHO Processor idle promote threshold / Prozessorleerlauf - Schwellenwert f?r Heraufstufung
ECHO Optimized Value: 0%
powercfg -attributes SUB_PROCESSOR 7b224883-b3cc-4d79-819f-8374152cbe7c -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 7b224883-b3cc-4d79-819f-8374152cbe7c 0 >NUL 2>&1


CALL :XECHO Processor performance core parking over utilization threshold / Prozessorleistung: Parken von Kernen - Schwellenwert f?r ?bem,áige Kernnutzung
ECHO Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR 943c8cb6-6f93-4227-ad87-e9a3feec08d1 -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 943c8cb6-6f93-4227-ad87-e9a3feec08d1 100 >NUL 2>&1

CALL :XECHO Processor performance boost mode / Leistungssteigerungsmodus f?r Prozessoren
ECHO Optimized Value: Enabled
powercfg -attributes SUB_PROCESSOR be337238-0d82-4146-a960-4f3749d470c7 -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor be337238-0d82-4146-a960-4f3749d470c7 1 >NUL 2>&1

CALL :XECHO Processor idle disable / Prozessorleerlauf deaktivieren
ECHO Optimized Value: idle disabled
powercfg -attributes SUB_PROCESSOR 5d76a2ca-e8c0-402f-a133-2158492d58ad -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad 1 >NUL 2>&1

CALL :XECHO Allow Throttle States / Drosselungszust,nde zulassen
ECHO Optimized Value: Disabled
powercfg -attributes SUB_PROCESSOR 3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb 0 >NUL 2>&1

CALL :XECHO Upper bound for processor performance throttling / Maximum processor state / Drosselungszust,nde zulassen
ECHO Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR bc5038f7-23e0-4960-96da-33abaf5935ec -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor bc5038f7-23e0-4960-96da-33abaf5935ec 100 >NUL 2>&1

CALL :XECHO Lower bound for processor performance throttling / Minimum processor state / Drosselungszust,nde zulassen
ECHO Optimized Value: 100%
powercfg -attributes SUB_PROCESSOR 893dee8e-2bef-41e0-89c6-b55d0929964c -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 893dee8e-2bef-41e0-89c6-b55d0929964c 100 >NUL 2>&1

CALL :XECHO Core-Parking
ECHO Processor performance core parking min cores
powercfg -attributes SUB_PROCESSOR 0cc5b647-c1df-4637-891a-dec35c318583 -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 0cc5b647-c1df-4637-891a-dec35c318583 100 >NUL 2>&1

ECHO Core-Parking for Skylake
ECHO Processor performance autonomous mode / Autonomer Modus f?r die Prozessorleistung
powercfg -attributes SUB_PROCESSOR 8baa4a8a-14c6-4451-8e8b-14bdbd197537 -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 8baa4a8a-14c6-4451-8e8b-14bdbd197537 1 >NUL 2>&1
ECHO Processor energy performance preference policy / Richtlinie f?r die bevorzugte Prozessorenergieeffizienz
powercfg -attributes SUB_PROCESSOR 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 0 >NUL 2>&1
ECHO Processor duty cycling / Prozessor-Aussetzbetrieb
powercfg -attributes SUB_PROCESSOR 4e4450b3-6179-4e91-b8f1-5bb9938f81a1 -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 4e4450b3-6179-4e91-b8f1-5bb9938f81a1 0 >NUL 2>&1
ECHO Processor autonomous activity window / Fenster fü?r die autonome Prozessoraktivit,t
powercfg -attributes SUB_PROCESSOR cfeda3d0-7697-4566-a922-a9086cd49dfa -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor cfeda3d0-7697-4566-a922-a9086cd49dfa 30000 >NUL 2>&1

CALL :XECHO Save new settings
powercfg -setactive scheme_current >NUL 2>&1
chcp 850 >NUL 2>&1
IF NOT DEFINED AUTOTWEAK GOTO :HOME
IF DEFINED AUTOTWEAK GOTO :NETTWEAK


:DISGRAPHIXSOUND 
FOR %%I IN ("NVIDIA High Definition Audio") DO powershell "Get-PnpDevice | Where-Object {$_.FriendlyName -match '%%I'} | Disable-PnpDevice -Confirm:$false"  >NUL 2>&1
GOTO :HOME


:DISNVTELEMETRY
CALL :XTITLE DISABLE NVIDIA TELEMETRY
CALL :XECHO Disable Nvidia telemetry schedule tasks
schtasks /change /TN NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable >NUL 2>&1
schtasks /change /TN NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable >NUL 2>&1
schtasks /change /TN NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /disable >NUL 2>&1
CALL :XECHO Uninstall Nvidia telemetry package
rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer -silent
CALL :XECHO Block Nvidia telemetry in hosts file
ECHO.
CHOICE /C:YN /M "Do you use GeForce Experience"
IF ERRORLEVEL 2 (
	FOR %%I IN (gfwsl.geforce.com gfe.geforce.com telemetry.nvidia.com
	gfe.nvidia.com telemetry.gfe.nvidia.com events.gfe.nvidia.com) DO ( 
		FINDSTR /X /C:"0.0.0.0 %%I" %WINDIR%\system32\drivers\etc\hosts >NUL 2>&1
		IF !ERRORLEVEL! NEQ 0 (
			CALL :XECHOF Add %%I to hosts
			ECHO ^0.0.0.0 %%I>>%WINDIR%\system32\drivers\etc\hosts
		)
	)
)
IF ERRORLEVEL 1 (
	FOR %%I IN (gfe.geforce.com telemetry.nvidia.com telemetry.gfe.nvidia.com events.gfe.nvidia.com) DO ( 
		FINDSTR /X /C:"0.0.0.0 %%I" %WINDIR%\system32\drivers\etc\hosts >NUL 2>&1
		IF !ERRORLEVEL! NEQ 0 (
			CALL :XECHOF Add %%I to hosts
			ECHO ^0.0.0.0 %%I>>%WINDIR%\system32\drivers\etc\hosts
		)
	)
)
GOTO :HOME

:UNINSTALLRZSTATS
CALL :XTITLE REMOVE RAZER STATS AND CHROMA SDK
IF EXIST %PROGRAMDATA%\Razer\Synapse\ProductUpdates\Uninstallers\RzStats (
	START /WAIT %PROGRAMDATA%\Razer\Synapse\ProductUpdates\Uninstallers\RzStats\Razer_RzStats_Uninstall.exe /S >NUL 2>&1
)
IF EXIST "%ProgramFiles(x86)%\Razer Chroma SDK" (
	START /WAIT "%ProgramFiles(x86)%\Razer Chroma SDK\Razer_Chroma_SDK_Uninstaller.exe" /S >NUL 2>&1
)

GOTO :HOME

:RMWINAPPS
CALL :XTITLE REMOVE WINDOWS BLOATWARE APPS
CALL :XECHO Uninstall and remove Windows Bloatware
FOR %%I IN (3DBuilder Appconnector BingFinance BingNews BingSports BingWeather Getstarted MicrosoftOfficeHub 
			MicrosoftSolitaireCollection MicrosoftStickyNotes Office.OneNote OneConnect People SkypeApp
			WindowsAlarms WindowsCamera WindowsMaps WindowsPhone WindowsSoundRecorder XboxApp ZuneMusic
			ZuneVideo windowscommunicationsapps MinecraftUWP MicrosoftPowerBIForWindows NetworkSpeedTest
			CommsPhone ConnectivityStore Messaging Office.Sway OneConnect WindowsFeedbackHub 
			BingFoodAndDrink BingTravel BingHealthAndFitness WindowsReadingList Microsoft3DViewer
			Twitter PandoraMediaInc.29680B314EFC2 Flipboard Shazam CandyCrushSaga CandyCrushSodaSaga
			iHeartRadio Netflix Wunderlist DrawboardPDF PicsArt-PhotoStudio	FarmVille2CountryEscape
			TuneInRadio Asphalt8Airborne Xbox.TCUI CyberLinkMediaSuiteEssentials Facebook RoyalRevolt2
			CaesarsSlotsFreeCasino MarchofEmpires Keeper Print3D PhototasticCollage XING AutodeskSketchBook
			HEVCVideoExtension Duolingo-LearnLanguagesforFree EclipseManager ActiproSoftwareLLC.562882FEEB491
			BioEnrollment WindowsFeedback XboxGameOverlay XboxGameCallableUI XboxIdentityProvider 
			ContactSupport XboxSpeechToTextOverlay MiracastView Print3D GetHelp HolographicFirstRun) DO (
	powershell "Get-AppxPackage '*%%I*' -AllUsers | Remove-AppxPackage -AllUsers" >NUL 2>&1
	powershell "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like '*%%I*'} | Remove-AppxProvisionedPackage -Online" >NUL 2>&1
)
CALL :XECHO Disable Consumer Features
REG ADD "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /F /v DisableWindowsConsumerFeatures /T REG_DWORD /D 1 >NUL 2>&1
GOTO :HOME


:::::::::::::::::::::::::::::::
:: REMOVE MICROSOFT ONEDRIVE ::
:::::::::::::::::::::::::::::::
:RMONEDRIVE
CALL :XTITLE Uninstalling OneDrive
SET x86="%SYSTEMROOT%\System32\OneDriveSetup.exe"
SET x64="%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe"
taskkill /f /im OneDrive.exe >NUL 2>&1
ping 127.0.0.1 -n 5 >NUL 2>&1 
IF EXIST %x64% (
	START /WAIT %x64% /uninstall
) ELSE (
	START /WAIT %x86% /uninstall
)
rd "%USERPROFILE%\OneDrive" /Q /S >NUL 2>&1
rd "C:\OneDriveTemp" /Q /S >NUL 2>&1
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S >NUL 2>&1
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S >NUL 2>&1 
ECHO.
ECHO Removeing OneDrive from the Explorer Side Panel.
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >NUL 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >NUL 2>&1
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /f /v OneDriveSetup >NUL 2>&1
IF NOT DEFINED AUTOTWEAK GOTO :HOME
IF DEFINED AUTOTWEAK GOTO :RMTELEMETRY
GOTO :HOME


:::::::::::::::::::::::::::::::::
:: DISABLE MICROSOFT TELEMETRY ::
:::::::::::::::::::::::::::::::::
:RMTELEMETRY
CALL :XTITLE DISABLE MICROSOFT TELEMETRY
CALL :XECHO Editing Hosts File
FOR %%I IN (choice.microsoft.com choice.microsoft.com.nstac.net df.telemetry.microsoft.com
			oca.telemetry.microsoft.com oca.telemetry.microsoft.com.nsatc.net
			redir.metaservices.microsoft.com reports.wes.df.telemetry.microsoft.com
			services.wes.df.telemetry.microsoft.com settings-sandbox.data.microsoft.com
			settings-win.data.microsoft.com sqm.df.telemetry.microsoft.com 
			sqm.telemetry.microsoft.com sqm.telemetry.microsoft.com.nsatc.net
			telecommand.telemetry.microsoft.com telecommand.telemetry.microsoft.com.nsatc.net
			telemetry.appex.bing.net telemetry.microsoft.com telemetry.urs.microsoft.com
			vortex-sandbox.data.microsoft.com vortex-win.data.microsoft.com vortex.data.microsoft.com
			watson.telemetry.microsoft.com watson.telemetry.microsoft.com.nsatc.net
			watson.ppe.telemetry.microsoft.com wes.df.telemetry.microsoft.com 
			vortex-bn2.metron.live.com.nsatc.net vortex-cy2.metron.live.com.nsatc.net
			watson.live.com watson.microsoft.com feedback.search.microsoft.com feedback.windows.com
			corp.sts.microsoft.com diagnostics.support.microsoft.com i1.services.social.microsoft.com
			i1.services.social.microsoft.com.nsatc.net ca.telemetry.microsoft.com
			cache.datamart.windows.com spynet2.microsoft.com spynetalt.microsoft.com
			a.ads1.msn.com a.ads2.msads.net a.ads2.msn.com a.rad.msn.com a-0001.a-msedge.net
			a-0002.a-msedge.net a-0003.a-msedge.net a-0004.a-msedge.net a-0005.a-msedge.net
			a-0006.a-msedge.net a-0007.a-msedge.net a-0008.a-msedge.net a-0009.a-msedge.net ac3.msn.com
			ad.doubleclick.net adnexus.net adnxs.com ads.msn.com ads1.msads.net ads1.msn.com aidps.atdmt.com
			aka-cdn-ns.adtech.de a-msedge.net apps.skype.com az361816.vo.msecnd.net az512334.vo.msecnd.net
			b.ads1.msn.com b.ads2.msads.net b.rad.msn.com bs.serving-sys.com c.atdmt.com c.msn.com
			cdn.atdmt.com cds26.ams9.msecn.net compatexchange.cloudapp.net 
			corpext.msitadfs.glbdns2.microsoft.com cs1.wpc.v0cdn.net db3aqu.atdmt.com ec.atdmt.com
			fe2.update.microsoft.com.akadns.net feedback.microsoft-hohm.com flex.msn.com g.msn.com
			h1.msn.com lb1.www.ms.akadns.net live.rads.msn.com m.adnxs.com m.hotmail.com msedge.net
			msftncsi.com msnbot-65-55-108-23.search.msn.com msntest.serving-sys.com pre.footprintpredict.com
			preview.msn.com pricelist.skype.com rad.live.com rad.msn.com s.gateway.messenger.live.com
			s0.2mdn.net schemas.microsoft.akadns.net secure.adnxs.com secure.flashtalking.com
			sls.update.microsoft.com.akadns.net static.2mdn.net statsfe1.ws.microsoft.com 
			statsfe2.update.microsoft.com.akadns.net statsfe2.ws.microsoft.com survey.watson.microsoft.com
			view.atdmt.com www.msftncsi.com) DO ( 
	FINDSTR /X /C:"0.0.0.0 %%I" %WINDIR%\system32\drivers\etc\hosts >NUL 2>&1
	IF !ERRORLEVEL! NEQ 0 (
		CALL :XECHOF Add %%I to hosts
		ECHO ^0.0.0.0 %%I>>%WINDIR%\system32\drivers\etc\hosts
	)
)
CALL :XECHO Stop Telemetry Services
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1

wmic useraccount where name='%username%' get sid /format:list|findstr /C:"SID=">%~dp0\tmp.tmp
FOR /f "usebackq" %%v in (%~dp0\tmp.tmp) DO SET uSID=%%v
DEL "%~dp0\tmp.tmp" /f /s /q >NUL 2>&1
SET uSID=!uSID:~4!
REG ADD "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\!uSID!" /F /v FeatureStates /T REG_DWORD /D 0x33C >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" /F /v WiFiSenseCredShared /T REG_DWORD /D 0 >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" /F /v WiFiSenseOpen /T REG_DWORD /D 0 >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /F /v CEIPEnable /T REG_DWORD /D 0 >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /v AllowTelemetry /T REG_DWORD /D 0 >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /F /v NoLockScreenCamera /T REG_DWORD /D 1 >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /F /v DisableUAR /T REG_DWORD /D 1 >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /F /v AITEnable /T REG_DWORD /D 0 >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /v DisableSensors /T REG_DWORD /D 1 >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /F /v PreventHandwritingDataSharing /T REG_DWORD /D 1 >NUL 2>&1
IF EXIST %ProgramFiles(x86)% (
	REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\WcmSvc\wifinetworkmanager\features\!uSID!" /F /v FeatureStates /T REG_DWORD /D 0x33C >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\WcmSvc\wifinetworkmanager\features" /F /v WiFiSenseCredShared /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\WcmSvc\wifinetworkmanager\features" /F /v WiFiSenseOpen /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\SQMClient\Windows" /F /v CEIPEnable /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection" /F /v AllowTelemetry /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Personalization" /F /v NoLockScreenCamera /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat" /F /v DisableUAR /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\AppCompat" /F /v AITEnable /T REG_DWORD /D 0 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\LocationAndSensors" /F /v DisableSensors /T REG_DWORD /D 1 >NUL 2>&1
	REG ADD "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\TabletPC" /F /v PreventHandwritingDataSharing /T REG_DWORD /D 1 >NUL 2>&1
)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /F /v Enabled /T REG_DWORD /D 0 >NUL 2>&1
IF NOT DEFINED AUTOTWEAK GOTO :HOME
IF DEFINED AUTOTWEAK GOTO :AUTOTWEAKS


:AUTOTWEAKS
IF NOT DEFINED AUTOTWEAK (
	SET AUTOTWEAK="y"
	IF %winversion% == 100 (
		CALL :XSVCTOKEN
	)
	GOTO :SVCTWEAKED
)
CALL :XDONE
GOTO :eof

:CLEANER
CALL :XTITLE WINDOWS CLEANER
CALL :XECHO Clean Windows with cleanmgr
powershell -ExecutionPolicy Bypass "& '%~dp0\resources\WindowsCleanup.ps1'" >NUL 2>&1
IF EXIST %LOCALAPPDATA%\Mozilla\Firefox\Profiles (
	CALL :XECHO Clear Firefox cache
	DEL "%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*.*" /f /s /q >NUL 2>&1
	FOR /D %%i IN ("%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*") DO RD /S /Q "%%i" >NUL 2>&1
)
GOTO :HOME

:UNUSEDDRIVER
CALL :XTITLE REMOVE UNUSED DRIVERS
IF EXIST %ProgramFiles(x86)% (
	CALL %~dp0\resources\x64\DeviceCleanupCmd.exe * -s
	MODE con lines=40 cols=59
) ELSE (
	CALL %~dp0\resources\x86\DeviceCleanupCmd.exe * -s
	MODE con lines=40 cols=59
)
GOTO :HOME

::::::::::::::::::::::::::::::::
:: WINDOWS SVC BY Black Viper ::
::::::::::::::::::::::::::::::::
:SVCSAFE
IF %winversion% == 100 (
	ECHO.
	ECHO Select:
	ECHO.
	ECHO 1. DESKTOP
	ECHO 2. LAPTOP or TABLET
	ECHO.


	SET /p web="Type option: "
	IF "%web%"=="1" GOTO :SVCSAFEDESK
	IF "%web%"=="2" GOTO :SVCSAFELAPTAB
)
IF %winversion% == 61 (
	::Automatic
	FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS Dnscache FDResPub gpsvc 
	MMCSS NlaSvc nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer 
	ShellHWDetection sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv 
	AudioEndpointBuilder WinDefend EventLog MpsSvc FontCache Winmgmt wuauserv LanmanWorkstation) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
	::Manual
	FOR %%I IN (AxInstSV SensrSvc AeLookupSvc AppIDSvc Appinfo ALG BITS BDESVC wbengine KeyIso 
	COMSysApp Browser VaultSvc WdiServiceHost WdiSystemHost defragsvc MSDTC EFS EapHost Fax fdPHost 
	hkmsvc HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect PolicyAgent KtmRm lltdsvc 
	clr_optimization_v2.0.50727 swprv Netman netprofm PNRPsvc p2psvc p2pimsvc pla IPBusEnum PNRPAutoReg 
	WPDBusEnum wercplsupport PcaSvc ProtectedStorage QWAVE RasAuto RasMan SessionEnv TermService 
	UmRdpService seclogon SstpSvc sppuinotify TabletInputService TapiSrv THREADORDER TBS upnphost 
	vds VSS WebClient SDRSVC WbioSrvc idsvc WcsPlugInService wudfsvc WerSvc Wecsvc StiSvc msiserver 
	ehRecvr ehSched TrustedInstaller FontCache3.0.0.0 WinRM W32Time WinHttpAutoProxySvc dot3svc Wlansvc 
	wmiApSrv WwanSvc) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
	::Disabled
	FOR %%I IN (AppMgmt bthserv PeerDistSvc CertPropSvc TrkWks SharedAccess iphlpsvc Mcx2Svc MSiSCSI 
	NetTcpPortSharing Netlogon napagent CscService WPCSvc RpcLocator RemoteRegistry RemoteAccess 
	SCardSvr SCPolicySvc SNMPTRAP SSDPSRV StorSvc wcncsvc WMPNetworkSvc WSearch) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
)
GOTO :HOME
:SVCTWEAKED
IF %winversion% == 100 (
	::Automatic
	FOR %%I IN (BITS BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_%service% CoreMessagingRegistrar 
	CryptSvc DusmSvc DcomLaunch Dhcp Dnscache gpsvc LSM NlaSvc nsi Power PcaSvc RpcSs 
	RpcEptMapper SamSs ShellHWDetection sppsvc SysMain OneSyncSvc_%service% SENS 
	SystemEventsBroker Schedule Themes UserManager ProfSvc AudioSrv AudioEndpointBuilder Wcmsvc WinDefend 
	MpsSvc SecurityHealthService EventLog FontCache Winmgmt WpnService WSearch LanmanWorkstation) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
	::Manual
	FOR %%I IN (AxInstSV AppReadiness AppIDSvc Appinfo AppXSVC BDESVC wbengine camsvc ClipSVC KeyIso 
	COMSysApp Browser PimIndexMaintenanceSvc_%service% VaultSvc DsSvc DeviceAssociationService 
	DeviceInstall DmEnrollmentSvc DsmSVC DevicesFlowUserSvc_%service% DevQueryBroker diagsvc 
	WdiSystemHost MSDTC embeddedmode EFS EntAppSvc EapHost fhsvc fdPHost FDResPub GraphicsPerfSvc 
	hidserv IKEEXT UI0Detect PolicyAgent KtmRm lltdsvc wlpasvc MessagingService_%service% wlidsvc 
	NgcSvc NgcCtnrSvc swprv smphost Netman NcaSVC netprofm NetSetupSvc defragsvc PNRPsvc p2psvc 
	p2pimsvc PerfHost pla PlugPlay PNRPAutoReg WPDBusEnum PrintNotify PrintWorkflowUserSvc_%service% 
	wercplsupport QWAVE RmSvc RasAuto RasMan seclogon SstpSvc SharedRealitySvc svsvc SSDPSRV 
	StateRepository WiaRpc StorSvc TieringEngineService lmhosts TapiSrv tiledatamodelsvc TimeBroker 
	UsoSvc upnphost UserDataSvc_%service% UnistoreSvc_%service% vds VSS WalletService TokenBroker 
	SDRSVC Sense WdNisSvc WEPHOSTSVC WerSvc Wecsvc StiSvc msiserver LicenseManager TrustedInstaller 
	spectrum WpnUserService_%service% InstallService W32Time wuauserv WinHttpAutoProxySvc dot3svc 
	WlanSvc wmiApSrv XboxGipSvc) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
	::Disabled
	FOR %%I IN (AJRouter ALG AppMgmt tzautoupdate BthHFSrv bthserv PeerDistSvc CertPropSvc NfsClnt 
	MapsBroker lfsvc HvHost vmickvpexchange vmicguestinterface vmicshutdown vmicheartbeat 
	vmicvmsession vmicrdv vmictimesync vmicvss irmon SharedAccess iphlpsvc IpxlatCfgSvc AppVClient 
	MSiSCSI SmsRouter NaturalAuthentication Netlogon NcdAutoSetup CscService SEMgrSvc PhoneSvc 
	SessionEnv TermService UmRdpService RpcLocator RemoteRegistry RetailDemo RemoteAccess SensorDataService 
	SensrSvc SensorService shpamsvc SCardSvr ScDeviceEnum SCPolicySvc SNMPTRAP TabletInputService 
	UevAgentService WebClient WFDSConSvc FrameServer wcncsvc wisvc WMPNetworkSvc icssvc WinRM WwanSvc 
	xbgm XblAuthManager XblGameSave XboxNetApiSvc diagnosticshub.standardcollector.service DiagTrack 
	DoSvc DPS WdiServiceHost HomeGroupListener HomeGroupProvider NetTcpPortSharing TrkWks WbioSrvc 
	wscsvc NcbService Spooler LanmanServer dmwappushservice) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
)
IF %winversion% == 61 (
	::Automatic
	FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp Dnscache gpsvc MMCSS NlaSvc 
	nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection 
	sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv AudioEndpointBuilder WinDefend 
	EventLog MpsSvc FontCache Winmgmt wuauserv LanmanWorkstation) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
	::Manual
	FOR %%I IN (AeLookupSvc AppIDSvc Appinfo BITS wbengine KeyIso COMSysApp Browser defragsvc 
	MSDTC EapHost HomeGroupListener HomeGroupProvider IKEEXT PolicyAgent KtmRm clr_optimization_v2.0.50727 
	swprv Netman netprofm pla ProtectedStorage RasAuto RasMan seclogon SstpSvc sppuinotify SSDPSRV TapiSrv 
	THREADORDER upnphost vds VSS SDRSVC wudfsvc Wecsvc StiSvc msiserver TrustedInstaller FontCache3.0.0.0 
	W32Time dot3svc Wlansvc wmiApSrv) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
	::Disabled
	FOR %%I IN (AxInstSV SensrSvc ALG AppMgmt BDESVC bthserv PeerDistSvc CertPropSvc VaultSvc DPS WdiServiceHost 
	WdiSystemHost TrkWks EFS Fax fdPHost FDResPub hkmsvc hidserv UI0Detect SharedAccess iphlpsvc lltdsvc Mcx2Svc 
	MSiSCSI NetTcpPortSharing Netlogon napagent CscService WPCSvc PNRPsvc p2psvc p2pimsvc IPBusEnum PNRPAutoReg 
	WPDBusEnum wercplsupport PcaSvc QWAVE SessionEnv TermService UmRdpService RpcLocator RemoteRegistry RemoteAccess 
	SCardSvr SCPolicySvc SNMPTRAP StorSvc TabletInputService TBS WebClient WbioSrvc idsvc WcsPlugInService wcncsvc 
	WerSvc ehRecvr ehSched WMPNetworkSvc WinRM WSearch WinHttpAutoProxySvc WwanSvc) DO (
		REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
		IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
)
IF NOT DEFINED AUTOTWEAK GOTO :HOME
IF DEFINED AUTOTWEAK GOTO :SYSTWEAK

:SVCDEFAULT
ECHO.
ECHO SET DEFAULT SERVICES FOR %winedition%
PAUSE
IF %winversion% == 100 (
	IF "%winedition%" == "Windows 10 Home" (
		::Automatic
		FOR %%I IN (BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_%service% DiagTrack CoreMessagingRegistrar 
		CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache MapsBroker gpsvc iphlpsvc LSM NlaSvc nsi 
		Power Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection sppsvc SysMain 
		OneSyncSvc_%service% SENS SystemEventsBroker Schedule Themes UserManager ProfSvc AudioSrv AudioEndpointBuilder 
		Wcmsvc WinDefend MpsSvc SecurityHealthService EventLog FontCache Winmgmt WpnService WSearch WlanSvc 
		LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
		::Manual
		FOR %%I IN (AxInstSV AJRouter AppReadiness AppIDSvc Appinfo ALG AppXSVC BITS BDESVC wbengine BthHFSrv 
		bthserv camsvc CertPropSvc ClipSVC KeyIso COMSysApp Browser PimIndexMaintenanceSvc_%service% VaultSvc DsSvc 
		DeviceAssociationService DeviceInstall DmEnrollmentSvc DsmSVC DevicesFlowUserSvc_%service% DevQueryBroker 
		diagsvc WdiServiceHost WdiSystemHost MSDTC embeddedmode EFS EntAppSvc EapHost Fax fhsvc 
		fdPHost FDResPub lfsvc GraphicsPerfSvc HomeGroupListener HomeGroupProvider hidserv HvHost vmickvpexchange 
		vmicguestinterface vmicshutdown vmicheartbeat vmicvmsession vmicrdv vmictimesync vmicvss IKEEXT irmon 
		UI0Detect SharedAccess IpxlatCfgSvc PolicyAgent KtmRm lltdsvc wlpasvc MessagingService_%service% 
		diagnosticshub.standardcollector.service wlidsvc MSiSCSI NgcSvc NgcCtnrSvc swprv smphost SmsRouter 
		NaturalAuthentication Netlogon NcdAutoSetup NcbService Netman NcaSVC netprofm NetSetupSvc defragsvc 
		SEMgrSvc PNRPsvc p2psvc p2pimsvc PerfHost pla PhoneSvc PlugPlay PNRPAutoReg WPDBusEnum PrintNotify 
		PrintWorkflowUserSvc_%service% wercplsupport QWAVE RmSvc RasAuto RasMan SessionEnv TermService UmRdpService 
		RpcLocator RetailDemo seclogon SstpSvc SensorDataService SensrSvc SensorService ScDeviceEnum SCPolicySvc 
		SNMPTRAP SharedRealitySvc svsvc SSDPSRV StateRepository WiaRpc StorSvc TieringEngineService lmhosts 
		TapiSrv tiledatamodelsvc TimeBroker TabletInputService UsoSvc upnphost UserDataSvc_%service% UnistoreSvc_%service% 
		vds VSS WalletService  TokenBroker WebClient WFDSConSvc SDRSVC WbioSrvc FrameServer wcncsvc WdNisSvc 
		WEPHOSTSVC WerSvc Wecsvc StiSvc wisvc msiserver LicenseManager WMPNetworkSvc icssvc TrustedInstaller 
		spectrum WpnUserService_%service% WinRM InstallService W32Time wuauserv WinHttpAutoProxySvc dot3svc wmiApSrv 
		workfolderssvc WwanSvc XboxGipSvc xbgm XblAuthManager XblGameSave XboxNetApiSvc dmwappushservice) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
		::Disabled
		FOR %%I IN (tzautoupdate NetTcpPortSharing RemoteRegistry RemoteAccess shpamsvc SCardSvr) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
	)
	IF "%winedition%" == "Windows 10 Pro" (
		::Automatic
		FOR %%I IN (BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_%service% DiagTrack CoreMessagingRegistrar 
		CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache MapsBroker gpsvc iphlpsvc LSM NlaSvc nsi 
		Power Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection sppsvc SysMain 
		OneSyncSvc_%service% SENS SystemEventsBroker Schedule Themes UserManager ProfSvc AudioSrv AudioEndpointBuilder 
		Wcmsvc WinDefend MpsSvc SecurityHealthService EventLog FontCache Winmgmt WpnService WSearch WlanSvc 
		LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
		::Manual
		FOR %%I IN (AxInstSV AJRouter AppReadiness AppIDSvc Appinfo ALG AppMgmt AppXSVC BITS BDESVC wbengine 
		BthHFSrv bthserv PeerDistSvc camsvc CertPropSvc ClipSVC KeyIso COMSysApp Browser dmwappushservice
		PimIndexMaintenanceSvc_%service% VaultSvc DsSvc DeviceAssociationService DeviceInstall DmEnrollmentSvc 
		DsmSVC DevicesFlowUserSvc_%service% DevQueryBroker diagsvc WdiServiceHost WdiSystemHost MSDTC 
		embeddedmode EFS EntAppSvc EapHost Fax fhsvc fdPHost FDResPub lfsvc GraphicsPerfSvc HomeGroupListener 
		HomeGroupProvider hidserv HvHost vmickvpexchange vmicguestinterface vmicshutdown vmicheartbeat 
		vmicvmsession vmicrdv vmictimesync vmicvss IKEEXT irmon UI0Detect SharedAccess IpxlatCfgSvc PolicyAgent 
		KtmRm lltdsvc wlpasvc MessagingService_%service% diagnosticshub.standardcollector.service wlidsvc MSiSCSI 
		NgcSvc NgcCtnrSvc swprv smphost SmsRouter NaturalAuthentication Netlogon NcdAutoSetup NcbService Netman 
		NcaSVC netprofm NetSetupSvc CscService defragsvc SEMgrSvc PNRPsvc p2psvc p2pimsvc PerfHost pla PhoneSvc 
		PlugPlay PNRPAutoReg WPDBusEnum PrintNotify PrintWorkflowUserSvc_%service% wercplsupport QWAVE RmSvc RasAuto 
		RasMan SessionEnv TermService UmRdpService RpcLocator RetailDemo seclogon SstpSvc SensorDataService 
		SensrSvc SensorService ScDeviceEnum SCPolicySvc SNMPTRAP SharedRealitySvc svsvc SSDPSRV StateRepository 
		WiaRpc StorSvc TieringEngineService lmhosts TapiSrv tiledatamodelsvc TimeBroker TabletInputService UsoSvc 
		upnphost UserDataSvc_%service% UnistoreSvc_%service% vds VSS WalletService  TokenBroker WebClient WFDSConSvc 
		SDRSVC WbioSrvc FrameServer wcncsvc Sense WdNisSvc WEPHOSTSVC WerSvc Wecsvc StiSvc wisvc msiserver 
		LicenseManager WMPNetworkSvc icssvc TrustedInstaller spectrum WpnUserService_%service% WinRM InstallService 
		W32Time wuauserv WinHttpAutoProxySvc dot3svc wmiApSrv workfolderssvc WwanSvc XboxGipSvc xbgm 
		XblAuthManager XblGameSave XboxNetApiSvc) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
		::Disabled
		FOR %%I IN (tzautoupdate AppVClient NetTcpPortSharing RemoteRegistry RemoteAccess shpamsvc SCardSvr UevAgentService) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
	)
)
IF %winversion% == 61 (
	IF "%winedition%" == "Windows 7 Starter" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc
		MMCSS NlaSvc nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection
		sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv AudioEndpointBuilder WinDefend EventLog
		MpsSvc FontCache Winmgmt WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
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
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
	)
	IF "%winedition%" == "Windows 7 Home Basic" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc 
		MMCSS NlaSvc nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection 
		sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv AudioEndpointBuilder WinDefend EventLog 
		MpsSvc FontCache Winmgmt WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
		::Manual
		FOR %%I IN (AxInstSV SensrSvc AeLookupSvc AppIDSvc Appinfo ALG BITS BDESVC wbengine bthserv CertPropSvc 
		KeyIso COMSysApp Browser VaultSvc WdiServiceHost WdiSystemHost defragsvc MSDTC EFS EapHost Fax fdPHost 
		hkmsvc HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect PolicyAgent KtmRm lltdsvc clr_optimization_v2.0.50727 
		MSiSCSI swprv Netlogon napagent Netman netprofm WPCSvc PNRPsvc p2psvc p2pimsvc pla IPBusEnum PNRPAutoReg WPDBusEnum 
		wercplsupport PcaSvc ProtectedStorage QWAVE RasAuto RasMan SessionEnv TermService RpcLocator RemoteRegistry seclogon 
		SstpSvc SCardSvr SCPolicySvc SNMPTRAP sppuinotify SSDPSRV TabletInputService TapiSrv THREADORDER TBS upnphost vds 
		VSS WebClient SDRSVC WbioSrvc idsvc WcsPlugInService wcncsvc wudfsvc WerSvc Wecsvc StiSvc msiserver WMPNetworkSvc 
		TrustedInstaller FontCache3.0.0.0 WinRM W32Time WinHttpAutoProxySvc dot3svc Wlansvc wmiApSrv WwanSvc) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
	)
	IF "%winedition%" == "Windows 7 Home Premium" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc MMCSS 
		NlaSvc nsi PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection sppsvc SysMain 
		SENS Schedule lmhosts Themes ProfSvc AudioSrv AudioEndpointBuilder WinDefend EventLog MpsSvc FontCache Winmgmt 
		WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
		::Manual
		FOR %%I IN (AxInstSV SensrSvc AeLookupSvc AppIDSvc Appinfo ALG BITS BDESVC wbengine bthserv CertPropSvc KeyIso 
		COMSysApp Browser VaultSvc WdiServiceHost WdiSystemHost defragsvc MSDTC EFS EapHost Fax fdPHost hkmsvc HomeGroupListener 
		HomeGroupProvider hidserv IKEEXT UI0Detect PolicyAgent KtmRm lltdsvc clr_optimization_v2.0.50727 MSiSCSI swprv Netlogon 
		napagent Netman netprofm WPCSvc PNRPsvc p2psvc p2pimsvc pla IPBusEnum PNRPAutoReg WPDBusEnum wercplsupport PcaSvc 
		ProtectedStorage QWAVE RasAuto RasMan SessionEnv TermService RpcLocator RemoteRegistry seclogon SstpSvc SCardSvr SCPolicySvc 
		SNMPTRAP sppuinotify SSDPSRV TabletInputService TapiSrv THREADORDER TBS upnphost vds VSS WebClient SDRSVC WbioSrvc idsvc 
		WcsPlugInService wcncsvc wudfsvc WerSvc Wecsvc StiSvc msiserver ehRecvr ehSched WMPNetworkSvc TrustedInstaller 
		FontCache3.0.0.0 WinRM W32Time WinHttpAutoProxySvc dot3svc Wlansvc wmiApSrv WwanSvc) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess Mcx2Svc NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
	)
	IF "%winedition%" == "Windows 7 Professional" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc 
		clr_optimization_v2.0.50727 MMCSS NlaSvc nsi CscService PlugPlay Power Spooler RpcSs RpcEptMapper SamSs 
		wscsvc LanmanServer ShellHWDetection sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv 
		AudioEndpointBuilder WinDefend EventLog MpsSvc FontCache Winmgmt WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
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
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess Mcx2Svc NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
	)
	IF "%winedition%" == "Windows 7 Ultimate" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc 
		MMCSS NlaSvc nsi CscService PlugPlay Power Spooler RpcSs RpcEptMapper SamSs wscsvc LanmanServer ShellHWDetection 
		sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv AudioEndpointBuilder WinDefend EventLog MpsSvc 
		FontCache Winmgmt WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
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
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess Mcx2Svc NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
	)
	IF "%winedition%" == "Windows 7 Enterprise" (
		::Automatic
		FOR %%I IN (BFE EventSystem CryptSvc DcomLaunch UxSms Dhcp DPS TrkWks Dnscache FDResPub gpsvc iphlpsvc 
		clr_optimization_v2.0.50727 MMCSS NlaSvc nsi CscService PlugPlay Power Spooler RpcSs RpcEptMapper SamSs 
		wscsvc LanmanServer ShellHWDetection sppsvc SysMain SENS Schedule lmhosts Themes ProfSvc AudioSrv 
		AudioEndpointBuilder WinDefend EventLog MpsSvc FontCache Winmgmt WSearch wuauserv LanmanWorkstation) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
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
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
		::Disabled
		FOR %%I IN (SharedAccess Mcx2Svc NetTcpPortSharing RemoteAccess) DO (
			REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
			IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
	)
)
GOTO :HOME

:SVCSAFEDESK
::Automatic
FOR %%I IN (BITS BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_%service% DiagTrack 
CoreMessagingRegistrar CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache gpsvc 
iphlpsvc LSM NlaSvc nsi Power Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer 
ShellHWDetection sppsvc SysMain OneSyncSvc_%service% SENS SystemEventsBroker Schedule Themes 
UserManager ProfSvc AudioSrv AudioEndpointBuilder Wcmsvc WinDefend MpsSvc SecurityHealthService 
EventLog FontCache Winmgmt WpnService WSearch LanmanWorkstation) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
::Manual
FOR %%I IN (AxInstSV AJRouter AppReadiness AppIDSvc Appinfo AppMgmt AppXSVC BDESVC wbengine 
BthHFSrv bthserv camsvc CertPropSvc ClipSVC KeyIso COMSysApp Browser PimIndexMaintenanceSvc_%service% 
VaultSvc DsSvc DeviceAssociationService DeviceInstall DmEnrollmentSvc DsmSVC DevicesFlowUserSvc_%service% 
DevQueryBroker diagsvc WdiServiceHost WdiSystemHost MSDTC embeddedmode EFS EntAppSvc EapHost fhsvc 
fdPHost FDResPub GraphicsPerfSvc HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect 
IpxlatCfgSvc PolicyAgent KtmRm lltdsvc wlpasvc MessagingService_%service% 
diagnosticshub.standardcollector.service wlidsvc NgcSvc NgcCtnrSvc swprv smphost NaturalAuthentication 
Netlogon NcdAutoSetup NcbService Netman NcaSVC netprofm NetSetupSvc defragsvc PNRPsvc p2psvc p2pimsvc 
PerfHost pla PlugPlay PNRPAutoReg WPDBusEnum PrintNotify PrintWorkflowUserSvc_%service% wercplsupport 
QWAVE RmSvc RasAuto RasMan SessionEnv TermService UmRdpService seclogon SstpSvc SharedRealitySvc 
svsvc SSDPSRV StateRepository WiaRpc StorSvc TieringEngineService lmhosts TapiSrv tiledatamodelsvc 
TimeBroker UsoSvc upnphost UserDataSvc_%service% UnistoreSvc_%service% vds VSS WalletService  TokenBroker 
WebClient SDRSVC WbioSrvc wcncsvc Sense WdNisSvc WEPHOSTSVC WerSvc Wecsvc StiSvc msiserver 
LicenseManager TrustedInstaller spectrum WpnUserService_%service% InstallService W32Time wuauserv 
WinHttpAutoProxySvc dot3svc WlanSvc wmiApSrv XboxGipSvc) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
::Disabled
FOR %%I IN (ALG tzautoupdate PeerDistSvc NfsClnt dmwappushservice MapsBroker lfsvc HvHost 
vmickvpexchange vmicguestinterface vmicshutdown vmicheartbeat vmicvmsession vmicrdv vmictimesync 
vmicvss irmon SharedAccess AppVClient MSiSCSI SmsRouter CscService SEMgrSvc PhoneSvc RpcLocator 
RemoteRegistry RetailDemo RemoteAccess SensorDataService SensrSvc SensorService shpamsvc SCardSvr 
ScDeviceEnum SCPolicySvc SNMPTRAP TabletInputService UevAgentService WFDSConSvc FrameServer wisvc 
WMPNetworkSvc icssvc WinRM WwanSvc xbgm XblAuthManager XblGameSave XboxNetApiSvc) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
GOTO :HOME
:SVCSAFELAPTAB
::Automatic
FOR %%I IN (BITS BrokerInfrastructure BFE EventSystem CDPSvc CDPUserSvc_%service% DiagTrack 
CoreMessagingRegistrar CryptSvc DusmSvc DcomLaunch DoSvc Dhcp DPS TrkWks Dnscache gpsvc 
iphlpsvc LSM NlaSvc nsi Power Spooler PcaSvc RpcSs RpcEptMapper SamSs wscsvc LanmanServer 
ShellHWDetection sppsvc SysMain OneSyncSvc_%service% SENS SystemEventsBroker Schedule Themes 
UserManager ProfSvc AudioSrv AudioEndpointBuilder Wcmsvc WinDefend MpsSvc SecurityHealthService 
EventLog FontCache Winmgmt WpnService WSearch WlanSvc LanmanWorkstation) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 2 >NUL 2>&1)
::Manual
FOR %%I IN (AxInstSV AJRouter AppReadiness AppIDSvc Appinfo AppMgmt AppXSVC BDESVC wbengine 
BthHFSrv bthserv camsvc CertPropSvc ClipSVC KeyIso COMSysApp Browser PimIndexMaintenanceSvc_%service% 
VaultSvc DsSvc DeviceAssociationService DeviceInstall DmEnrollmentSvc DsmSVC DevicesFlowUserSvc_%service% 
DevQueryBroker diagsvc WdiServiceHost WdiSystemHost MSDTC embeddedmode EFS EntAppSvc EapHost fhsvc 
fdPHost FDResPub GraphicsPerfSvc HomeGroupListener HomeGroupProvider hidserv IKEEXT UI0Detect 
IpxlatCfgSvc PolicyAgent KtmRm lltdsvc wlpasvc MessagingService_%service% 
diagnosticshub.standardcollector.service wlidsvc NgcSvc NgcCtnrSvc swprv smphost NaturalAuthentication 
Netlogon NcdAutoSetup NcbService Netman NcaSVC netprofm NetSetupSvc defragsvc PNRPsvc p2psvc p2pimsvc 
PerfHost pla PlugPlay PNRPAutoReg WPDBusEnum PrintNotify PrintWorkflowUserSvc_%service% wercplsupport QWAVE 
RmSvc RasAuto RasMan SessionEnv TermService UmRdpService seclogon SstpSvc SensorDataService SensrSvc 
SensorService SharedRealitySvc svsvc SSDPSRV StateRepository WiaRpc StorSvc TieringEngineService lmhosts 
TapiSrv tiledatamodelsvc TimeBroker TabletInputService UsoSvc upnphost UserDataSvc_%service% UnistoreSvc_%service% 
vds VSS WalletService  TokenBroker WebClient WFDSConSvc SDRSVC WbioSrvc wcncsvc Sense WdNisSvc WEPHOSTSVC 
WerSvc Wecsvc StiSvc msiserver LicenseManager TrustedInstaller spectrum WpnUserService_%service% InstallService 
W32Time wuauserv WinHttpAutoProxySvc dot3svc wmiApSrv XboxGipSvc) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 3 >NUL 2>&1)
::Disabled
FOR %%I IN (ALG tzautoupdate PeerDistSvc NfsClnt dmwappushservice MapsBroker lfsvc HvHost vmickvpexchange 
vmicguestinterface vmicshutdown vmicheartbeat vmicvmsession vmicrdv vmictimesync vmicvss irmon 
SharedAccess AppVClient MSiSCSI SmsRouter CscService SEMgrSvc PhoneSvc RpcLocator RemoteRegistry 
RetailDemo RemoteAccess shpamsvc SCardSvr ScDeviceEnum SCPolicySvc SNMPTRAP UevAgentService FrameServer 
wisvc WMPNetworkSvc icssvc WinRM WwanSvc xbgm XblAuthManager XblGameSave XboxNetApiSvc) DO (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /ve >NUL 2>&1
	IF NOT ERRORLEVEL 1 REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\%%I" /F /v Start /T REG_DWORD /D 4 >NUL 2>&1)
GOTO :HOME

:::::::::::::::::::::::::::::::::::::
:: BATCH SCRIPT INTERNAL FUNCTIONS ::
:::::::::::::::::::::::::::::::::::::
:XSVCTOKEN
REG EXPORT HKLM\SYSTEM\CurrentControlSet\Services %~dp0\TEMP.reg >NUL 2>&1
FOR /F "SKIP=2" %%u IN ('FIND "CDPUserSvc_" %~dp0\TEMP.reg') DO (
	FOR /F "TOKENS=1 DELIMS=<[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc_>" %%a in ("%%u") DO (
		SET service=%%a
		DEL /F /Q "%~dp0\TEMP.reg" >NUL 2>&1
		GOTO :BREAK
	)
)
:BREAK
SET service=%service:~0,5%
GOTO :eof
::END.XSVCTOKEN

:XWAIT
PING -n %1 127.0.0.1 >NUL 2>&1
GOTO :eof
::END.XWAIT

:XDONE
ECHO/
ECHO/===========================================================
ECHO/DONE: %* 
ECHO/
IF DEFINED _TRACE ECHO Press any key to quit &PAUSE >NUL &EXIT
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