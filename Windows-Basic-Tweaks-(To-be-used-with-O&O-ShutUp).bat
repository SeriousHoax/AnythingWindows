rem                       1    2    3    4                     *Here We Go*                              


rem Requesting Administrator privilege for this batch script

:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

rem Disable Hibernate
powercfg -h off

rem Disable Reserved Storage (7GB)
Dism /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t reg_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t reg_DWORD /d "0" /f

rem winget list
winget uninstall "cortana"
winget uninstall "get help"
winget uninstall "microsoft people"
winget uninstall "microsoft tips"
winget uninstall "windows alarms & clock"
winget uninstall "windows camera"
winget uninstall "windows maps"
winget install --id 9nblggh1zbkw --exact --source msstore --accept-package-agreements --accept-source-agreements

rem https://msdn.microsoft.com/en-us/windows/hardware/commercialize/manufacture/desktop/enable-or-disable-windows-features-using-dism
rem DISM /Online /Get-Features /Format:Table

Dism /Online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2 /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2Root /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart

rem =================================== Windows Explorer ===================================
rem --------------------------------------- Options ----------------------------------------
rem ....................................... General ........................................

rem 2 - Open File Explorer to Quick access / 1 - Open File Explorer to This PC / 3 - Open File Explorer to Downloads
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t reg_DWORD /d "1" /f

rem 1 - Show recently used folders in Quick Access
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t reg_DWORD /d "0" /f

rem 1 - Show frequently folders in Quick Access
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t reg_DWORD /d "0" /f

rem =================================== Windows Explorer ===================================
rem --------------------------------------- Options ----------------------------------------
rem .................................. Advanced Settings ...................................

rem 1 - Show hidden files, folders and drives
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t reg_DWORD /d "1" /f

rem 0 - Show extensions for known file types
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t reg_DWORD /d "0" /f

rem 0 - Hide protected operating system files 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t reg_DWORD /d "0" /f

rem 1 - Always show more details in copy dialog
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t reg_DWORD /d "1" /f

rem Restricting PowerShell to Constrained Language mode

reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Environment" /v "__PSLockDownPolicy" /t reg_SZ /d "4" /f

rem Disable SMB 1.0/2.0
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t reg_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB2" /t reg_DWORD /d "0" /f

rem =============================== Windows Scheduled Tasks ================================

rem UAC Bypass - https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup
rem MsCtfMonitor Task (keylogger) is required to be able to type within Settings and etc

schtasks /DELETE /TN "AMDLinkUpdate" /f
schtasks /DELETE /TN "AMDRyzenMasterSDKTask" /f
schtasks /DELETE /TN "AMDInstallLauncher" /f
schtasks /DELETE /TN "ModifyLinkUpdate" /f
schtasks /DELETE /TN "StartDVR" /f

schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable

schtasks /DELETE /TN "Microsoft\Office\Office Automatic Updates 2.0" /f
schtasks /DELETE /TN "Microsoft\Office\Office ClickToRun Service Monitor" /f
schtasks /DELETE /TN "Microsoft\Office\Office Feature Updates" /f
schtasks /DELETE /TN "Microsoft\Office\Office Feature Updates Logon" /f
schtasks /DELETE /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /f
schtasks /DELETE /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /f
schtasks /DELETE /TN "Microsoft\Office\Office Performance Monitor" /f

rem Remote Desktop Services
sc config TermService start= disabled

rem =================================== Windows Settings ===================================
rem ------------------------------------ Accessibility ------------------------------------
rem ...................................... Keyboard .......................................

rem Sticky keys / 26 - Disable All / 511 - Default
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t reg_SZ /d "26" /f

rem =================================== Windows Settings ===================================
rem --------------------------------- Bluetooth & Devices ----------------------------------
rem ...................................... Autoplay .......................................

rem 0 - Use Autoplay for all media and devices
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t reg_DWORD /d "1" /f 

rem ________________________________________________________________________________________
rem Disable AutoPlay and AutoRun
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t reg_DWORD /d "255" /f

rem 0 - Disable WiFi Sense (shares your WiFi network login with other people)
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t reg_DWORD /d "0" /f

rem Setup DNS over HTTPS (DoH) Add Custom Servers

netsh dns add encryption server=45.90.28.211 dohtemplate=https://dns.nextdns.io/b95fb1/AniK-PC autoupgrade=yes udpfallback=no
netsh dns add encryption server=45.90.30.211 dohtemplate=https://dns.nextdns.io/b95fb1/AniK-PC autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.14.14 dohtemplate=https://dns.adguard.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.15.15 dohtemplate=https://dns.adguard.com/dns-query autoupgrade=yes udpfallback=no

rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ..................................... Background .......................................

rem ________________________________________________________________________________________
rem 60-100% Wallpaper's image quality / 85 - Default
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t reg_DWORD /d "100" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ....................................... Colors .........................................

rem 1 - Transparency Effects
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t reg_DWORD /d "1" /f

rem 1 - Show accent color on Start and taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t reg_DWORD /d "1" /f

rem 1 - Show accent color on the title bars and windows borders
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "ColorPrevalence" /t reg_DWORD /d "1" /f

rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ..................................... Lock screen ......................................

rem 1 Disable Sign-in screen acrylic (blur) background 
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t reg_DWORD /d "1" /f

rem Disable Password Reveal Button
reg add "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f

rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ........................................ Start .........................................

rem 1 - Show recently opened items in Start, Jump Lists, and File Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t reg_DWORD /d "0" /f

rem - Hide Recently Added Apps
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d "1" /f

rem - Hide Most Used Apps
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "ShowOrHideMostUsedApps" /t REG_DWORD /d "2" /f

rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ....................................... Taskbar ........................................

rem Task view / 0 - Off / 1 - On
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t reg_DWORD /d "0" /f

rem Chat / 0 - Off / 1 - On
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t reg_DWORD /d "0" /f

rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ................................ Diagnostics & feedback ................................

rem - Inking And Typing Personalization
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization" /v "Value" /t REG_DWORD /d "0" /f

rem 3 - Send optional diagnostic data / 1 - No
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t reg_DWORD /d "1" /f

rem Send optional dianostgic data / 0 - Security (Not aplicable on Home/Pro, it resets to Basic) / 1 - Basic / 2 - Enhanced (Hidden) / 3 - Full
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t reg_DWORD /d "0" /f

rem ................................... Remote Assistance ...................................

rem Remote Settings - Disable Remote Assistance
reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t reg_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t reg_DWORD /d "0" /f

rem Disable Remote Assistance
sc config Remoteregistry start= disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicitedFullControl" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSAppCompat" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSEnabled" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSUserEnabled" /t reg_DWORD /d "0" /f

rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem .................................... Notifications .....................................

rem 1 - Show me the Windows welcome experience
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t reg_DWORD /d "0" /f

rem 1 - Offer suggestions on how I can set up my device
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t reg_DWORD /d "0" /f

rem ________________________________________________________________________________________

rem 1 - Disable Malicious Software Removal Tool offered via Windows Updates (MRT)

reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t reg_DWORD /d "1" /f

rem Add "Take Ownership" Option in Files and Folders Context Menu in Windows

reg add "HKCR\*\shell\runas" /ve /t reg_SZ /d "Take ownership" /f
reg add "HKCR\*\shell\runas" /v "HasLUAShield" /t reg_SZ /d "" /f
reg add "HKCR\*\shell\runas" /v "NoWorkingDirectory" /t reg_SZ /d "" /f
reg add "HKCR\*\shell\runas\command" /ve /t reg_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
reg add "HKCR\*\shell\runas\command" /v "IsolatedCommand" /t reg_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
reg add "HKCR\Directory\shell\runas" /ve /t reg_SZ /d "Take ownership" /f
reg add "HKCR\Directory\shell\runas" /v "HasLUAShield" /t reg_SZ /d "" /f
reg add "HKCR\Directory\shell\runas" /v "NoWorkingDirectory" /t reg_SZ /d "" /f
reg add "HKCR\Directory\shell\runas\command" /ve /t reg_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
reg add "HKCR\Directory\shell\runas\command" /v "IsolatedCommand" /t reg_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f

rem Show Detailed Information During Startup, Shutdown, Login, and Logout / Enable Verbose or Highly Detailed Status Messages
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f

rem Disable Microsoft Edge Tabs in Alt+Tab

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "MultiTaskingAltTabFilter" /t REG_DWORD /d "3" /f

rem Disable Thumbnail Border for Images and Videos

reg add "HKCR\SystemFileAssociations\image" /v "Treatment" /t REG_DWORD /d "0" /f
reg add "HKCR\SystemFileAssociations\video" /v "Treatment" /t REG_DWORD /d "0" /f

rem Make mouse cursor Black 

reg add "HKCU\Control Panel\Cursors" /v "AppStarting" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\wait_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "Arrow" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\arrow_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "ContactVisualization" /t reg_DWORD /d "1" /f
reg add "HKCU\Control Panel\Cursors" /v "Crosshair" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\cross_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "CursorBaseSize" /t reg_DWORD /d "32" /f
reg add "HKCU\Control Panel\Cursors" /v "GestureVisualization" /t reg_DWORD /d "31" /f
reg add "HKCU\Control Panel\Cursors" /v "Help" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\help_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "IBeam" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\beam_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "No" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\no_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "NWPen" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\pen_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "Scheme Source" /t reg_DWORD /d "2" /f
reg add "HKCU\Control Panel\Cursors" /v "SizeAll" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\move_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "SizeNESW" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\size1_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "SizeNS" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\size4_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "SizeNWSE" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\size2_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "SizeWE" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\size3_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "UpArrow" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\up_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "Wait" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\busy_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /ve /t reg_SZ /d "Windows Black" /f
reg add "HKCU\Control Panel\Cursors" /v "Pin" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\pin_r.cur" /f
reg add "HKCU\Control Panel\Cursors" /v "Person" /t reg_EXPAND_SZ /d "%%SystemRoot%%\cursors\person_r.cur" /f

rem Microsoft Defender Hash Log, Startup Update, Cloud Protection Level, Cloud Timeout Extend and PUP Protection

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d "50" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "UpdateOnStartUp" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ThreatFileHashLogging" /t REG_DWORD /d "1" /f

rem Remove Windows product key from the registry
slmgr /cpky


rem                            OK                              *It's Over*
