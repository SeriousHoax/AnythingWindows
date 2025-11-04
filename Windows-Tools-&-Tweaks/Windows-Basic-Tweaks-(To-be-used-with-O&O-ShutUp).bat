rem                       1    2    3    4                     *Here We Go*                              

rem Requesting Administrator privilege for this batch script

:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 fsutil dirty query %systemdrive%

REM --> If error flag set, we do not have admin.
if %errorlevel% NEQ 0 (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    powershell -Command "Start-Process '%~s0' -Verb RunAs"
    exit /B

:gotAdmin
:--------------------------------------

rem Disable Hibernate
powercfg -h off

rem Disable Reserved Storage (7GB)
Dism /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t reg_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t reg_DWORD /d "0" /f

rem Remove unnecessary files/folders

rd "C:\Users\AniK\Favorites" /s /q
rd "C:\Users\AniK\Links" /s /q

rem ================================ Windows Error Reporting ===============================

rem https://docs.microsoft.com/en-us/windows/win32/wer/wer-settings

rem Disable Microsoft Support Diagnostic Tool MSDT
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t REG_DWORD /d "0" /f

rem Disable System Debugger (Dr. Watson)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d "0" /f

rem 1 - Disable Windows Error Reporting (WER)
reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f

rem DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f

rem 1 - Disable WER sending second-level data
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f

rem 1 - Disable WER crash dialogs, popups
reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f

rem 1 - Disable WER logging
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f

schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

rem Disable Windows Error Reporting Service
sc config WerSvc start= disabled

rem =================================== Windows Explorer ===================================

rem 2 - Open File Explorer to Quick access / 1 - Open File Explorer to This PC / 3 - Open File Explorer to Downloads
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t reg_DWORD /d "1" /f

rem 1 - Show recently used folders in Quick Access
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t reg_DWORD /d "0" /f

rem 1 - Show frequently folders in Quick Access
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t reg_DWORD /d "0" /f

rem 1 - Show hidden files, folders and drives
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t reg_DWORD /d "1" /f

rem 0 - Show extensions for known file types
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t reg_DWORD /d "0" /f

rem 0 - Hide protected operating system files 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t reg_DWORD /d "0" /f

rem Remove Home (Quick access) from This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "1" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f

rem Remove Gallery from Navigation Pane in File Explorer
reg add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f

rem 1 - Always show more details in copy dialog
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t reg_DWORD /d "1" /f

rem Disable 260 character limit for file path

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f

rem =================================== Windows Policies ===================================

rem Disable Active Desktop
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceActiveDesktopOn" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktop" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktopChanges" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "ff" /f

rem Enables or disables the retrieval of online tips and help for the Settings app (ADs)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f

rem 1 - Disable recent documents history
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "1" /f

rem 1 - Do not add shares from recently opened documents to the My Network Places folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsNetHood" /t REG_DWORD /d "1" /f

rem Disable SMB 1.0/2.0
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t reg_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB2" /t reg_DWORD /d "0" /f

rem =============================== Windows Scheduled Tasks ================================

schtasks /DELETE /TN "AMDLinkUpdate" /f
schtasks /DELETE /TN "AMDRyzenMasterSDKTask" /f
schtasks /DELETE /TN "AMDInstallLauncher" /f
schtasks /DELETE /TN "ModifyLinkUpdate" /f
schtasks /DELETE /TN "StartDVR" /f

schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable

schtasks /DELETE /TN "Microsoft\Office\Office Automatic Updates 2.0" /f
schtasks /DELETE /TN "Microsoft\Office\Office ClickToRun Service Monitor" /f
schtasks /DELETE /TN "Microsoft\Office\Office Feature Updates" /f
schtasks /DELETE /TN "Microsoft\Office\Office Feature Updates Logon" /f
schtasks /DELETE /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /f
schtasks /DELETE /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /f
schtasks /DELETE /TN "Microsoft\Office\Office Performance Monitor" /f

rem =============================== Windows Services ========================

rem Connected User Experiences and Telemetry
sc config DiagTrack start= disabled

rem Geolocation Service
sc config lfsvc start= disabled

rem Remote Desktop Services
sc config TermService start= disabled

rem Windows Remote Management (WS-Management)
sc config WinRM start= disabled

rem =================================== Windows Settings ===================================
rem ------------------------------------ Accessibility ------------------------------------
rem ...................................... Keyboard .......................................

rem Sticky keys / 26 - Disable All / 511 - Default
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t reg_SZ /d "26" /f

rem Enable Clipboard history
reg add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t reg_DWORD /d 1 /f

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

netsh dns add encryption server=94.140.14.14 dohtemplate=https://dns.adguard.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.15.15 dohtemplate=https://dns.adguard.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.2.42 dohtemplate=https://freedns.controld.com/x-hagezi-proplus autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.10.42 dohtemplate=https://freedns.controld.com/x-hagezi-proplus autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.2.2 dohtemplate=https://freedns.controld.com/p2 autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.10.2 dohtemplate=https://freedns.controld.com/p2 autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.2.4 dohtemplate=https://freedns.controld.com/family autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.10.4 dohtemplate=https://freedns.controld.com/family autoupgrade=yes udpfallback=no

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

rem Add Right Click "Open in Windows Terminal as administrator" Context Menu

reg add "HKCR\Directory\shell\OpenWTHereAsAdmin" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\Directory\shell\OpenWTHereAsAdmin" /v "MUIVerb" /t REG_SZ /d "Open in Windows Terminal as administrator" /f
reg delete "HKCR\Directory\shell\OpenWTHereAsAdmin" /v "Extended" /f
reg add "HKCR\Directory\shell\OpenWTHereAsAdmin" /v "SubCommands" /t REG_SZ /d "" /f
reg add "HKCR\Directory\Shell\OpenWTHereAsAdmin\shell\001flyout" /v "MUIVerb" /t REG_SZ /d "Default Profile" /f
reg add "HKCR\Directory\Shell\OpenWTHereAsAdmin\shell\001flyout" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\Directory\Shell\OpenWTHereAsAdmin\shell\001flyout\command" /ve /t REG_SZ /d "powershell.exe -WindowStyle Hidden \"Start-Process -Verb RunAs cmd.exe -ArgumentList @('/c','start wt.exe','-d','\"\"\"%%V\.\"\"\"')\"" /f
reg add "HKCR\Directory\Shell\OpenWTHereAsAdmin\shell\002flyout" /v "MUIVerb" /t REG_SZ /d "Command Prompt" /f
reg add "HKCR\Directory\Shell\OpenWTHereAsAdmin\shell\002flyout" /v "Icon" /t REG_SZ /d "imageres.dll,-5324" /f
reg add "HKCR\Directory\Shell\OpenWTHereAsAdmin\shell\002flyout\command" /ve /t REG_SZ /d "powershell.exe -WindowStyle Hidden \"Start-Process -Verb RunAs cmd.exe -ArgumentList @('/c','start wt.exe','-p','\"\"\"Command Prompt\"\"\"','-d','\"\"\"%%V\.\"\"\"')\"" /f
reg add "HKCR\Directory\Shell\OpenWTHereAsAdmin\shell\003flyout" /v "MUIVerb" /t REG_SZ /d "PowerShell" /f
reg add "HKCR\Directory\Shell\OpenWTHereAsAdmin\shell\003flyout" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\Directory\Shell\OpenWTHereAsAdmin\shell\003flyout" /v "Icon" /t REG_SZ /d "powershell.exe" /f
reg add "HKCR\Directory\Shell\OpenWTHereAsAdmin\shell\003flyout\command" /ve /t REG_SZ /d "powershell.exe -WindowStyle Hidden \"Start-Process -Verb RunAs cmd.exe -ArgumentList @('/c','start wt.exe','-p','\"\"\"Windows PowerShell\"\"\"','-d','\"\"\"%%1\.\"\"\"')\"" /f
reg add "HKCR\Directory\Background\shell\OpenWTHereAsAdmin" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\Directory\Background\shell\OpenWTHereAsAdmin" /v "MUIVerb" /t REG_SZ /d "Open in Windows Terminal as administrator" /f
reg delete "HKCR\Directory\Background\shell\OpenWTHereAsAdmin" /v "Extended" /f
reg add "HKCR\Directory\Background\shell\OpenWTHereAsAdmin" /v "SubCommands" /t REG_SZ /d "" /f
reg add "HKCR\Directory\Background\Shell\OpenWTHereAsAdmin\shell\001flyout" /v "MUIVerb" /t REG_SZ /d "Default Profile" /f
reg add "HKCR\Directory\Background\Shell\OpenWTHereAsAdmin\shell\001flyout" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\Directory\Background\Shell\OpenWTHereAsAdmin\shell\001flyout\command" /ve /t REG_SZ /d "powershell.exe -WindowStyle Hidden \"Start-Process -Verb RunAs cmd.exe -ArgumentList @('/c','start wt.exe','-d','\"\"\"%%V\.\"\"\"')\"" /f
reg add "HKCR\Directory\Background\Shell\OpenWTHereAsAdmin\shell\002flyout" /v "MUIVerb" /t REG_SZ /d "Command Prompt" /f
reg add "HKCR\Directory\Background\Shell\OpenWTHereAsAdmin\shell\002flyout" /v "Icon" /t REG_SZ /d "imageres.dll,-5324" /f
reg add "HKCR\Directory\Background\Shell\OpenWTHereAsAdmin\shell\002flyout\command" /ve /t REG_SZ /d "powershell.exe -WindowStyle Hidden \"Start-Process -Verb RunAs cmd.exe -ArgumentList @('/c','start wt.exe','-p','\"\"\"Command Prompt\"\"\"','-d','\"\"\"%%V\.\"\"\"')\"" /f
reg add "HKCR\Directory\Background\Shell\OpenWTHereAsAdmin\shell\003flyout" /v "MUIVerb" /t REG_SZ /d "PowerShell" /f
reg add "HKCR\Directory\Background\Shell\OpenWTHereAsAdmin\shell\003flyout" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\Directory\Background\Shell\OpenWTHereAsAdmin\shell\003flyout" /v "Icon" /t REG_SZ /d "powershell.exe" /f
reg add "HKCR\Directory\Background\Shell\OpenWTHereAsAdmin\shell\003flyout\command" /ve /t REG_SZ /d "powershell.exe -WindowStyle Hidden \"Start-Process -Verb RunAs cmd.exe -ArgumentList @('/c','start wt.exe','-p','\"\"\"Windows PowerShell\"\"\"','-d','\"\"\"%%V\.\"\"\"')\"" /f

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

rem Windows Firewall Block

netsh advfirewall firewall add rule name="CCleaner" dir=out action=block program="E:\Portables\Ccleaner Portable\CCleaner64.exe" enable=yes
netsh advfirewall firewall add rule name="CCleaner" dir=out action=block program="E:\Portables\Ccleaner Portable\x64\CCleanerBugReport.exe" enable=yes
netsh advfirewall firewall add rule name="Google Chrome TestingBox" dir=in action=block program="E:\Portables\Chrome Portable TestingBox\Chrome\Chrome.exe" enable=yes 
netsh advfirewall firewall add rule name="Google Chrome Report" dir=in action=block program="E:\Portables\Chrome Portable Report\Chrome\Chrome.exe" enable=yes
netsh advfirewall firewall add rule name="Microsoft Compatibility Telemetry" dir=out action=block program="C:\Windows\System32\CompatTelRunner.exe" enable=yes
netsh advfirewall firewall add rule name="EagleGet Free Downloader" dir=in action=block program="E:\Portables\EagleGet Protable\EagleGet.exe" enable=yes
netsh advfirewall firewall add rule name="filec" dir=in action=block program="E:\Portables\File Centipede\filec.exe" enable=yes
netsh advfirewall firewall add rule name="fileu" dir=in action=block program="E:\Portables\File Centipede\fileu.exe" enable=yes
netsh advfirewall firewall add rule name="Firefox" dir=in action=block program="C:\Program Files\Mozilla Firefox\firefox.exe" enable=yes
netsh advfirewall firewall add rule name="LocalSend" dir=in action=block program="E:\Portables\LocalSend\localsend_app.exe" enable=yes
netsh advfirewall firewall add rule name="Microsoft Edge" dir=in action=block program="C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" enable=yes description
netsh advfirewall firewall add rule name="Tixati Portable" dir=in action=block program="E:\Portables\Tixati Portable\tixati_Windows64bit.exe" enable=yes
netsh advfirewall firewall add rule name="WOMicClient" dir=in action=block program="C:\Program Files (x86)\WOMic\WOMicClient.exe" enable=yes

rem Set Windows Time to UTC - Prevents messing up system time after booting Linux ISOs

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f

rem Windows's built-in time syncing method is often buggy and doesn't work, so the `Windows Time` service is disabled

sc config w32time start= disabled

rem As an alternative the "Update Time" app by Sordum has been used to sync time - https://www.sordum.org/9203/update-time-v1-3/
rem copy UpdateTime folder to Program Files - Copying to the program files is not necessary but recommended to store it in the system drive

xcopy "E:\Portables\UpdateTime" "C:\Program Files\UpdateTime\" /e /i /y

rem Create the Update-Time service to sync time at every system startup

sc create Update-Time binpath= "\"C:\Program Files\UpdateTime\UpdateTime.exe\" /Service" displayname= "Update Time v1-3" start= auto
sc description Update-Time "Automatically Synchronize Computer date and time on Windows Startup."

rem Microsoft Defender Hash Log, Startup Update, Cloud Protection Level, Cloud Timeout Extend and PUP Protection

powershell -Command "Set-MpPreference -PUAProtection Enabled"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d "50" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "UpdateOnStartUp" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ThreatFileHashLogging" /t REG_DWORD /d "1" /f

rem Remove Windows product key from the registry
slmgr /cpky


rem                            OK                              *It's Over*