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
winget uninstall "Mail and Calendar"
winget uninstall "microsoft tips"
winget uninstall "Feedback Hub"
winget uninstall "windows camera"
winget uninstall "windows maps"
winget uninstall "Microsoft Teams"
winget uninstall "Microsoft News"
winget uninstall "MSN Weather"
winget uninstall "Office"
winget uninstall "Microsoft Solitaire Collection"
winget uninstall "Microsoft To Do"
winget uninstall "Movies & TV"
winget uninstall "Quick Assist"
winget uninstall "Clipchamp"
winget uninstall "Power Automate"

rem https://msdn.microsoft.com/en-us/windows/hardware/commercialize/manufacture/desktop/enable-or-disable-windows-features-using-dism
rem DISM /Online /Get-Features /Format:Table

Dism /Online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2 /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2Root /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart

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

rem Windows Error Reporting Service
sc config WerSvc start= disabled

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

rem Windows Remote Management (WS-Management)
sc config WinRM start= disabled

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

netsh dns add encryption server=**.**.**.*** dohtemplate=https://dns.nextdns.io/******/***-PC autoupgrade=yes udpfallback=no
netsh dns add encryption server=**.**.**.*** dohtemplate=https://dns.nextdns.io/******/***-PC autoupgrade=yes udpfallback=no
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

rem  Microsoft Edge Policies

rem https://docs.microsoft.com/en-us/deployedge/microsoft-edge-relnote-stable-channel
rem https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-policies
rem https://www.microsoft.com/en-us/download/details.aspx?id=55319
rem rem https://admx.help/?Category=EdgeChromium
rem edge://policy

rem reg delete "HKCU\Software\Policies\Microsoft\Edge" /f
rem reg delete "HKLM\Software\Policies\Microsoft\Edge" /f

rem 1 - Microsoft Edge can automatically enhance images to show you sharper images with better color, lighting, and contrast
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeEnhanceImagesEnabled" /t REG_DWORD /d "1" /f

rem 1 - Allows the Microsoft Edge browser to enable Follow service and apply it to users
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeFollowEnabled" /t REG_DWORD /d "0" /f

rem 1 - Allow Google Cast to connect to Cast devices on all IP addresses (Multicast), Edge trying to connect to 239.255.255.250 via UDP port 1900
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EnableMediaRouter" /t REG_DWORD /d "0" /f

rem 1 - Hide restore pages dialog after browser crash
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "HideRestoreDialogEnabled" /t REG_DWORD /d "1" /f

rem 1 - Show Hubs Sidebar
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t REG_DWORD /d "0" /f

rem 1 - Shows content promoting the Microsoft Edge Insider channels on the About Microsoft Edge settings page
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "MicrosoftEdgeInsiderPromotionEnabled" /t REG_DWORD /d "0" /f

rem 1 - Allow remote debugging
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "RemoteDebuggingAllowed" /t REG_DWORD /d "0" /f

rem 1 - Allow notifications to set Microsoft Edge as default PDF reader
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowPDFDefaultRecommendationsEnabled" /t REG_DWORD /d "0" /f

rem 1 - Allow Speech Recognition
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SpeechRecognitionEnabled" /t REG_DWORD /d "0" /f

rem ------------------------------------ Microsoft Edge ------------------------------------
rem ..................................... Appearances ......................................

rem 1 - Show mini menu when selecting text
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "QuickSearchShowMiniMenu" /t REG_DWORD /d "0" /f

rem 1 - Show home button
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowHomeButton" /t REG_DWORD /d "1" /f

rem 1 - Show tab actions menu (Show vertical tabs)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "VerticalTabsAllowed" /t REG_DWORD /d "0" /f

rem 1 - Allow the Edge bar
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "WebWidgetAllowed" /t REG_DWORD /d "0" /f

rem 1 - Allow the Edge bar at Windows startup
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "WebWidgetIsEnabledOnStartup" /t REG_DWORD /d "0" /f

rem ------------------------------------ Microsoft Edge ------------------------------------
rem .............................. Cookies and site permissions ............................

rem Block third-party cookies / 0 - Allow / 1 - Block
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BlockThirdPartyCookies" /t REG_DWORD /d "1" /f

rem Third-party cookies allowed for URLs

reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge\CookiesAllowedForUrls" /v "1" /t REG_SZ /d "[*.]live.com" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge\CookiesAllowedForUrls" /v "2" /t REG_SZ /d "[*.]googleusercontent.com" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge\CookiesAllowedForUrls" /v "3" /t REG_SZ /d "[*.]microsoft.com" /f

rem Ads setting for sites with intrusive ads / 1 - Allow ads on all sites / 2 - Block ads on sites with intrusive ads. (Default value)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AdsSettingForIntrusiveAdsSites" /t REG_DWORD /d "2" /f

rem File Editing / 2 - BlockFileSystemRead / 3 - AskFileSystemRead
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultFileSystemReadGuardSetting" /t REG_DWORD /d "2" /f

rem File Editing / 2 - BlockFileSystemWrite / 3 - AskFileSystemWrite
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultFileSystemWriteGuardSetting" /t REG_DWORD /d "2" /f

rem Location / 1 - AllowGeolocation / 2 - BlockGeolocation / 3 - AskGeolocation
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultGeolocationSetting" /t REG_DWORD /d "2" /f

rem Notifications / 1 - AllowNotifications / 2 - BlockNotifications / 3 - AskNotifications
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultNotificationsSetting" /t REG_DWORD /d "2" /f

rem Motion or light sensors / 1 - AllowSensors / 2 - BlockSensors
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultSensorsSetting" /t REG_DWORD /d "2" /f

rem USB Devices / 2 - BlockWebUsb / 3 - AskWebUsb
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultWebUsbGuardSetting" /t REG_DWORD /d "2" /f

rem Bluetooth / 2 - BlockWebBluetooth / 3 - AskWebBluetooth
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultWebBluetoothGuardSetting" /t REG_DWORD /d "2" /f

rem ------------------------------------ Microsoft Edge ------------------------------------
rem ...................................... Downloads .......................................

rem Set download directory
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DownloadDirectory" /t REG_SZ /d "E:\Downloads\Browser Downloads" /f

rem ------------------------------------ Microsoft Edge ------------------------------------
rem ..................................... Extensions .......................................

rem 1 - Allow extensions from other stores
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ControlDefaultStateOfAllowExtensionFromOtherStoresSettingEnabled" /t REG_DWORD /d "1" /f

rem ------------------------------------ Microsoft Edge ------------------------------------
rem ...................................... Languages .......................................

rem 1 - Enable spellcheck
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SpellcheckEnabled" /t REG_DWORD /d "1" /f

rem 1 - Offer to translate pages that aren't in a language I read
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "TranslateEnabled" /t REG_DWORD /d "1" /f

rem ------------------------------------ Microsoft Edge ------------------------------------
rem ..................................... New tab page .....................................

rem 1 - Allow Microsoft News content on the new tab page
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageContentEnabled" /t REG_DWORD /d "0" /f

rem 1 - Preload the new tab page for a faster experience
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPagePrerenderEnabled" /t REG_DWORD /d "1" /f

rem ________________________________________________________________________________________
rem 1 - Hide the default top sites from the new tab page
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageHideDefaultTopSites" /t REG_DWORD /d "1" /f

rem 1 - Allow quick links on the new tab page
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageQuickLinksEnabled" /t REG_DWORD /d "0" /f

rem ------------------------------------ Microsoft Edge ------------------------------------
rem ............................ Privacy, search, and services .............................

rem Diagnostic Data / 0 - Off / 1 - RequiredData / 2 - OptionalData
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DiagnosticData" /t REG_DWORD /d "0" /f

rem 1 - Enhance the security state in Microsoft Edge / 0 - Standard mode / 1 - Balanced mode / 2 - Strict mode
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EnhanceSecurityMode" /t REG_DWORD /d "1" /f

rem Search on new tabs uses search box or address bar / redirect - address bar / bing - search box
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageSearchBox" /t REG_SZ /d "redirect" /f

rem 1 - Show me search and site suggestions using my typed characters
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SearchSuggestEnabled" /t REG_DWORD /d "1" /f

rem 1 - Use a web service to help resolve navigation errors
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ResolveNavigationErrorsUseWebService" /t REG_DWORD /d "1" /f

rem 1 - Turn on site safety services to get more info about the sites you visit
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SiteSafetyServicesEnabled" /t REG_DWORD /d "1" /f

rem Tracking prevention / 0 - Off / 1 - Basic / 2 - Balanced / 3 - Strict
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "TrackingPrevention" /t REG_DWORD /d "3" /f

rem Configure "Do Not Track" / 0 -Off / 1 - On
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ConfigureDoNotTrack" /t REG_DWORD /d "0" /f

rem Configure Payment method wuery / 0 -Off / 1 - On
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PaymentMethodQueryEnabled" /t REG_DWORD /d "0" /f

rem 1 - Typosquatting Checker (just sending what you type to MS)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "TyposquattingCheckerEnabled" /t REG_DWORD /d "1" /f

rem 1 - Visual search (sending what you are looking at to MS)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "VisualSearchEnabled" /t REG_DWORD /d "1" /f

rem ________________________________________________________________________________________
rem Enable Microsoft Search in Bing suggestions in the address bar
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AddressBarMicrosoftSearchInBingProviderEnabled" /t REG_DWORD /d "0" /f

rem Allow personalization of ads, Microsoft Edge, search, news and other Microsoft services by sending browsing history, favorites and collections, usage and other browsing data to Microsoft
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f

rem Enable full-tab promotional content
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PromotionalTabsEnabled" /t REG_DWORD /d "0" /f

rem Allow recommendations and promotional notifications from Microsoft Edge
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowRecommendationsEnabled" /t REG_DWORD /d "0" /f

rem Choose whether users can receive customized background images and text, suggestions, notifications, and tips for Microsoft services)
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SpotlightExperiencesAndRecommendationsEnabled" /t REG_DWORD /d "0" /f

rem Use secure DNS (DoH)
rem reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BuiltInDnsClientEnabled" /t REG_DWORD /d "1" /f
rem reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsMode" /t REG_SZ /d "secure" /f
rem reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://dns.nextdns.io/******" /f

rem ------------------------------------ Microsoft Edge ------------------------------------
rem ...................................... Profiles ........................................

rem 1 - Save and fill payment info
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AutofillCreditCardEnabled" /t REG_DWORD /d "1" /f

rem 1 - Let users compare the prices of a product they are looking at, get coupons or rebates from the website they're on
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d "0" /f

rem 1 - Suggest strong passwords
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PasswordGeneratorEnabled" /t REG_DWORD /d "0" /f

rem 1 - Offer to save passwords
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PasswordManagerEnabled" /t REG_DWORD /d "0" /f

rem 1 - Show alerts when passwords are found in an online leak
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PasswordMonitorAllowed" /t REG_DWORD /d "0" /f

rem 1 - Show alerts when passwords are found in an online leak
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PasswordMonitorAllowed" /t REG_DWORD /d "0" /f

rem 1 - Show the "Reveal password" button in password fields
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PasswordRevealEnabled" /t REG_DWORD /d "1" /f

rem 1 - Show Microsoft Rewards experience and notifications
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowMicrosoftRewards" /t REG_DWORD /d "0" /f

rem ------------------------------------ Microsoft Edge ------------------------------------
rem ................................ System and performance ................................

rem 1 - Continue running background apps when Microsoft Edge is closed
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f

rem Efficiency Mode / 0 - AlwaysActive / 1 - NeverActive / 2 - ActiveWhenUnplugged / 3 - ActiveWhenUnpluggedBatteryLow 
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "EfficiencyMode" /t REG_DWORD /d "1" /f

rem 1 - Use hardware acceleration when available
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "1" /f

rem 1 - Save resources with sleeping tabs
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SleepingTabsEnabled" /t REG_DWORD /d "1" /f

rem - Sleeping tabs timeout
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SleepingTabsTimeout" /t REG_DWORD /d "30" /f

rem - Block Sleeping Tabs for URLs
reg add "HKLM\Software\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls" /v "1" /t REG_SZ /d "https://mega.nz/" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls" /v "2" /t REG_SZ /d "https://mega.io/" /f
rem 1 - Startup boost
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem NetworkPrediction / 0 - Always / 1 - WifiOnly / 2 - Never
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NetworkPredictionOptions" /t REG_DWORD /d "0" /f

rem Windows Firewall Block

reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{61112D6C-55F9-4CF0-8764-0A8652197DD2}" /t REG_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=Out|App=E:\Portables\Ccleaner Portable\CCleaner64.exe|Name=Ccleaner|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{6D98561A-44DF-455B-A0D2-7830DA49ACBC}" /t reg_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|App=C:\Program Files\Mozilla Firefox\firefox.exe|Name=Firefox (C:\Program Files\Mozilla Firefox)|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{6D98561A-44DF-455B-A0D2-7830DA49ACBC}" /t reg_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|App=C:\Program Files\Mozilla Firefox\firefox.exe|Name=Firefox (C:\Program Files\Mozilla Firefox)|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{0268C0A7-4729-45D8-B784-A8D1E769D8AB}" /t reg_SZ /d "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Private|App=C:\Program Files\Mozilla Firefox\firefox.exe|Name=Firefox (C:\Program Files\Mozilla Firefox)|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "TCP Query User{1E1E3E97-A917-4E6B-B63A-AC5BD16D9364}C:\program files\qbittorrent\qbittorrent.exe" /t reg_SZ /d "v2.10|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=C:\program files\qbittorrent\qbittorrent.exe|Name=qBittorrent - A Bittorrent Client|Desc=qBittorrent - A Bittorrent Client|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "UDP Query User{55ED4F1F-C1CE-4CEF-AC5D-062E14697285}C:\program files\qbittorrent\qbittorrent.exe" /t reg_SZ /d "v2.10|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|App=C:\program files\qbittorrent\qbittorrent.exe|Name=qBittorrent - A Bittorrent Client|Desc=qBittorrent - A Bittorrent Client|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "TCP Query User{5CEBD803-F9B0-42F2-895F-D23E6CC6AC3D}C:\program files (x86)\epic games\launcher\engine\binaries\win64\epicwebhelper.exe" /t reg_SZ /d "v2.10|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=C:\program files (x86)\epic games\launcher\engine\binaries\win64\epicwebhelper.exe|Name=EpicWebHelper|Desc=EpicWebHelper|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "UDP Query User{2B7467D3-0740-4B61-BCEA-21CCEA654BF5}C:\program files (x86)\epic games\launcher\engine\binaries\win64\epicwebhelper.exe" /t reg_SZ /d "v2.10|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|App=C:\program files (x86)\epic games\launcher\engine\binaries\win64\epicwebhelper.exe|Name=EpicWebHelper|Desc=EpicWebHelper|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "TCP Query User{6350CB95-B319-4EA7-994B-655BFC205599}E:\portables\eagleget protable\eagleget.exe" /t reg_SZ /d "v2.10|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=E:\portables\eagleget protable\eagleget.exe|Name=EagleGet Free Downloader|Desc=EagleGet Free Downloader|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "UDP Query User{DE42227D-83C2-410B-8FB2-B9C05945B830}E:\portables\eagleget protable\eagleget.exe" /t reg_SZ /d "v2.10|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|App=E:\portables\eagleget protable\eagleget.exe|Name=EagleGet Free Downloader|Desc=EagleGet Free Downloader|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "TCP Query User{398FF899-86AD-4A72-90A2-542F98489A12}C:\program files\mozilla firefox\firefox.exe" /t reg_SZ /d "v2.10|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=C:\program files\mozilla firefox\firefox.exe|Name=Firefox|Desc=Firefox|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "UDP Query User{C8F979E6-548A-4316-B347-E3A1D35FADFE}C:\program files\mozilla firefox\firefox.exe" /t reg_SZ /d "v2.10|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|App=C:\program files\mozilla firefox\firefox.exe|Name=Firefox|Desc=Firefox|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "TCP Query User{87406A58-ABF8-4ECA-B157-DE4EFA432355}C:\program files (x86)\microsoft\edge\application\msedge.exe" /t REG_SZ /d "v2.10|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=C:\program files (x86)\microsoft\edge\application\msedge.exe|Name=Microsoft Edge|Desc=Microsoft Edge|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "UDP Query User{D570C1AC-D818-4D07-B0B4-3C6F644B6D37}C:\program files (x86)\microsoft\edge\application\msedge.exe" /t REG_SZ /d "v2.10|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|App=C:\program files (x86)\microsoft\edge\application\msedge.exe|Name=Microsoft Edge|Desc=Microsoft Edge|" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "{33548AFE-75C8-45F2-ABF8-F61BB49AEB7E}" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|App=C:\Program Files\Google\Chrome\Application\chrome.exe|Name=Google Chrome|" /f

rem Microsoft Defender Hash Log, Startup Update, Cloud Protection Level, Cloud Timeout Extend and PUP Protection

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d "50" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "UpdateOnStartUp" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ThreatFileHashLogging" /t REG_DWORD /d "1" /f

rem Remove Windows product key from the registry
slmgr /cpky


rem                            OK                              *It's Over*
