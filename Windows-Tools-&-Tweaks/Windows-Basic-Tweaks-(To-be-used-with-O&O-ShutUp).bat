::                       1    2    3    4                     *Here We Go*                              

rem - Requesting Administrator privilege for this batch script

rem - BatchGotAdmin
:-------------------------------------
rem  --> Check for permissions
>nul 2>&1 fsutil dirty query %systemdrive%

rem --> If error flag set, we do not have admin.
if %errorlevel% NEQ 0 (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    powershell -Command "Start-Process '%~s0' -Verb RunAs"
    exit /B

:gotAdmin
:--------------------------------------

:: =============================== Windows Optimizations ================================

rem - Disable Fast Startup and Hibernation

powercfg -h off

rem - Disable Reserved Storage (7GB)

Dism /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t reg_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t reg_DWORD /d "0" /f

rem Disables automatic startup of diagnostic, telemetry, and Wi-Fi ETW logging sessions.

reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f

rem - Turn on DEP for all programs and services except those I select

bcdedit /set nx OptOut

rem - 1 - Disable recording NTFS last-access timestamp, To query the current state - fsutil behavior query disablelastaccess

fsutil behavior set disablelastaccess 1

rem - 2 - Increases NTFS memory usage for filesystem metadata/cache; reduces disk I/O at the cost of slightly more RAM / 1 - Default

fsutil behavior set memoryusage 2

rem - 0 - Keeps kernel and driver code in physical RAM instead of paging it to disk; may use more RAM / 1 - Default

reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f

rem - 4 - Disables Windows' NDU component that tracks per-app network usage 

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu" /v Start /t REG_DWORD /d 4 /f

rem - Stops the DPS service first to clear Windows network usage history by deleting the SRU database and then restarts DPS.

sc stop DPS && del /f /s /q /a "%windir%\System32\sru\*" && sc start DPS

:: ================================ Windows Error Reporting ===============================

rem - Disable Microsoft Support Diagnostic Tool MSDT

reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t REG_DWORD /d "0" /f

rem - Disable System Debugger (Dr. Watson)

reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d "0" /f

rem - 1 - Disable Windows Error Reporting (WER)

reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f

rem - DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data

reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f

rem - 1 - Disable WER sending second-level data

reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f

rem - 1 - Disable WER crash dialogs, popups

reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f

rem - 1 - Disable WER logging

reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

rem - Disable Windows Error Reporting Service

sc stop WerSvc >nul 2>&1
sc config WerSvc start= disabled

:: =================================== Windows Explorer ===================================
rem - 2 - Open File Explorer to Quick access / 1 - Open File Explorer to This PC / 3 - Open File Explorer to Downloads

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t reg_DWORD /d "1" /f

rem - 1 - Show recently used folders in Quick Access

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t reg_DWORD /d "0" /f

rem - 1 - Show frequently folders in Quick Access

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t reg_DWORD /d "0" /f

rem - 1 - Show hidden files, folders and drives

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t reg_DWORD /d "1" /f

rem - 0 - Show extensions for known file types

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t reg_DWORD /d "0" /f

rem - 0 - Hide protected operating system files 

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t reg_DWORD /d "0" /f

rem - Remove Home (Quick access) from This PC

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "1" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f

rem - Remove Gallery from Navigation Pane in File Explorer

reg add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f

rem - 1 - Show files from Office.com

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowCloudFilesInQuickAccess" /t REG_DWORD /d "0" /f

rem - 1 - Always show more details in copy dialog

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t reg_DWORD /d "1" /f

rem - Disable 260 character limit for file path

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f

rem - Remove unnecessary files/folders

rd "%USERPROFILE%\Favorites" /s /q
rd "%USERPROFILE%\Links" /s /q

:: =================================== Windows Policies ===================================

rem - Disable Active Desktop

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceActiveDesktopOn" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktop" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktopChanges" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "ff" /f

rem - Enables or disables the retrieval of online tips and help for the Settings app (ADs)

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f

rem - 1 - Disable recent documents history

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "1" /f

rem - 1 - Do not add shares from recently opened documents to the My Network Places folder

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsNetHood" /t REG_DWORD /d "1" /f

rem - Disable SMB 1.0/2.0

reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t reg_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB2" /t reg_DWORD /d "0" /f

rem - Enforce Cert Padding Checks to prevent bypass of digital signatures via malicious padding

reg add "HKLM\Software\Microsoft\Cryptography\Wintrust\Config" /v "EnableCertPaddingCheck" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /v "EnableCertPaddingCheck" /t REG_DWORD /d "1" /f

rem - Prevent modification of batch files while executing

reg add "HKLM\Software\Microsoft\Command Processor" /v "LockBatchFilesWhenInUse" /t REG_DWORD /d 1 /f

:: =============================== Windows Scheduled Tasks ================================

schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable

:: =============================== Windows Services ========================

rem - Connected User Experiences and Telemetry

sc stop DiagTrack >nul 2>&1
sc config DiagTrack start= disabled

rem - Geolocation Service

sc stop lfsvc >nul 2>&1
sc config lfsvc start= disabled

rem - Windows Search

sc stop wsearch >nul 2>&1
sc config wsearch start=disabled

rem - Remote Desktop Services

sc stop TermService >nul 2>&1
sc config TermService start= disabled

rem - Windows Health and Optimized Experiences

sc stop whesvc >nul 2>&1
sc config whesvc start= disabled

rem - Windows Remote Management (WS-Management)

sc stop WinRM >nul 2>&1
sc config WinRM start= disabled

rem - WebClient

sc stop WebClient >nul 2>&1
sc config WebClient start= disabled

:: =================================== Windows Settings ===================================
:: ------------------------------------ Accessibility ------------------------------------
:: ...................................... Keyboard .......................................

rem - Sticky keys / 26 - Disable All / 511 - Default

reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t reg_SZ /d "26" /f

rem - Enable Clipboard history

reg add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t reg_DWORD /d 1 /f

rem - Disable "Use the Print Screen key to open screen capture"

reg add "HKCU\Control Panel\Keyboard" /v PrintScreenKeyForSnippingEnabled /t REG_DWORD /d 0 /f

:: =================================== Windows Settings ===================================
:: --------------------------------- Bluetooth & Devices ----------------------------------
:: ...................................... Autoplay .......................................

rem - 0 - Use Autoplay for all media and devices

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t reg_DWORD /d "1" /f 

rem - Disable AutoPlay and AutoRun

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t reg_DWORD /d "255" /f

rem - 0 - Disable WiFi Sense (shares your WiFi network login with other people)

reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t reg_DWORD /d "0" /f

rem - Setup DNS over HTTPS (DoH) Add Custom Servers

netsh dns add encryption server=94.140.14.14 dohtemplate=https://dns.adguard.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=94.140.15.15 dohtemplate=https://dns.adguard.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.2.42 dohtemplate=https://freedns.controld.com/x-hagezi-proplus autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.10.42 dohtemplate=https://freedns.controld.com/x-hagezi-proplus autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.2.2 dohtemplate=https://freedns.controld.com/p2 autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.10.2 dohtemplate=https://freedns.controld.com/p2 autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.2.4 dohtemplate=https://freedns.controld.com/family autoupgrade=yes udpfallback=no
netsh dns add encryption server=76.76.10.4 dohtemplate=https://freedns.controld.com/family autoupgrade=yes udpfallback=no

:: =================================== Windows Settings ===================================
:: ----------------------------------- Personalization ------------------------------------
:: ..................................... Background .......................................

rem - 60-100% Wallpaper's image quality / 85 - Default

reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t reg_DWORD /d "100" /f

:: =================================== Windows Settings ===================================
:: ----------------------------------- Personalization ------------------------------------
:: ....................................... Colors .........................................

rem - Allow Windows to derive an accent color from the current wallpaper

reg add "HKCU\Control Panel\Desktop" /v "AutoColorization" /t REG_DWORD /d "1" /f

rem - Apply the automatically derived accent color to windows and system UI

reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableWindowColorization" /t REG_DWORD /d "1" /f

rem - Show accent color on Start and taskbar

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t REG_DWORD /d "1" /f

rem - Sets apps (File Explorer, Settings) to Dark Mode

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f

rem - Sets system UI (Taskbar, Start Menu) to Dark Mode

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f

rem - Enable transparency effects

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "1" /f

rem - Completely remove Recommended section from Windows 11 Start Menu (Windows 11 Enterprise only)

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v HideRecommendedSection /t REG_DWORD /d "1" /f


:: =================================== Windows Settings ===================================
:: ----------------------------------- Personalization ------------------------------------
:: ..................................... Lock screen ......................................

rem - 1 - Disable Sign-in screen acrylic (blur) background 

reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t reg_DWORD /d "1" /f

rem - Disable Password Reveal Button

reg add "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f

:: =================================== Windows Settings ===================================
:: ----------------------------------- Personalization ------------------------------------
:: ........................................ Start .........................................

rem - 1 - Show recently opened items in Start, Jump Lists, and File Explorer

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t reg_DWORD /d "0" /f

:: =================================== Windows Settings ===================================
:: ----------------------------------- Personalization ------------------------------------
:: ....................................... Taskbar ........................................

rem - Chat / 0 - Off / 1 - On

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t reg_DWORD /d "0" /f

:: =================================== Windows Settings ===================================
:: ---------------------------------- Privacy & security ----------------------------------
:: ................................ Diagnostics & feedback ................................

rem - Inking And Typing Personalization

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization" /v "Value" /t REG_DWORD /d "0" /f

:: ................................... Remote Assistance ...................................

rem - Remote Settings - Disable Remote Assistance

reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t reg_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t reg_DWORD /d "0" /f

rem - Disable Remote Registry service

sc stop Remoteregistry >nul 2>&1
sc config Remoteregistry start= disabled

reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicitedFullControl" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSAppCompat" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSEnabled" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSUserEnabled" /t reg_DWORD /d "0" /f

:: =================================== Windows Settings ===================================
:: --------------------------------------- System -----------------------------------------
:: .................................... Notifications .....................................

rem - 1 - Show me the Windows welcome experience

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t reg_DWORD /d "0" /f

rem - 1 - Offer suggestions on how I can set up my device

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t reg_DWORD /d "0" /f

rem - 1 - Disable Malicious Software Removal Tool offered via Windows Updates (MRT)

reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t reg_DWORD /d "1" /f

rem - Add "Take Ownership" Option in Files and Folders Context Menu in Windows

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

rem - Add Right Click "Open in Windows Terminal as administrator" Context Menu

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

rem - Show Detailed Information During Startup, Shutdown, Login, and Logout / Enable Verbose or Highly Detailed Status Messages

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f

rem - Disable Microsoft Edge Tabs in Alt+Tab

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "MultiTaskingAltTabFilter" /t REG_DWORD /d "3" /f

rem - Disable Thumbnail Border for Images and Videos

reg add "HKCR\SystemFileAssociations\image" /v "Treatment" /t REG_DWORD /d "0" /f
reg add "HKCR\SystemFileAssociations\video" /v "Treatment" /t REG_DWORD /d "0" /f

rem - Windows Firewall

netsh advfirewall firewall add rule name="CCleaner" dir=out action=block program="E:\Portables\Ccleaner Portable\CCleaner64.exe" enable=yes
netsh advfirewall firewall add rule name="CCleaner" dir=out action=block program="E:\Portables\Ccleaner Portable\x64\CCleanerBugReport.exe" enable=yes
netsh advfirewall firewall add rule name="Microsoft Compatibility Telemetry" dir=out action=block program="C:\Windows\System32\CompatTelRunner.exe" enable=yes
netsh advfirewall firewall add rule name="LocalSend" dir=in action=allow program="E:\Portables\LocalSend\localsend_app.exe" enable=yes
netsh advfirewall firewall add rule name="Tixati Portable" dir=in action=allow program="E:\Portables\Tixati Portable\tixati_Windows64bit.exe" enable=yes

rem - Microsoft Defender PUA Protection, Hash Log, Startup Update, Cloud Protection Level and Cloud Timeout Extend

powershell -Command "Set-MpPreference -PUAProtection Enabled"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d "50" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "UpdateOnStartUp" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ThreatFileHashLogging" /t REG_DWORD /d "1" /f

:: =============================== Windows Time ================================

rem - Set Windows Time to UTC - Prevents messing up system time after booting Linux ISOs

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f

rem - Configure Windows Time for more accurate NTP synchronization since the default config often bugs out and stops syncing time

rem - Configure Cloudflare and Meta NTP server IPs as the NTP providers
w32tm /config /manualpeerlist:"162.159.200.123,0x8 129.134.25.123,0x8 2606:4700:f1::1,0x8 2a03:2880:ff08::123,0x8" /syncfromflags:MANUAL /update

rem - Adaptive polling: 64s minimum, 1024s maximum
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config" /v "MinPollInterval" /t REG_DWORD /d "6" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config" /v "MaxPollInterval" /t REG_DWORD /d "10" /f

rem - Faster phase correction
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config" /v "PhaseCorrectRate" /t REG_DWORD /d "1" /f

rem - Gradual corrections tick every 1s
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config" /v "UpdateInterval" /t REG_DWORD /d "100" /f

rem - Any offset over 1s steps immediately instead of drifting in gradually
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config" /v "MaxAllowedPhaseOffset" /t REG_DWORD /d "1" /f

rem - Fix the default trigger-start behavior, which stops the service on non-domain-joined (workgroup) machines
net stop w32time >nul 2>&1
sc triggerinfo w32time delete
sc config w32time start= auto

rem - Start the service
net start w32time

rem - Initiate time synchronization
w32tm /resync /rediscover

rem - Remove Windows product key from the registry

slmgr /cpky


::                            OK                              *It's Over*
