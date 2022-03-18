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

rem Access CMD with SYSTEM rights at logon (Win+U)
takeown /s %computername% /u %username% /f "%WINDIR%\System32\utilman.exe"
icacls "%WINDIR%\System32\utilman.exe" /grant:r %username%:F
copy /y %WINDIR%\System32\cmd.exe %WINDIR%\System32\utilman.exe
takeown /s %computername% /u %username% /f "%WINDIR%\System32\sethc.exe"
icacls "%WINDIR%\System32\sethc.exe" /grant:r %username%:F
copy /y %WINDIR%\System32\cmd.exe %WINDIR%\System32\sethc.exe

rem Disable Auto-install subscribed/suggested apps (games like Candy Crush Soda Saga/Minecraft)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t reg_DWORD /d "1" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f

rem winget list
winget uninstall "cortana"
winget uninstall "get help"
winget uninstall "microsoft people"
winget uninstall "microsoft tips"
winget uninstall "windows alarms & clock"
winget uninstall "windows camera"
winget uninstall "windows maps"
winget uninstall "your phone"
winget install --id 9nblggh1zbkw --exact --source msstore --accept-package-agreements --accept-source-agreements

rem https://msdn.microsoft.com/en-us/windows/hardware/commercialize/manufacture/desktop/enable-or-disable-windows-features-using-dism
rem DISM /Online /Get-Features /Format:Table

Dism /Online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2 /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2Root /Quiet /NoRestart
Dism /Online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart

rem ================================ Windows Error Reporting ===============================

rem https://docs.microsoft.com/en-us/windows/win32/wer/wer-settings

rem Disable Microsoft Support Diagnostic Tool MSDT
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t reg_DWORD /d "0" /f

rem Disable System Debugger (Dr. Watson)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t reg_SZ /d "0" /f

rem 1 - Disable Windows Error Reporting (WER)
reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t reg_DWORD /d "1" /f

rem DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t reg_DWORD /d "1" /f

rem 1 - Disable WER sending second-level data
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t reg_DWORD /d "1" /f

rem 1 - Disable WER crash dialogs, popups
reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t reg_DWORD /d "1" /f

rem 1 - Disable WER logging
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t reg_DWORD /d "1" /f

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

rem 1 - Show Sync Provider Notifications in Windows Explorer (ADs)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t reg_DWORD /d "0" /f

rem 1 - Always show more details in copy dialog
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t reg_DWORD /d "1" /f

rem ================================ Windows Optimizations =================================

rem https://channel9.msdn.com/Blogs/Seth-Juarez/Memory-Compression-in-Windows-10-RTM

rem Determines in milliseconds the interval from the time the cursor is pointed at a menu until the menu items are displayed
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t reg_SZ /d "0" /f

rem Mouse Hover Time in milliseconds before Pop-up Display
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t reg_SZ /d "0" /f

rem Enables or disables the retrieval of online tips and help for the Settings app (ADs)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t reg_DWORD /d "0" /f

rem 1 - Disable recent documents history
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t reg_DWORD /d "1" /f

rem 1 - Do not add shares from recently opened documents to the My Network Places folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Norecentdocsnethood" /t reg_DWORD /d "1" /f

rem 0 - Disable configuring the machine at boot-up / 1 - Enable configuring the machine at boot-up / 2 - Enable configuring the machine only if DSC is in pending or current state (Default)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DSCAutomationHostEnabled" /t reg_DWORD /d "0" /f

rem Restricting PowerShell to Constrained Language mode

reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Environment" /v "__PSLockDownPolicy" /t reg_SZ /d "4" /f

rem Disable Customer Experience Improvement (CEIP/SQM - Software Quality Management)
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Messenger\Client" /v "CEIP" /t reg_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t reg_DWORD /d "0" /f

rem 0 - Disable Application Impact Telemetry (AIT)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t reg_DWORD /d "0" /f

rem 0 - Disable Inventory Collector
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t reg_DWORD /d "1" /f

rem 0 - Disable Program Compatibility Assistant
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t reg_DWORD /d "1" /f

rem Disable PerfTrack (tracking of responsiveness events)
reg add "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t reg_DWORD /d "0" /f

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

rem Connected User Experiences and Telemetry
sc config DiagTrack start= disabled

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

rem =================================== Windows Settings ===================================
rem --------------------------------- Bluetooth & Devices ----------------------------------
rem ..................................... Your Phone .......................................

rem 1 - Show me suggestions for using my Android phone with Windows
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Mobility" /v "OptedIn" /t reg_DWORD /d "0" /f

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

rem 1 - Get fun facts, tips, and more from Windows and Cortana on your lock screen (Windows spotlight)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t reg_DWORD /d "0" /f

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
rem .................................... App diagnostic ....................................

rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ........................................ Camera ........................................

rem Allow/Deny - Camera access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t reg_SZ /d "Deny" /f

rem Allow/Deny - Let Apps access your camera
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t reg_SZ /d "Deny" /f

rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ................................ Diagnostics & feedback ................................

rem - Inking And Typing Personalization
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization" /v "Value" /t REG_DWORD /d "0" /f

rem 3 - Send optional diagnostic data / 1 - No
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t reg_DWORD /d "1" /f

rem 1 - Tailored experiences
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t reg_DWORD /d "0" /f

rem Send optional dianostgic data / 0 - Security (Not aplicable on Home/Pro, it resets to Basic) / 1 - Basic / 2 - Enhanced (Hidden) / 3 - Full
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t reg_DWORD /d "0" /f

rem Feedback Frequency - Windows should ask for my feedback: 0 - Never / Removed - Automatically
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t reg_DWORD /d "0" /f

rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ........................................ General ......................................

rem 1 - Let apps show me personalized ads by using my advertising ID
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\AdvertisingInfo" /v "Value" /t reg_DWORD /d "0" /f

rem 0 - Let websites show me locally relevant content by accessing my language list (let browsers access your local language)
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t reg_DWORD /d "1" /f

rem 1 - Show me suggested content in the Settings app
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t reg_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t reg_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ....................................... Location .......................................

rem Allow/Deny - Location services
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t reg_SZ /d "Deny" /f

rem Allow/Deny - Let apps access your location
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t reg_SZ /d "Deny" /f

rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ........................................ Speech ........................................

rem 1 - Help make online speech recognition better
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t reg_DWORD /d "0" /f

rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem .................................. Search permissions ..................................

rem  -  Disable Bing search on start menu
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t reg_DWORD /d "1" /f

rem 1 - Cloud content search
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsAADCloudSearchEnabled" /t reg_DWORD /d "0" /f

rem 1 - Search history on this device
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t reg_DWORD /d "0" /f

rem 1 - Cloud content search
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t reg_DWORD /d "0" /f

rem SafeSearch / 0 - Off / 1 - Moderate - 2 - Strict
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t reg_DWORD /d "0" /f

rem =================================== Windows Settings ===================================
rem ---------------------------------- Privacy & security ----------------------------------
rem ................................... Voice activation ...................................

rem 1 - Let apps access voice activation services
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t reg_DWORD /d "0" /f

rem 1 - Let apps use voice activation when device is locked
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationOnLockScreenEnabled" /t reg_DWORD /d "0" /f

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

rem 1 - Get tips and suggestions when I use Windows
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t reg_DWORD /d "0" /f

rem 1 - Offer suggestions on how I can set up my device
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t reg_DWORD /d "0" /f

rem =================================== Windows Settings ===================================
rem ------------------------------------ Windows Update ------------------------------------
rem ................................... Advanced options ...................................

rem ________________________________________________________________________________________
rem 1 - Disable File History (Creating previous versions of files/Windows Backup)
reg add "HKLM\Software\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t reg_DWORD /d "1" /f

rem 1 - Disable Malicious Software Removal Tool offered via Windows Updates (MRT) + Disable Heartbeat Telemetry
reg add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "HeartbeatTrackingIndex" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "SpyNetReportingLocation" /t reg_MULTI_SZ /d "" /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t reg_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t reg_DWORD /d "1" /f

rem Choose how updates are delivered / 0 - Turns off Delivery Optimization / 1 - Gets or sends updates and apps to PCs on the same NAT only / 2 - Gets or sends updates and apps to PCs on the same local network domain / 3 - Gets or sends updates and apps to PCs on the Internet / 99 - Simple download mode with no peering / 100 - Use BITS instead of Windows Update Delivery Optimization
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t reg_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t reg_DWORD /d "0" /f

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

rem Collect Activity History / 0 - Disabled / 1 - Enabled

reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f

rem Let Windows collect my activities from this PC / 0 - Disabled / 1 - Enabled

reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f

rem Let Windows collect my activities from this PC to the cloud / 0 - Disabled / 1 - Enabled

reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f

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
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "UpdateOnStartUp" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ThreatFileHashLogging" /t REG_DWORD /d "1" /f

rem Remove Windows product key from the registry
slmgr /cpky


rem                            OK                              *It's Over*
