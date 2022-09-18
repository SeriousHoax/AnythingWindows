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
rem reg add "HKLM\Software\Policies\Microsoft\Edge" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://dns.nextdns.io/b95fb1" /f

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
reg add "HKLM\Software\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls\1 = "https://mega.nz/"
reg add "HKLM\Software\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls\2 = "https://mega.io/"

rem 1 - Startup boost
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem NetworkPrediction / 0 - Always / 1 - WifiOnly / 2 - Never
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NetworkPredictionOptions" /t REG_DWORD /d "0" /f