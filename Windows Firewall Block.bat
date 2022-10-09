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
