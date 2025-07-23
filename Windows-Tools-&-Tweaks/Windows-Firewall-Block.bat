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