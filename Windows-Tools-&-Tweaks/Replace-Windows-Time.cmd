@echo off

rem Windows's built-in time syncing method is often buggy and doesn't work, so the `Windows Time` service is disabled

sc stop w32time >nul 2>&1
sc config w32time start= disabled

rem As an alternative the "Update Time" app by Sordum has been used to sync time - https://www.sordum.org/9203/update-time-v1-3/
rem Downloading the app from my Google Drive and extracting to the Program Files

powershell -Command "Invoke-WebRequest -Uri 'https://drive.google.com/uc?export=download&id=1GdfzfSYZMnRxmyc5TiGEXlTMYVKzYX4b' -OutFile '%TEMP%\UpdateTime.zip'"
powershell -Command "Expand-Archive -Path '%TEMP%\UpdateTime.zip' -DestinationPath 'C:\Program Files' -Force; Remove-Item '%TEMP%\UpdateTime.zip' -Force"

rem Create the Update-Time scheduled task for startup syncing as well as scheduled syncing

powershell -Command "$action = New-ScheduledTaskAction -Execute 'C:\Program Files\UpdateTime\UpdateTime.exe'; $triggerBoot = New-ScheduledTaskTrigger -AtLogOn; $triggerHourly = New-ScheduledTaskTrigger -Once -At (Get-Date); $repeatClass = Get-CimClass -ClassName MSFT_TaskRepetitionPattern -Namespace Root/Microsoft/Windows/TaskScheduler; $repeat = New-CimInstance -CimClass $repeatClass -ClientOnly; $repeat.Interval = 'PT1H'; $repeat.Duration = ''; $repeat.StopAtDurationEnd = $false; $triggerHourly.Repetition = $repeat; $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest; Register-ScheduledTask -TaskName 'Update-Time' -Action $action -Trigger @($triggerBoot, $triggerHourly) -Settings $settings -Principal $principal -Force"

rem Trigger the initial time synchronization

schtasks /Run /TN "Update-Time"

pause
