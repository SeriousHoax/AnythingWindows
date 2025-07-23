rem Copy the file into the "Other" folder first. eg: "E:\Thunderbird Portable\Other"

set "CURRENT-PATH=%CD%" & cd..
set "PROGRAM-PATH=%CD%" & cd %CURRENT-PATH%

if exist "%PROGRAM-PATH%\ThunderbirdPortable.exe" goto :SETTINGS
if exist "%CURRENT-PATH%\ThunderbirdPortable.exe" set PROGRAM-PATH=%CURRENT-PATH% & goto :SETTINGS

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:SETTINGS
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

set "PROGRAM-LINK=%CURRENT-PATH%\Thunderbird Portable.lnk"
set "SENDTO-FILE=%CURRENT-PATH%\Thunderbird SendTo.cmd"
set "SENDTO-ICON=%PROGRAM-PATH%\app\appinfo\appicon.ico"
set "CONFIG-FILE=%CURRENT-PATH%\Thunderbird Portable.ini"
set "ROAMING-PATH=C:\Users\%USERLOGON%\AppData\Roaming"

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
: START
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

cls
echo ========================================================================================================================
echo THUNDERBIRD PORTABLE INTEGRATION (RUNNING AS: %RUNAS%)
echo ========================================================================================================================
echo.
echo PROGRAM-PATH : "%PROGRAM-PATH%"
echo CURRENT-PATH : "%CURRENT-PATH%"
echo PROGRAM-LINK : "%PROGRAM-LINK%"
echo SENDTO-FILE  : "%SENDTO-FILE%"
echo SENDTO-ICON  : "%SENDTO-ICON%"
echo CONFIG-FILE : "%CONFIG-FILE%"
echo ROAMING-PATH : "%ROAMING-PATH%"
echo.

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
: CHOICE
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

CHOICE /C YN /N /M "DO YOU WANT TO CONTINUE (Y/N): "

IF %ERRORLEVEL%==1 GOTO :PROCESSING
IF %ERRORLEVEL%==2 EXIT

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
: PROCESSING
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

if not exist "%PROGRAM-PATH%\ThunderbirdPortable.exe" goto :ERROR

cls
echo ========================================================================================================================
echo THUNDERBIRD PORTABLE INTEGRATION PROCESS (RUNNING AS: %RUNAS%)
echo ========================================================================================================================
echo.

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo CREATING CONFIG-FILE...
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

echo [General]>"%CONFIG-FILE%"
echo StartWithLastProfile=^1>>"%CONFIG-FILE%"
echo(>>"%CONFIG-FILE%"
echo [Profile0]>>"%CONFIG-FILE%"
echo Name=Portable>>"%CONFIG-FILE%"
echo IsRelative=^0>>"%CONFIG-FILE%"
echo Path=%PROGRAM-PATH%\Data\profile>>"%CONFIG-FILE%"
echo Default=^1>>"%CONFIG-FILE%"

echo.

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo CREATING SENDTO-FILE...
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

echo @echo off>"%SENDTO-FILE%"
echo if %%1. == . exit>>"%SENDTO-FILE%"
echo set PARAMS=file:///%%1>>"%SENDTO-FILE%"
echo :loop>>"%SENDTO-FILE%"
echo shift>>"%SENDTO-FILE%"
echo if %%1. == . goto send>>"%SENDTO-FILE%"
echo set PARAMS=%%PARAMS%%,file:///%%1>>"%SENDTO-FILE%"
echo goto loop>>"%SENDTO-FILE%"
echo :send>>"%SENDTO-FILE%"
echo start "Thunderbird" "%PROGRAM-PATH%\ThunderbirdPortable.exe" -compose attachment='%%PARAMS%%'>>"%SENDTO-FILE%"
echo.

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo CREATING PROGRAM-LINK...
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

set SCRIPT="%TEMP%\%RANDOM%-%RANDOM%-%RANDOM%-%RANDOM%.vbs"

echo Set oWS = WScript.CreateObject("WScript.Shell")>>%SCRIPT%
echo sLinkFile = "%PROGRAM-LINK%">>%SCRIPT%
echo Set oLink = oWS.CreateShortcut(sLinkFile)>>%SCRIPT%
echo oLink.TargetPath = "%SENDTO-FILE%">>%SCRIPT%
echo oLink.IconLocation = "%SENDTO-ICON%">>%SCRIPT%
echo oLink.Save>>%SCRIPT%

cscript /nologo %SCRIPT%
del %SCRIPT%
echo.

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo CLEANING OLD SENDTO-LINK...
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

del  /Q /F "%ROAMING-PATH%\Microsoft\Windows\SendTo\Thunderbird*.lnk"
echo.

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo COPYING CREATED FILES...
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

echo.
if not exist "%ROAMING-PATH%\Thunderbird" md "%ROAMING-PATH%\Thunderbird"
copy "%CONFIG-FILE%" "%ROAMING-PATH%\Thunderbird\profiles.ini"
copy "%PROGRAM-LINK%" "%ROAMING-PATH%\Microsoft\Windows\SendTo"

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:FINISH
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

echo.
echo ========================================================================================================================
echo FINISH - THE DEFAULT-MAIL-CLIENT MUST BE SET MANUALLY - FIRST IN THUNDERBIRD - THEN IN YOUR WINDOWS-DEFAULT-APPS !
echo ========================================================================================================================
echo.
pause
exit

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:ERROR
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

echo ========================================================================================================================
echo ERROR - MOVE THIS BATCH INTO YOUR THUNDERBIRD-PORTABLE FOLDER OR SUBFOLDER !
echo ========================================================================================================================
echo.
pause
