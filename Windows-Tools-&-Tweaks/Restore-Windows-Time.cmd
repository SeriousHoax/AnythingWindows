@echo off

rem Enable Windows Time service
echo Enabling the w32time service...

net stop w32time >nul 2>&1
w32tm /unregister
w32tm /register
net start w32time
w32tm /resync /force

echo Done.

pause
