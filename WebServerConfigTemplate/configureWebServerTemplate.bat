

@REM Invokes wsadmin to create the web server defintion

@echo off
@setlocal

call "%~dp0setupCmdLine.bat" %*

set  COMMAND_INVOKED=%0

set  PROFILE_NAME_PARAMETER=
set  WSADMIN_USERID_PARAMETER=
set  WSADMIN_PASSWORD_PARAMETER=
set  IHS_ADMIN_PASSWORD_PARAMETER=

:parse
if "%1"=="-profileName"           goto profile.name
if "%1"=="-user"                  goto wsadmin.user
if "%1"=="-password"              goto wsadmin.password
if "%1"=="-ihsAdminPassword"      goto ihs.admin.password
if "%1"=="-help"                  goto error
if "%1"==""                       goto done
goto error

:profile.name
shift
echo Using the profile %1
set  PROFILE_NAME_PARAMETER= -profileName %1
goto recursive

:wsadmin.user
shift
echo Using WebSphere admin userID %1
set  WSADMIN_USERID_PARAMETER= -user %1
goto recursive

:wsadmin.password
shift
set  WSADMIN_PASSWORD_PARAMETER= -password %1
goto recursive

:ihs.admin.password
shift
set  IHS_ADMIN_PASSWORD_PARAMETER=%1
goto recursive

:recursive
shift
goto parse
goto done

:error
echo.
echo.
echo Usage: %COMMAND_INVOKED%
echo          [-profileName      profile_name]
echo          [-user             WAS_Admin_userID]
echo          [-password         WAS_Admin_password]
echo          [-ihsAdminPassword IHS_Admin_password]
echo          [-help ]
echo.
echo Where:
echo     profileName        is the name of the profile in which
echo                        web server should be created
echo     user               is the WebSphere Administration userID
echo     password           is the WebSphere Administration password
echo     ihsAdminPassword   is the password to access the IHS Adminstration server
echo.
echo Example: 
echo     %COMMAND_INVOKED% -profileName AppSrv01 -user admin -password admin1
echo.
echo.

goto end

:done

wsadmin.bat %PROFILE_NAME_PARAMETER% %WSADMIN_USERID_PARAMETER% %WSADMIN_PASSWORD_PARAMETER% -f "%WAS_HOME%\bin\configureWebserverDefinition.jacl" __WebServerName__ __WebServerType__ "__IHSInstallLocation__"  "__WebServerConfigFile__" __WebServerPortNumber__ MAP_ALL "__IHSPluginInstallLocation__" unmanaged __WebNodeName__  __WebServerHostName__ windows __IhsAdminPort__  __IHSAdmin__ __IHSAdminPassword__ "IBM HTTP Server V8.5" 

:end
@endlocal

