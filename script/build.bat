::============================================================================::
:: This script must be started from its folder ::
::============================================================================::
@ECHO OFF

SET BUILD_DIR=_BUILD_

FOR %%f IN ("%CD%") DO SET LastPathElement=%%~nxf
SET CUR_FOLDER_NAME=%LastPathElement%
IF "%CUR_FOLDER_NAME%" == "script" ( ECHO Welcome ) ELSE (
    ECHO This script must be started from its folder. Press any key to exit.
    EXIT /B 1
)

:: CD to root folder.
CD ..
MKDIR %BUILD_DIR%
MKDIR %BUILD_DIR%\tool

CALL :BuildToolExecutable "Argon2"
IF %ERRORLEVEL% NEQ 0 ( GOTO :BadExit )

ECHO Copying files ...
XCOPY script\start_tool_*.bat %BUILD_DIR%\ /Q

EXIT /B 0

::============================================================================::

:BuildToolExecutable
SET TOOL_NAME=%~1
ECHO Building tool %TOOL_NAME%
CD tool\%TOOL_NAME%\
go build -o ..\..\%BUILD_DIR%\tool\
IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%
CD ..\..\
EXIT /B 0

:BadExit
PAUSE
EXIT /B %ERRORLEVEL%

::============================================================================::
