@ECHO OFF

SET /p PWD=Enter password:

:: CMD has a limit of about 1020 symbols per variable.
::SET /p SALT_B64=Enter salt (as Base64):

tool\Argon2.exe -p=%PWD% -s=?

PAUSE
