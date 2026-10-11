@REM ----------------------------------------------------------------------------
@REM Maven Start Up Batch script
@REM ----------------------------------------------------------------------------
@IF "%DEBUG%" == "" @ECHO OFF
@SETLOCAL
SET ERROR_CODE=0

@REM Set local scope for the variables with windows NT shell
IF "%OS%"=="Windows_NT" @SETLOCAL

@REM ==== START VALIDATION ====
IF NOT "%JAVA_HOME%" == "" GOTO OkJHome

ECHO.
ECHO Error: JAVA_HOME not found in your environment. >&2
ECHO Please set the JAVA_HOME variable in your environment to match the >&2
ECHO location of your Java installation. >&2
ECHO.
GOTO error

:OkJHome
IF EXIST "%JAVA_HOME%\bin\java.exe" GOTO init

ECHO.
ECHO Error: JAVA_HOME is set to an invalid directory. >&2
ECHO JAVA_HOME = "%JAVA_HOME%" >&2
ECHO Please set the JAVA_HOME variable in your environment to match the >&2
ECHO location of your Java installation. >&2
ECHO.
GOTO error

:init
@REM Decide how to startup maven
SET MAVEN_CMD_LINE_ARGS=%*
SET MAVEN_PROJECTBASEDIR=%~dp0
IF "%MAVEN_PROJECTBASEDIR:~-1%"=="\" SET MAVEN_PROJECTBASEDIR=%MAVEN_PROJECTBASEDIR:~0,-1%

SET WRAPPER_JAR="%MAVEN_PROJECTBASEDIR%\.mvn\wrapper\maven-wrapper.jar"
SET WRAPPER_PROPERTIES="%MAVEN_PROJECTBASEDIR%\.mvn\wrapper\maven-wrapper.properties"

IF EXIST %WRAPPER_JAR% GOTO runJar

@REM Download wrapper jar or delegate to system mvn if present
SET MVN_EXE=
WHERE mvn.cmd >nul 2>nul && SET MVN_EXE=mvn.cmd
IF "%MVN_EXE%" == "" WHERE mvn.bat >nul 2>nul && SET MVN_EXE=mvn.bat
IF "%MVN_EXE%" == "" WHERE mvn >nul 2>nul && SET MVN_EXE=mvn
IF NOT "%MVN_EXE%" == "" (
  CALL %MVN_EXE% %*
  GOTO end
)

ECHO Maven wrapper JAR not found: %WRAPPER_JAR%
ECHO Please install Maven or run with installed maven.
GOTO error

:runJar
"%JAVA_HOME%\bin\java.exe" -Dmaven.multiModuleProjectDirectory="%MAVEN_PROJECTBASEDIR%" -cp %WRAPPER_JAR% org.apache.maven.wrapper.MavenWrapperMain %MAVEN_CMD_LINE_ARGS%
IF ERRORLEVEL 1 GOTO error
GOTO end

:error
SET ERROR_CODE=1

:end
@IF "%OS%"=="Windows_NT" @ENDLOCAL
EXIT /B %ERROR_CODE%
