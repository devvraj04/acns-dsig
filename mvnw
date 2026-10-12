#!/bin/sh
# ----------------------------------------------------------------------------
# Maven Wrapper Startup Script for POSIX systems
# ----------------------------------------------------------------------------
set -e

PRG="$0"
while [ -h "$PRG" ]; do
  ls=`ls -ld "$PRG"`
  link=`expr "$ls" : '.*-> \(.*\)$'`
  if expr "$link" : '/.*' > /dev/null; then
    PRG="$link"
  else
    PRG=`dirname "$PRG"`/"$link"
  fi
done

SAVED="`pwd`"
cd "`dirname \"$PRG\"`" >/dev/null
APP_HOME="`pwd -P`"
cd "$SAVED" >/dev/null

WRAPPER_JAR="$APP_HOME/.mvn/wrapper/maven-wrapper.jar"

if [ -f "$WRAPPER_JAR" ]; then
  exec java -cp "$WRAPPER_JAR" org.apache.maven.wrapper.MavenWrapperMain "$@"
else
  if command -v mvn >/dev/null 2>&1; then
    exec mvn "$@"
  else
    echo "Error: Could not find maven-wrapper.jar or system mvn." >&2
    exit 1
  fi
fi
