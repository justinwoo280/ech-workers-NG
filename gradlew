#!/bin/sh
# Gradle wrapper script for Unix

APP_NAME="Gradle"
APP_BASE_NAME=$(basename "$0")
DEFAULT_JVM_OPTS='"-Xmx64m" "-Xms64m"'

die() {
    echo "$*"
    exit 1
}

cygwin=false
msys=false
darwin=false
nonstop=false
case "$(uname)" in
    CYGWIN*) cygwin=true ;;
    Darwin*) darwin=true ;;
    MSYS* | MINGW*) msys=true ;;
    NONSTOP*) nonstop=true ;;
esac

CLASSPATH=$APP_HOME/gradle/wrapper/gradle-wrapper.jar

if [ -n "$JAVA_HOME" ]; then
    JAVACMD="$JAVA_HOME/bin/java"
else
    JAVACMD="java"
fi

exec "$JAVACMD" $DEFAULT_JVM_OPTS $JAVA_OPTS $GRADLE_OPTS \
    -classpath "$CLASSPATH" \
    org.gradle.wrapper.GradleWrapperMain "$@"
