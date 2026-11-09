#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p out
javac --add-modules jdk.httpserver -d out src/main/java/demo/SecureNotesServer.java
exec java --add-modules jdk.httpserver -cp out demo.SecureNotesServer
