@echo off
setlocal
cd /d "%~dp0"
if not exist out mkdir out
javac --add-modules jdk.httpserver -d out src\main\java\demo\SecureNotesServer.java
if errorlevel 1 exit /b %errorlevel%
java --add-modules jdk.httpserver -cp out demo.SecureNotesServer
