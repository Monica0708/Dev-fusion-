@echo off
title PandaHub Backend Server
cd /d "%~dp0backend"
echo Starting PandaHub backend...
node server.js
pause
