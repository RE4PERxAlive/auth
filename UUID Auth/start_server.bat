@echo off
title Bloody Auth Server
echo ====================================================
echo Starting Bloody Auth System on http://localhost:8080
echo ====================================================
start "" http://localhost:8080
python server.py
pause
