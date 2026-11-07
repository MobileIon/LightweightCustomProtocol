@echo off
title LCP Minecraft Client Bridge (QUIC Acceleration)
echo =================================================================
echo    LCP Minecraft Client Bridge (Local TCP -> Remote QUIC UDP)
echo                  v1.2.1-FINAL Production
echo =================================================================
echo [Status] Connecting to mc.potatolight.cn over LCP QUIC (UDP 856 / 855)...
echo [Status] Listening locally on 127.0.0.1:25565
echo [Hint] Open Minecraft and connect to "127.0.0.1" (or "127.0.0.1:25565")
echo =================================================================

"%~dp0..\..\bin\lcp-mc-client.exe" -listen=127.0.0.1:25565 -server=mc.potatolight.cn -fallback-ip=49.232.234.137

pause
