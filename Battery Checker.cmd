echo off
color 03
title Battery Checker
cls

powercfg -energy
cls
Start iexplore C:\Windows\System32\energy-report.html
Start chrome.exe C:\Windows\System32\energy-report.html
Start firefox.exe C:\Windows\System32\energy-report.html
cls
exit
