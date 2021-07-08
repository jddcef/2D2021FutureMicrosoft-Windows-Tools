echo off
color 03
title Memory Booster
cls

echo Welcome To Memory Booster!
timeout 2 > nul
cls

EmptyStandbyList.exe workingsets
cls
EmptyStandbyList.exe standbylist
cls

echo RAM Has Been Cleaned! 
timeout 2 > nul
cls

echo Exiting...
timeout 2 > nul
cls

exit

