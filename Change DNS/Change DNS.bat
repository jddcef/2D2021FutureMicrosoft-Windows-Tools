@echo off
color 04
title Change DNS Using Batch.

:Primary
netsh
cls
echo Welcome To DNS Changer! Change DNS Using This Batch ONLY!
echo Type "Google" For Google DNS.
echo -----------------------------------
echo Type "clouldflare" For Cloudflare DNS.
echo ---------------------------------------
echo Type "OpenDns" For OpenDNS DNS.
echo -------------------------------------
echo Type "Quad9" For Quad9 DNS.
echo ----------------------------------------
echo Type "Comodo" For Comodo Secure DNS.
echo ----------------------------------------
echo Type "DNS Watch" For DNS Watch DNS.
echo ----------------------------------------
echo Type "Verisign" For Verisign DNS.
echo ----------------------------------------------
echo Type "Opennic" For OpenNIC DNS.
echo -----------------------------------------------
echo Have IPV6? Well, Type "Ipv6" For All IPV6 DNS.
echo ----------------------------------------------
echo Type "exit' to Exit. 
echo -----------------------------------------------
echo For More What is DNS, Go To This Link:https://www.cloudflare.com/en-gb/learning/dns/what-is-dns/
echo ------------------------------------------------------------------------------------------------
echo Or, You Can Check The DNS Speed Link:https://www.dnsperf.com/
echo ------------------------------------------------------------------------------------------------
echo What Would You Like?
set /p a=
if "%a%" == "Google" goto :google
if "%a%" == "cloudflare" goto :cloudflare
if "%a%" == "OpenDns" goto :openDNS
if "%a%" == "Quad9" goto :quad9
if "%a%" == "Comodo" goto :comodo
if "%a%" == "DNS Watch" goto :dnswatch
if "%a%" == "Verisign" goto :verisign
if "%a%" == "Opennic" goto :opennic
if "%a%" == "Ipv6" goto :IPv6
cls

:google
netsh interface ipv4 set dns "Wi-Fi" static 8.8.8.8
netsh interface ipv4 set dns "Wi-Fi" static 8.8.4.4 index=2.
netsh interface ipv4 set dns "Ethernet" static 8.8.8.8
netsh interface ipv4 set dns name=”Ethernet” static 8.8.4.4 index=2
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:cloudflare
netsh interface ipv4 set dns "Wi-Fi" static 1.1.1.1
netsh interface ipv4 set dns "Wi-Fi" static 1.0.0.1 index=2
netsh interface ipv4 set dns name=”Ethernet” static 1.1.1.1
netsh interface ipv4 set dns name=”Ethernet” static 1.0.0.1
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:openDNS
netsh interface ipv4 set dns "Wi-Fi" static 208.67.222.222
netsh interface ipv4 set dns "Wi-Fi" static 208.67.220.220 index=2
netsh interface ipv4 set dns name=”Ethernet” static 208.67.222.222
netsh interface ipv4 set dns name=”Ethernet” static 208.67.220.220 index=2
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:quad9
netsh interface ipv4 set dns "Wi-Fi" static 9.9.9.9 > nul
netsh interface ipv4 set dns "Wi-Fi" static 149.112.112.112 index=2 > nul
netsh interface ipv4 set dns name=”Ethernet” static 9.9.9.9 > nul
netsh interface ipv4 set dns name=”Ethernet” static 149.112.112.112 index=2 > nul
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:comodo
netsh interface ipv4 set dns "Wi-Fi" static 8.26.56.26 > nul
netsh interface ipv4 set dns "Wi-Fi" static 8.20.247.20 index=2 > nul
netsh interface ipv4 set dns name=”Ethernet” static 8.26.56.26 > nul
netsh interface ipv4 set dns name=”Ethernet” static 8.20.247.20 index=2 > nul
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:dnswatch
netsh interface ipv4 set dns "Wi-Fi" static 84.200.69.80 > nul
netsh interface ipv4 set dns "Wi-Fi" static 84.200.70.40 index=2 > nul
netsh interface ipv4 set dns name=”Ethernet” static 84.200.69.80 > nul
netsh interface ipv4 set dns name=”Ethernet” static 84.200.70.40 index=2 > nul
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:verisign
netsh interface ipv4 set dns "Wi-Fi" static 64.6.64.6 > nul
netsh interface ipv4 set dns "Wi-Fi" static 64.6.65.6 index=2 > nul
netsh interface ipv4 set dns name=”Ethernet” static 64.6.64.6 > nul
netsh interface ipv4 set dns name=”Ethernet” static 64.6.65.6 index=2 > nul
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:opennic
netsh interface ipv4 set dns "Wi-Fi" static 192.95.54.3 > nul
netsh interface ipv4 set dns "Wi-Fi" static 192.95.54.1 index=2 > nul
netsh interface ipv4 set dns name=”Ethernet” static 192.95.54.3 > nul
netsh interface ipv4 set dns name=”Ethernet” static 192.95.54.1 index=2 > nul
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:IPv6
echo Type "Google" For Google DNS.
echo -----------------------------------
echo Type "clouldflare" For Cloudflare DNS.
echo ---------------------------------------
echo Type "OpenDns" For OpenDNS DNS.
echo -------------------------------------
echo Type "Quad9" For Quad9 DNS.
echo ----------------------------------------
echo Type "DNS Watch" For DNS Watch DNS.
echo ----------------------------------------
echo Type "Verisign" For Verisign DNS.
echo ----------------------------------------------
echo Type "exit" to Exit. 
echo -----------------------------------------------
echo Type "back ipv4' To Go Back.
echo ---------------------------------------------
echo What Would You Like?
set /p a=
if "%a%" == "Google" goto :google
if "%a%" == "cloudflare" goto :cloudflare
if "%a%" == "OpenDns" goto :openDNS
if "%a%" == "Quad9" goto :quad9
if "%a%" == "Comodo" goto :comodo
if "%a%" == "DNS Watch" goto :dnswatch
if "%a%" == "Verisign" goto :verisign
if "%a%" == "back ipv4" goto :primary
cls

:google
netsh interface ipv6 set dns "Wi-Fi" static 2001:4860:4860::8888  > nul
netsh interface ipv6 set dns "Wi-Fi" static 2001:4860:4860::8844 index=2 > nul
netsh interface ipv6 set dns "Ethernet" static 2001:4860:4860::8888 > nul
netsh interface ipv6 set dns name=”Ethernet” static 2001:4860:4860::8844 index=2 > nul
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:cloudflare
netsh interface ipv6 set dns "Wi-Fi" static 2606:4700:4700::1111 > nul
netsh interface ipv6 set dns "Wi-Fi" static 2606:4700:4700::1001 index=2 > nul
netsh interface ipv6 set dns name=”Ethernet” static 2606:4700:4700::1111 > nul
netsh interface ipv6 set dns name=”Ethernet” static 2606:4700:4700::1001 index=2 > nul
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:openDNS
netsh interface ipv6 set dns "Wi-Fi" static 2620:119:35::35 > nul
netsh interface ipv6 set dns "Wi-Fi" static 2620:119:53::53 index=2 > nul
netsh interface ipv6 set dns name=”Ethernet” static 2620:119:35::35 > nul
netsh interface ipv6 set dns name=”Ethernet” static 2620:119:53::53 index=2 > nul
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:quad9
netsh
netsh interface ipv6 set dns "Wi-Fi" static 2620:fe::fe2620:fe::9 > nul
netsh interface ipv6 set dns name=”Ethernet” static 2620:fe::fe2620:fe::9 > nul
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:dnswatch
netsh interface ipv4 set dns "Wi-Fi" static 2001:1608:10:25::1c04:b12f > nul
netsh interface ipv4 set dns "Wi-Fi" static 2001:1608:10:25::9249:d69b index=2 > nul
netsh interface ipv4 set dns name=”Ethernet” static  2001:1608:10:25::1c04:b12f > nul
netsh interface ipv4 set dns name=”Ethernet” static  2001:1608:10:25::9249:d69b index=2 > nul
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

:verisign
netsh interface ipv4 set dns "Wi-Fi" static 2620:74:1b::1:1 > nul
netsh interface ipv4 set dns "Wi-Fi" static 2620:74:1c::2:2 index=2 > nul
netsh interface ipv4 set dns name=”Ethernet” static 2620:74:1b::1:1 > nul
netsh interface ipv4 set dns name=”Ethernet” static 2620:74:1c::2:2 index=2 > nul
The Operation Succes, Would You Like To Exit? (Yes Or No)
set /p a=
if "%a%" == "Yes" goto :exit
if "%a%" == "No" goto :Primary

