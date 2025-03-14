# PXEServer quick-setup script
#
# WARNING - This will disable the firewall for this host
# This is tested on a regular workstation with a single NIC and DHCP enabled.
#
# Tasks performed by this script
# 1) Get adapter name via internet gateway
# 2) Enable dual IP on DHCP adapter
# 3) Create new secondary static IP on adapter outside of main subnet on /24
#
# Admin rights are required to change network settings, script will exit if you are not running as Admin or UAC prompt is declined
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}
# THIS MUST MATCH WHAT YOU USE IN PXEServer.ps1 (default 169.168.2.1)
$PXEServerIP = "169.168.2.1"
$route = Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1
$global:gateway = $route.NextHop
$gatewayParts = $global:gateway -split '\.'
$gatewayPrefix = "$($gatewayParts[0]).$($gatewayParts[1]).$($gatewayParts[2])."
$internalIP = (Get-NetIPAddress | Where-Object {
	$_.AddressFamily -eq 'IPv4' -and
	$_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' -and
	$_.IPAddress -like "$gatewayPrefix*"
}).IPAddress

$adapter = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
	$_.InterfaceAlias -match 'Ethernet|Wi-Fi' -and
	$_.IPAddress -like "$gatewayPrefix*"
}).InterfaceAlias
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -eq $adapter -and $_.IPAddress -eq $PXEServerIP } 

# DISABLE Windows Firewall
Set-NetFirewallProfile -Profile ((Get-NetConnectionProfile).NetworkCategory) -Enabled False

# Enable DHCP/Static co-exististence on adapter
netsh interface ipv4 set interface "$adapter" dhcpstaticipcoexistence=enabled | Out-Null

# Add PXEServer static IP to adapter
netsh interface ipv4 add address "$adapter" $PXEServerIP | Out-Null
Write-Host "Windows Firewall is DISABLED on the current profile`nPXEServer static set to $PXEServerIP`n`(match this in the main script - if you didn't change anything you are ready to go as-is`)`n`nPress any key to continue..."
[void][System.Console]::ReadKey($true)