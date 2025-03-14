# PXEServer settings quick-removal script
#
# This will RE-ENABLE Windows Firewall for this host
# PXEServer static and DHCP/Static coexisitence will be removed/disabled 
#
# Tasks performed by this script
# 1) Get adapter name via internet gateway
# 2) Remove secondary static IP on adapter
# 3) Disable dual IP on adapter
#
# Admin rights are required to change network settings, script will exit if you are not running as Admin or UAC prompt is declined
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}
# THIS MUST MATCH WHAT HAVE BEEN USING IN PXEServer.ps1 (default 169.168.2.1)
$PXEServerIP = "169.168.2.1"

# Find gateway - this is needed to find adapter
$route = Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1
$global:gateway = $route.NextHop
$gatewayParts = $global:gateway -split '\.'
$gatewayPrefix = "$($gatewayParts[0]).$($gatewayParts[1]).$($gatewayParts[2])."
$internalIP = (Get-NetIPAddress | Where-Object {
	$_.AddressFamily -eq 'IPv4' -and
	$_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' -and
	$_.IPAddress -like "$gatewayPrefix*"
}).IPAddress

# Find current adapter
$adapter = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
	$_.InterfaceAlias -match 'Ethernet|Wi-Fi' -and
	$_.IPAddress -like "$gatewayPrefix*"
}).InterfaceAlias

# REMOVE PXEServer static from adapter
Remove-NetIPAddress -InterfaceAlias "$adapter" -IPAddress $PXEServerIP -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

# DISABLE DHCP/Static co-exististence on adapter
netsh interface ipv4 set interface "$adapter" dhcpstaticipcoexistence=disabled | Out-Null

# ENABLE Windows Firewall
Set-NetFirewallProfile -Profile ((Get-NetConnectionProfile).NetworkCategory) -Enabled True
Write-Host "Firewall Enabled and PXEServerIP removed`n`nPress any key to continue..."
[void][System.Console]::ReadKey($true)