# Admin rights are required to create BCD and firewall rules, the script will exit if you are not running as Admin or UAC prompt is declined
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

# Allow Single Instance Only
$AppId = 'PXEServer' # Dont do this ;P, use a GUID instead
$singleInstance = $false
$script:SingleInstanceEvent = New-Object Threading.EventWaitHandle $true,([Threading.EventResetMode]::ManualReset),"Global\$AppId",([ref] $singleInstance)
if (-not $singleInstance){
	$shell = New-Object -ComObject Wscript.Shell
	$shell.Popup("$AppId is already running!",0,'ERROR:',0x0) | Out-Null
	Exit
}

Add-Type -AssemblyName System.Net

# Configuration
$Config = @{
	PXEServerRoot   = "C:\PXE"
	LogFile         = "pxeSession.log"
	PXEServerIP     = "169.168.2.1"
	SubnetMask      = "255.255.255.0"
	StartIP         = 2
	EndIP           = 254
	LeaseTime       = 300
	HttpPort        = 80
	DebugMode       = $false
}

# SecureBoot compatility can be enabled, but provides less NIC support(drivers), if you are having boot issues try leaving SecureBoot Compatibility disabled
# To enable SecureBoot support navigate to the following page: https://knowledge.broadcom.com/external/article/280113/updated-64bit-ipxeefi-ipxe-v1211+-binari.html
# Scroll to the bottom of the page, and click the 64bit_ipxe_efi.zip download button to get a signed copy of ipxe.efi (Thank you Broadcom)
# Extract ipxe.efi from 64bit_ipxe_efi.zip AND RENAME IT TO ==> ipxe2.efi
# Assuming your PXEServer is located at C:\PXE, place the new ipxe2.efi in C:\PXE\NBP\ - if the file exists here SecureBoot compatibility mode will be enabled when the script is launched
#
# This feature will override the PXEServer HttpPort config settings, it will be locked to 4433 - To disable this feature simply remove C:\PXE\NBP\ipxe2.efi and restart the server
#
$SecureBootCompatibility = (Test-Path -Path "$($Config.PXEServerRoot)\NBP\ipxe2.efi")

# Console/Log output
function Write-Log {
	param (
		[string]$Message,
		[ConsoleColor]$Color = "White"
	)
	$timestamp = "[$(Get-Date -Format 'HH:mm:ss')] $Message"
	if ($Config.DebugMode) {
		Write-Host $timestamp -ForegroundColor $Color
	} else {
		if ($Message -match "^\[INFO\]|\[ERROR\]") {
			Write-Host $timestamp -ForegroundColor $Color
		}
	}
	try {
		$logFile = "$($Config.PXEServerRoot)\logs\$($Config.LogFile)"
		if (-not (Test-Path $logFile)) {
			New-Item -Path $logFile -ItemType File -Force | Out-Null
		}
		Add-Content -Path $logFile -Value $timestamp -ErrorAction Stop
	}
	catch {
		Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [ERROR] Failed to write to log file: $_" -ForegroundColor Red
	}
}

Write-Log "[INFO] Initializing..." -Color White

# Log file management
$logDir = "$($Config.PXEServerRoot)\logs"
$logBase = $Config.LogFile
$logFile = "$logDir\$logBase"
$log2File = "$logDir\$($logBase -replace '.log$', '.log2')"

try {
	if (-not (Test-Path $logDir)) {
		New-Item -Path $logDir -ItemType Directory -Force | Out-Null
		Write-Log "[DEBUG] Created log directory: $logDir" -Color Yellow
	}

	# Rotate logs if the main log file exists, keeping only 1 old log
	if (Test-Path $logFile) {
		if (Test-Path $log2File) {
			Remove-Item -Path $log2File -Force -ErrorAction Stop
			Write-Log "[DEBUG] Removed old $log2File" -Color Yellow
		}
		Rename-Item -Path $logFile -NewName $log2File -ErrorAction Stop
		Write-Log "[DEBUG] Renamed previous log to $log2File" -Color Yellow
	}

	New-Item -Path $logFile -ItemType File -Force | Out-Null
	Write-Log "[DEBUG] Started fresh log file at $logFile" -Color Yellow
}
catch {
	Write-Host "[ERROR] Log file management failed: $_" -ForegroundColor Red
	Write-Host "`n`nPress any key to exit..." -ForegroundColor White
	[void][System.Console]::ReadKey($true)
	exit
}

# If SecureBootCompatibility is on these settings are mandatory
if($SecureBootCompatibility){
	$global:UEFIBootfileName = "ipxe2.efi"
	$global:BIOSBootfileName = "undionly2.kpxe"
	$Config.HttpPort = 4433
	try {
$ueficonfig = @"
#!ipxe
kernel http://$($Config.PXEServerIP):4433/NBP/wimboot
initrd http://$($Config.PXEServerIP):4433/boot/BCD BCD
initrd http://$($Config.PXEServerIP):4433/boot/boot.sdi boot.sdi
initrd http://$($Config.PXEServerIP):4433/bootmgr.efi bootmgr.efi
initrd http://$($Config.PXEServerIP):4433/sources/boot.wim boot.wim
boot
"@
		Set-Content -Path "$($Config.PXEServerRoot)\NBP\uefi.cfg" -Value $ueficonfig -Force -ErrorAction Stop
		Write-Log "[DEBUG] Generated boot data at $($Config.PXEServerRoot) with $($Config.PXEServerIP):4433" -Color Yellow
	}
	catch {
		Write-Log "[ERROR] Failed to generate boot data (uefi.cfg): $_" -Color Red
		Write-Host "`n`nPress any key to exit..." -ForegroundColor White
		[void][System.Console]::ReadKey($true)
		exit
	}
} else {
	$global:UEFIBootfileName = "ipxe.efi"
	$global:BIOSBootfileName = "undionly.kpxe"
}

function prepareNetworkSettings {
	$currentNetProfile = (Get-NetConnectionProfile -InterfaceAlias $adapter).NetworkCategory	
	try {
		Write-Log "[INFO] Configuring Firewall" -Color White
		New-NetFirewallRule -DisplayName "PXEServer Services HTTP" -Direction Inbound -Protocol TCP -LocalPort $($Config.HttpPort) -Action Allow -Profile "$currentNetProfile" -Enabled True | Out-Null
		Write-Log "[DEBUG] Firewall rule created: PXEServer Services HTTP (TCP/$($Config.httpPort))" -Color Yellow
		$udpPorts = @(53, 67, 69, 4011)
		New-NetFirewallRule -DisplayName "PXEServer Services DNS/DHCP/TFTP/pDHCP" -Direction Inbound -Protocol UDP -LocalPort $udpPorts -Action Allow -Profile "$currentNetProfile" -Enabled True | Out-Null
		Write-Log "[DEBUG] Firewall rule created: PXEServer Services DNS/DHCP/TFTP/pDHCP (UDP/53,67,69,4011)" -Color Yellow
	} catch {
		Write-Log "[ERROR] Failed to create firewall rules: $_" -Color Red
		Write-Host "`n`nPress any key to exit..." -ForegroundColor White
		[void][System.Console]::ReadKey($true)
	}
	Write-Log "[INFO] Configuring Network Adapter" -Color White
	netsh interface ipv4 set interface "$adapter" dhcpstaticipcoexistence=enabled | Out-Null
	netsh interface ipv4 add address "$adapter" $Config.PXEServerIP $Config.SubnetMask | Out-Null
}

# Check network settings, adjust if needed
$route = Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1
$gateway = $route.NextHop
$gatewayParts = $gateway -split '\.'
$gatewayPrefix = "$($gatewayParts[0]).$($gatewayParts[1]).$($gatewayParts[2])."
$internalIP = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' -and $_.IPAddress -like "$gatewayPrefix*" }).IPAddress
$adapter = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet|Wi-Fi' -and $_.IPAddress -like "$gatewayPrefix*" }).InterfaceAlias
if(!(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -eq $adapter -and $_.IPAddress -eq $($Config.PXEServerIP) })) {
	$needsSetup++
}
if((Get-NetFirewallProfile -Profile (Get-NetConnectionProfile).NetworkCategory).Enabled){
	$needsSetup++
}
$ipAddress = Get-NetIPAddress -InterfaceAlias $adapter -AddressFamily IPv4
$ips = @((Get-NetIPAddress -InterfaceAlias $adapter -AddressFamily IPv4).IPAddress)
if ($ips.Count -le 1) {
	$needsSetup++
}

if($needsSetup){
	prepareNetworkSettings
}

Write-Log "[INFO] Starting PXE Server, please wait..." -Color White

# Make sure a HTTP server isnt already running from an improper shutdown
try {
	Set-Variable ProgressPreference SilentlyContinue
	iwr "http://$($Config.PXEServerIP):$($Config.HttpPort)/shutdown" -ErrorAction SilentlyContinue | Out-Null
	Set-Variable ProgressPreference Continue
	Write-Log "[DEBUG] HTTP Server, stale process found and closed" -Color Yellow
}
catch {
	Write-Log "[DEBUG] HTTP Server IP/Port screened" -Color Yellow
}
# Initialize and create BCD
try {
	$requiredFiles = @(
		"$($Config.PXEServerRoot)\NBP\$global:BIOSBootfileName",
		"$($Config.PXEServerRoot)\NBP\$global:UEFIBootfileName",
		"$($Config.PXEServerRoot)\NBP\wimboot",
		"$($Config.PXEServerRoot)\boot\boot.sdi",
		"$($Config.PXEServerRoot)\bootmgr.exe",
		"$($Config.PXEServerRoot)\bootmgr.efi",
		"$($Config.PXEServerRoot)\sources\boot.wim"
	)
	foreach ($file in $requiredFiles) {
		if (-not (Test-Path $file)) {
			Write-Log "[ERROR] Required file not found: $file." -Color Red
			$missingfiles++
		}
	}
	if($missingfiles){
		Write-Log "[ERROR] Required files missing! Please ensure all files are in place." -Color Red
		Write-Host "`n`nPress any key to exit..." -ForegroundColor White
		[void][System.Console]::ReadKey($true)
		Exit
	}
	$BcdEditExe = "C:\Windows\System32\bcdedit.exe"
	$TargetBCD = "$($Config.PXEServerRoot)\boot\BCD"
	$Timeout = 5
	$Description = "Windows PE"
	$Locale = "en-US"

	Write-Log "[DEBUG] Creating BCD store at $TargetBCD..." -Color Yellow
	Remove-Item $TargetBCD -Force -ErrorAction SilentlyContinue | Out-Null

	& $BcdEditExe /createstore $TargetBCD | Out-Null
	& $BcdEditExe /store $TargetBCD /create "{ramdiskoptions}" | Out-Null
	& $BcdEditExe /store $TargetBCD /set "{ramdiskoptions}" ramdisksdidevice boot | Out-Null
	& $BcdEditExe /store $TargetBCD /set "{ramdiskoptions}" ramdisksdipath "\boot.sdi" | Out-Null
	& $BcdEditExe /store $TargetBCD /create "{bootmgr}" /d "PXE Boot Manager" | Out-Null
	& $BcdEditExe /store $TargetBCD /set "{bootmgr}" device boot | Out-Null
	& $BcdEditExe /store $TargetBCD /set "{bootmgr}" path "\bootmgr.exe" | Out-Null
	& $BcdEditExe /store $TargetBCD /set "{bootmgr}" timeout $Timeout | Out-Null
	& $BcdEditExe /store $TargetBCD /set "{bootmgr}" locale $Locale | Out-Null
	& $BcdEditExe /store $TargetBCD /set "{bootmgr}" nointegritychecks Yes | Out-Null

	$osLoaderOutput = & $BcdEditExe /store $TargetBCD /create /application osloader /d $Description
	$guid = ($osLoaderOutput | Where-Object { $_ -match "{[a-f0-9-]+}" } | ForEach-Object { $matches[0] })
	if (-not $guid) { throw "Failed to extract GUID from osloader creation." }

	& $BcdEditExe /store $TargetBCD /set $guid device "ramdisk=`[boot`]\boot.wim,{ramdiskoptions}" | Out-Null
	& $BcdEditExe /store $TargetBCD /set $guid osdevice "ramdisk=`[boot`]\boot.wim,{ramdiskoptions}" | Out-Null
	& $BcdEditExe /store $TargetBCD /set $guid path "\windows\system32\winload.exe" | Out-Null
	& $BcdEditExe /store $TargetBCD /set $guid systemroot "\windows" | Out-Null
	& $BcdEditExe /store $TargetBCD /set $guid detecthal Yes | Out-Null
	& $BcdEditExe /store $TargetBCD /set $guid winpe Yes | Out-Null
	& $BcdEditExe /store $TargetBCD /set $guid locale $Locale | Out-Null
	& $BcdEditExe /store $TargetBCD /set $guid nointegritychecks Yes | Out-Null
	& $BcdEditExe /store $TargetBCD /set $guid testsigning Yes | Out-Null
	& $BcdEditExe /store $TargetBCD /set "{bootmgr}" default $guid | Out-Null
	& $BcdEditExe /store $TargetBCD /set "{bootmgr}" displayorder $guid | Out-Null
	& $BcdEditExe /store $TargetBCD /set "{default}" bootmenupolicy legacy | Out-Null
	Write-Log "[DEBUG] BCD store created successfully at $TargetBCD" -Color Yellow
}
catch {
	Write-Log "[ERROR] BCD creation failed: $_" -Color Red
	Write-Host "`n`nPress any key to exit..." -ForegroundColor White
	[void][System.Console]::ReadKey($true)
	exit
}

# Initialize sockets
try {
	Write-Log "[DEBUG] Initializing DHCP socket on $($Config.PXEServerIP):67" -Color Yellow
	$dhcpSocket = New-Object System.Net.Sockets.UdpClient
	$dhcpSocket.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
	$dhcpSocket.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Config.PXEServerIP), 67))
	Write-Log "[DEBUG] DHCP socket bound, LocalEndpoint: $($dhcpSocket.Client.LocalEndPoint)" -Color Yellow

	Write-Log "[DEBUG] Initializing TFTP socket on $($Config.PXEServerIP):69" -Color Yellow
	$tftpSocket = New-Object System.Net.Sockets.UdpClient
	$tftpSocket.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
	$tftpSocket.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Config.PXEServerIP), 69))
	Write-Log "[DEBUG] TFTP socket bound, LocalEndpoint: $($tftpSocket.Client.LocalEndPoint)" -Color Yellow

	$proxyDhcpSocket = $null
	try {
		$proxyDhcpSocket = New-Object System.Net.Sockets.UdpClient
		$proxyDhcpSocket.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
		$proxyDhcpSocket.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Config.PXEServerIP), 4011))
		Write-Log "[DEBUG] ProxyDHCP socket bound, LocalEndpoint: $($proxyDhcpSocket.Client.LocalEndPoint)" -Color Yellow
	}
	catch {
		Write-Log "[ERROR] Failed to bind ProxyDHCP socket on port 4011: $_" -Color Red
	}

	Write-Log "[DEBUG] Initializing DNS socket on $($Config.PXEServerIP):53" -Color Yellow
	$dnsSocket = New-Object System.Net.Sockets.UdpClient
	$dnsSocket.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
	$dnsSocket.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Config.PXEServerIP), 53))
	$dnsSocket.Client.ReceiveTimeout = 2000
	Write-Log "[DEBUG] DNS server initialized on $($Config.PXEServerIP):53" -Color Yellow
}
catch {
	Write-Log "[ERROR] Failed to initialize sockets: $_" -Color Red
	Write-Host "`n`nPress any key to exit..." -ForegroundColor White
	[void][System.Console]::ReadKey($true)
	exit
}

# Generate client IP pool
if (-not ([int]::TryParse($Config.StartIP, [ref]$null)) -or -not ([int]::TryParse($Config.EndIP, [ref]$null))) {
	Write-Log "[ERROR] StartIP and EndIP must be integers, check config!" -Color Red
	Write-Host "`n`nPress any key to exit..." -ForegroundColor White
	[void][System.Console]::ReadKey($true)
    Exit
}
$startIPcheck = [int]$Config.StartIP
$endIPcheck = [int]$Config.EndIP
if ($startIPcheck -lt 0 -or $startIPcheck -gt 254 -or $endIPcheck -lt 0 -or $endIPcheck -gt 254) {
	Write-Log "[ERROR] StartIP and EndIP must be between 0 and 254, check config!" -Color Red
	Write-Host "`n`nPress any key to exit..." -ForegroundColor White
	[void][System.Console]::ReadKey($true)
    Exit
}
if ($startIPcheck -gt $endIPcheck) {
    $Config.StartIP, $Config.EndIP = @($Config.EndIP, $Config.StartIP)
    $startIPcheck = [int]$Config.StartIP
    $endIPcheck = [int]$Config.EndIP
}
$serverSubnet = [System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes()
$serverFourthOctet = [int]$serverSubnet[3]
if ($serverFourthOctet -ge $startIPcheck -and $serverFourthOctet -le $endIPcheck) {
    Write-Log "[ERROR] PXEServerIP ($($Config.PXEServerIP)) cannot be within the client IP range ($($Config.StartIP) to $($Config.EndIP)), check config!" -Color Red
	Write-Host "`n`nPress any key to exit..." -ForegroundColor White
    [void][System.Console]::ReadKey($true)
    Exit
}
$ipPool = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
for ($i = $Config.StartIP; $i -le $Config.EndIP; $i++) {
	$ipPool.Add("$($serverSubnet[0..2] -join '.').$i")
}
$ipAssignments = [System.Collections.Concurrent.ConcurrentDictionary[string,string]]::new()
$processedTransactionIDs = [System.Collections.Concurrent.ConcurrentBag[string]]::new()

# TFTP
function Send-TFTPFile {
	param (
		[System.Net.IPEndPoint]$ClientEndpoint,
		[string]$FilePath,
		[int]$BlockSize = 512,
		[int]$TimeoutMs = 2000
	)
	try {
		if (-not $FilePath -or -not (Test-Path $FilePath)) {
			Write-Log "[ERROR] File not found or null: $FilePath (TFTP Error 1)" -Color Red
			$errorPacket = [byte[]](0,5, 0,1) + [System.Text.Encoding]::ASCII.GetBytes("File not found") + [byte]0
			$tftpSocket.Send($errorPacket, $errorPacket.Length, $ClientEndpoint) | Out-Null
			return
		}
		if (-not $FilePath.StartsWith($Config.PXEServerRoot)) {
			Write-Log "[ERROR] Access denied: $FilePath outside TFTP root (TFTP Error 2)" -Color Red
			$errorPacket = [byte[]](0,5, 0,2) + [System.Text.Encoding]::ASCII.GetBytes("Access violation") + [byte]0
			$tftpSocket.Send($errorPacket, $errorPacket.Length, $ClientEndpoint) | Out-Null
			return
		}

		$fileStream = [System.IO.File]::OpenRead($FilePath)
		$blockNumber = 1
		$buffer = New-Object byte[] $BlockSize
		$maxRetries = 5
		$timeout = $TimeoutMs

		Write-Log "[DEBUG] Starting TFTP transfer to $($ClientEndpoint.Address):$($ClientEndpoint.Port) for $FilePath" -Color Yellow

		while (($bytesRead = $fileStream.Read($buffer, 0, $BlockSize)) -gt 0) {
			$blockBytes = [BitConverter]::GetBytes([uint16]$blockNumber)
			[array]::Reverse($blockBytes)
			$dataPacket = [byte[]](0,3) + $blockBytes + $buffer[0..($bytesRead - 1)]
			$retryCount = 0
			$ackReceived = $false

			while ($retryCount -lt $maxRetries -and -not $ackReceived) {
				$tftpSocket.Send($dataPacket, $dataPacket.Length, $ClientEndpoint) | Out-Null
				if ($Config.DebugMode) { 
					Write-Log "[DEBUG] Sent block $blockNumber ($bytesRead bytes) to $($ClientEndpoint.Address):$($ClientEndpoint.Port), Retry $retryCount" -Color Yellow
				}
				$tftpSocket.Client.ReceiveTimeout = $timeout
				$ackResult = Receive-TFTPPacket
				$ackBytes = $ackResult.Data
				$ackEndpoint = $ackResult.Endpoint

				if ($ackBytes -and $ackBytes.Length -ge 4 -and $ackBytes[0] -eq 0 -and $ackBytes[1] -eq 4) {
					$receivedBlockNum = ($ackBytes[2] * 256) + $ackBytes[3]
					if ($receivedBlockNum -eq $blockNumber) {
						$ackReceived = $true
					}
				}
				elseif ($ackBytes -and $ackBytes[0] -eq 0 -and $ackBytes[1] -eq 5) {
					$errorCode = [BitConverter]::ToUInt16($ackBytes[2..3], 0)
					$errorMsg = [System.Text.Encoding]::ASCII.GetString($ackBytes[4..($ackBytes.Length - 2)])
					Write-Log "[ERROR] Client error: $errorMsg (Code: $errorCode)" -Color Red
					break
				}
				else {
					$retryCount++
					if ($retryCount -lt $maxRetries) { Start-Sleep -Milliseconds $timeout }
				}
			}

			if (-not $ackReceived) {
				Write-Log "[ERROR] Failed to transfer block $blockNumber after $maxRetries retries" -Color Red
				break
			}
			$blockNumber++
		}
		if ($bytesRead -eq 0) {
			$tftpfileName = Split-Path $FilePath -Leaf
			if ($tftpfileName -like "undionly*") {
				Write-Log "[INFO] $($ClientEndpoint.Address) received chainloader for BIOS mode" -Color Green
			}
			elseif ($tftpfileName -like "ipxe*") {
				Write-Log "[INFO] $($ClientEndpoint.Address) received chainloader for UEFI mode" -Color Green
			}
			else {
				Write-Log "[INFO] TFTP transfer completed for $tftpfileName to $($ClientEndpoint.Address):$($ClientEndpoint.Port)" -Color Yellow
			}
		}
	}
	catch {
		Write-Log "[ERROR] TFTP transfer failed: $_" -Color Red
	}
	finally {
		if ($fileStream) { $fileStream.Close() }
	}
}

function Receive-TFTPPacket {
	try {
		$endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
		$data = $tftpSocket.Receive([ref]$endpoint)
		if ($data[0] -eq 0 -and $data[1] -eq 1) {
			$nullTermIndexes = [System.Collections.ArrayList]::new()
			for ($i = 2; $i -lt $data.Length; $i++) {
				if ($data[$i] -eq 0) { $nullTermIndexes.Add($i) }
			}
			if ($nullTermIndexes.Count -lt 2) {
				Write-Log "[ERROR] Malformed RRQ packet" -Color Red
				return [PSCustomObject]@{ Data = $null; Endpoint = $null; Filename = $null; Mode = $null; Options = $null }
			}
			$filename = [System.Text.Encoding]::ASCII.GetString($data[2..($nullTermIndexes[0] - 1)])
			$mode = [System.Text.Encoding]::ASCII.GetString($data[($nullTermIndexes[0] + 1)..($nullTermIndexes[1] - 1)]).ToLower()
			$options = @{}
			for ($i = 1; $i -lt $nullTermIndexes.Count - 1; $i += 2) {
				$key = [System.Text.Encoding]::ASCII.GetString($data[($nullTermIndexes[$i] + 1)..($nullTermIndexes[$i + 1] - 1)]).ToLower()
				$value = [System.Text.Encoding]::ASCII.GetString($data[($nullTermIndexes[$i + 1] + 1)..($nullTermIndexes[$i + 2] - 1)])
				$options[$key] = $value
			}
			return [PSCustomObject]@{ Data = $data; Endpoint = $endpoint; Filename = $filename; Mode = $mode; Options = $options }
		}
		return [PSCustomObject]@{ Data = $data; Endpoint = $endpoint; Filename = $null; Mode = $null; Options = $null }
	}
	catch {
		Write-Log "[DEBUG] TFTP receive error: $_" -Color Yellow
		return [PSCustomObject]@{ Data = $null; Endpoint = $null; Filename = $null; Mode = $null; Options = $null }
	}
}

# DHCP/ProxyDHCP
function Send-ProxyDHCPOffer {
	param (
		[System.Net.IPEndPoint]$ClientEndpoint,
		[string]$AssignedIP = "0.0.0.0",
		[byte[]]$ClientMAC,
		[byte[]]$TransactionID,
		[bool]$IsUEFI = $false
	)
	try {
		$bootfileName = if ($IsUEFI) { $global:UEFIBootfileName } else { $global:BIOSBootfileName }

		$offer = [byte[]]::new(400)
		$offer[0] = 2
		$offer[1] = 1
		$offer[2] = 6
		$offer[3] = 0
		[Array]::Copy($TransactionID, 0, $offer, 4, 4)
		$offer[8] = 0x00
		[Array]::Copy([System.Net.IPAddress]::Parse("0.0.0.0").GetAddressBytes(), 0, $offer, 16, 4)
		[Array]::Copy([System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes(), 0, $offer, 20, 4)
		[Array]::Copy($ClientMAC, 0, $offer, 28, 6)

		$bootfileBytes = [System.Text.Encoding]::ASCII.GetBytes($bootfileName)
		$options = [byte[]]@(0x63, 0x82, 0x53, 0x63, 53, 1, 2, 54, 4) + [System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes() +
				   [byte[]](66, 4) + [System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes() +
				   [byte[]](67, $bootfileBytes.Length) + $bootfileBytes +
				   [byte[]](60, 9, 80, 88, 69, 67, 108, 105, 101, 110, 116)
		if ($IsUEFI) {
			$options += [byte[]](93, 2, 0, 7)
			$options += [byte[]](94, 3, 3, 16, 0)
		}
		$options += [byte]255
		[Array]::Copy($options, 0, $offer, 236, $options.Length)

		$targetEndpoint = if ($AssignedIP -eq "0.0.0.0") {
			New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Broadcast, 68)
		} else {
			New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($AssignedIP), 4011)
		}
		if ($proxyDhcpSocket) {
			Start-Sleep -Seconds 1
			$proxyDhcpSocket.Send($offer, $offer.Length, $targetEndpoint) | Out-Null
			Write-Log "[DEBUG] ProxyDHCP OFFER sent to $($targetEndpoint.Address):$($targetEndpoint.Port), TID $([BitConverter]::ToString($TransactionID).Replace('-',''))" -Color Yellow
		}
	}
	catch {
		Write-Log "[ERROR] ProxyDHCP Offer Error: $_" -Color Red
	}
}

function Send-DHCPOffer {
	param (
		[System.Net.IPEndPoint]$ClientEndpoint,
		[string]$AssignedIP,
		[byte[]]$ClientMAC,
		[byte[]]$TransactionID,
		[bool]$IsUEFI = $false
	)
	try {
		$bootfileName = if ($IsUEFI) { $global:UEFIBootfileName } else { $global:BIOSBootfileName }

		$offer = [byte[]]::new(516)
		$offer[0] = 2
		$offer[1] = 1
		$offer[2] = 6
		$offer[3] = 0
		[Array]::Copy($TransactionID, 0, $offer, 4, 4)
		$offer[8] = 0x80
		[Array]::Copy([System.Net.IPAddress]::Parse($AssignedIP).GetAddressBytes(), 0, $offer, 16, 4)
		[Array]::Copy([System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes(), 0, $offer, 20, 4)
		[Array]::Copy($ClientMAC, 0, $offer, 28, 6)

		$bootfileBytes = [System.Text.Encoding]::ASCII.GetBytes($bootfileName)
		$pxeServerBytes = [System.Text.Encoding]::ASCII.GetBytes("PXEServer")
		$options = [byte[]]@(0x63, 0x82, 0x53, 0x63, 53, 1, 2, 1, 4) + [System.Net.IPAddress]::Parse($Config.SubnetMask).GetAddressBytes() +
				   [byte[]](3, 4) + [System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes() +
				   [byte[]](6, 4) + [System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes() +
				   [byte[]](51, 4) + [BitConverter]::GetBytes([uint32]$Config.LeaseTime)[3,2,1,0] +
				   [byte[]](54, 4) + [System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes() +
				   [byte[]](200, $pxeServerBytes.Length) + $pxeServerBytes +
				   [byte[]](66, 4) + [System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes() +
				   [byte[]](67, $bootfileBytes.Length) + $bootfileBytes
		if ($IsUEFI) {
			$options += [byte[]](93, 2, 0, 7)
		}
		$options += [byte]255
		[Array]::Copy($options, 0, $offer, 236, $options.Length)

		$broadcast = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Broadcast, 68)
		$bytesSent = $dhcpSocket.Send($offer, $offer.Length, $broadcast)
		Write-Log "[DEBUG] Sent DHCP OFFER to $AssignedIP with bootfile $bootfileName for $(if ($IsUEFI) {'UEFI'} else {'BIOS'}) client, bytes sent: $bytesSent" -Color Yellow
	}
	catch {
		Write-Log "[ERROR] DHCP Offer Error: $_" -Color Red
	}
}

function Send-DHCPAck {
	param (
		[System.Net.IPEndPoint]$ClientEndpoint,
		[string]$AssignedIP,
		[byte[]]$ClientMAC,
		[byte[]]$TransactionID,
		[bool]$IsUEFI = $false
	)
	try {
		$bootfileName = if ($IsUEFI) { $global:UEFIBootfileName } else { $global:BIOSBootfileName }
		$ack = [byte[]]::new(516)
		$ack[0] = 2
		$ack[1] = 1
		$ack[2] = 6
		$ack[3] = 0
		[Array]::Copy($TransactionID, 0, $ack, 4, 4)
		$ack[8] = 0x80
		[Array]::Copy([System.Net.IPAddress]::Parse($AssignedIP).GetAddressBytes(), 0, $ack, 16, 4)
		[Array]::Copy([System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes(), 0, $ack, 20, 4)
		[Array]::Copy($ClientMAC, 0, $ack, 28, 6)
		$bootfileBytes = [System.Text.Encoding]::ASCII.GetBytes($bootfileName)
		$pxeServerBytes = [System.Text.Encoding]::ASCII.GetBytes("PXEServer")
		$options = [byte[]]@(0x63, 0x82, 0x53, 0x63, 53, 1, 5, 1, 4) + [System.Net.IPAddress]::Parse($Config.SubnetMask).GetAddressBytes() +
				   [byte[]](3, 4) + [System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes() +
				   [byte[]](6, 4) + [System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes() +
				   [byte[]](51, 4) + [BitConverter]::GetBytes([uint32]$Config.LeaseTime)[3,2,1,0] +
				   [byte[]](54, 4) + [System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes() +
				   [byte[]](200, $pxeServerBytes.Length) + $pxeServerBytes +
				   [byte[]](66, 4) + [System.Net.IPAddress]::Parse($Config.PXEServerIP).GetAddressBytes() +
				   [byte[]](67, $bootfileBytes.Length) + $bootfileBytes +
				   [byte[]](60, 9, 80, 88, 69, 67, 108, 105, 101, 110, 116)
		if ($IsUEFI) {
			$options += [byte[]](93, 2, 0, 7)
		}
		$options += [byte]255
		[Array]::Copy($options, 0, $ack, 236, $options.Length)
		$broadcast = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Broadcast, 68)
		$bytesSent = $dhcpSocket.Send($ack, $ack.Length, $broadcast)
		Write-Log "[DEBUG] Sent DHCP ACK to $AssignedIP with bootfile $bootfileName for $(if ($IsUEFI) {'UEFI'} else {'BIOS'}) client, bytes sent: $bytesSent" -Color Yellow
	}
	catch {
		Write-Log "[ERROR] DHCP ACK Error: $_" -Color Red
	}
}

# DNS
function Handle-DNSQuery {
	param ([System.Net.IPEndPoint]$ClientEndpoint, [byte[]]$Query)

	Write-Log "[DEBUG] DNS query from $($ClientEndpoint.Address):$($ClientEndpoint.Port), length: $($Query.Length)" -Color Yellow
	try {
		if ($Query.Length -lt 12) {
			Write-Log "[DEBUG] Query too short, sending FORMERR" -Color Yellow
			Send-DNSResponse -ClientEndpoint $ClientEndpoint -TransactionID $Query[0..1] -RCode 1
			return
		}

		$transactionID = $Query[0..1]
		$questions = ($Query[4] -shl 8) + $Query[5]
		if ($questions -eq 0) {
			Write-Log "[DEBUG] No questions, sending FORMERR" -Color Yellow
			Send-DNSResponse -ClientEndpoint $ClientEndpoint -TransactionID $transactionID -RCode 1
			return
		}

		$pos = 12
		$qnameParts = @()
		$maxPos = $Query.Length - 4
		while ($pos -lt $maxPos -and $Query[$pos] -ne 0) {
			$len = $Query[$pos]
			if ($pos + $len + 1 -gt $maxPos) {
				Write-Log "[DEBUG] Malformed QNAME, sending FORMERR" -Color Yellow
				Send-DNSResponse -ClientEndpoint $ClientEndpoint -TransactionID $transactionID -RCode 1
				return
			}
			$qnameParts += [System.Text.Encoding]::ASCII.GetString($Query[($pos + 1)..($pos + $len)])
			$pos += $len + 1
		}
		if ($pos + 4 -gt $Query.Length) {
			Write-Log "[DEBUG] No QTYPE/QCLASS, sending FORMERR" -Color Yellow
			Send-DNSResponse -ClientEndpoint $ClientEndpoint -TransactionID $transactionID -RCode 1
			return
		}

		$qname = $qnameParts -join "."
		$qtype = ($Query[$pos + 1] -shl 8) + $Query[$pos + 2]
		$qclass = ($Query[$pos + 3] -shl 8) + $Query[$pos + 4]
		Write-Log "[DEBUG] QNAME: $qname, QTYPE: $qtype, QCLASS: $qclass" -Color Yellow

		if ($qname -ne "pxeserver.local") {
			Write-Log "[DEBUG] Not pxeserver.local, sending NXDOMAIN" -Color Yellow
			Send-DNSResponse -ClientEndpoint $ClientEndpoint -TransactionID $transactionID -RCode 3
			return
		}
		if ($qtype -ne 1 -or $qclass -ne 1) {
			Write-Log "[DEBUG] Unsupported QTYPE/QCLASS, sending NOTIMP" -Color Yellow
			Send-DNSResponse -ClientEndpoint $ClientEndpoint -TransactionID $transactionID -RCode 4
			return
		}

		Write-Log "[DEBUG] Responding with $($Config.PXEServerIP)" -Color Yellow
		Send-DNSResponse -ClientEndpoint $ClientEndpoint -TransactionID $transactionID -Query $Query -AnswerIP $Config.PXEServerIP
	}
	catch {
		Write-Log "[ERROR] DNS handling failed: $_, sending SERVFAIL" -Color Red
		Send-DNSResponse -ClientEndpoint $ClientEndpoint -TransactionID $transactionID -RCode 2
	}
}

function Send-DNSResponse {
	param (
		[System.Net.IPEndPoint]$ClientEndpoint,
		[byte[]]$TransactionID,
		[byte]$RCode = 0,
		[byte[]]$Query = $null,
		[string]$AnswerIP = $null
	)

	$response = [byte[]]::new(512)
	[Array]::Copy($TransactionID, 0, $response, 0, 2)
	$response[2] = 0x84
	$response[3] = $RCode
	$response[4] = 0x00
	$response[5] = 0x00
	$response[6] = 0x00
	$response[7] = 0x00
	$response[8] = 0x00
	$response[9] = 0x00
	$response[10] = 0x00
	$response[11] = 0x00

	$pos = 12
	if ($Query -and $AnswerIP) {
		$response[5] = 0x01
		$response[7] = 0x01
		$questionEnd = 12
		while ($Query[$questionEnd] -ne 0) { $questionEnd += $Query[$questionEnd] + 1 }
		$questionLength = $questionEnd + 5 - 12
		[Array]::Copy($Query, 12, $response, 12, $questionLength)
		$pos += $questionLength

		$response[$pos] = 0xc0
		$response[$pos + 1] = 0x0c
		$response[$pos + 2] = 0x00
		$response[$pos + 3] = 0x01
		$response[$pos + 4] = 0x00
		$response[$pos + 5] = 0x01
		$response[$pos + 6] = 0x00
		$response[$pos + 7] = 0x00
		$response[$pos + 8] = 0x01
		$response[$pos + 9] = 0x2c
		$response[$pos + 10] = 0x00
		$response[$pos + 11] = 0x04
		[Array]::Copy([System.Net.IPAddress]::Parse($AnswerIP).GetAddressBytes(), 0, $response, $pos + 12, 4)
		$pos += 16
	}

	$bytesSent = $dnsSocket.Send($response, $pos, $ClientEndpoint)
	Write-Log "[DEBUG] Sent response ($bytesSent bytes), RCODE: $RCode" -Color Yellow
}

# HTTP Server ScriptBlock
$httpScriptBlock = {
	param($Config)

	Add-Type -AssemblyName System.Net

	function Write-Log {
		param ([string]$Message, [ConsoleColor]$Color = "White")
		$timestamp = "[$(Get-Date -Format 'HH:mm:ss')] $Message"
		if ($Config.DebugMode) {
			Write-Host $timestamp -ForegroundColor $Color
		} else {
			if ($Message -match "^\[INFO\]|\[ERROR\]") {
				Write-Host $timestamp -ForegroundColor $Color
			}
		}
		try {
			$logFile = "$($Config.PXEServerRoot)\logs\$($Config.LogFile)"
			if (-not (Test-Path $logFile)) {
				New-Item -Path $logFile -ItemType File -Force | Out-Null
			}
			Add-Content -Path $logFile -Value $timestamp -ErrorAction Stop
		}
		catch {
			Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [ERROR] Failed to write to log file: $_" -Color Red
		}
	}

	try {
		$listener = New-Object System.Net.HttpListener
		$listener.Prefixes.Add("http://$($Config['PXEServerIP']):$($Config['HttpPort'])/")
		$listener.Start()
		Write-Log "[DEBUG] HTTP server started on http://$($Config['PXEServerIP']):$($Config['HttpPort'])/" -Color Yellow
	}
	catch {
		Write-Log "[ERROR] Failed to start HTTP server: $_" -Color Red
		return
	}

	try {
		while ($true) {
			Write-Log "[DEBUG] Waiting for HTTP request..." -Color Yellow
			$context = $listener.GetContext()
			$request = $context.Request
			$response = $context.Response
			$urlPath = $request.RawUrl.TrimStart('/')

			Write-Log "[DEBUG] HTTP request received for: $urlPath from $($request.RemoteEndPoint)" -Color Yellow

			if ($urlPath -match ".*shutdown") {
				Write-Log "[DEBUG] Shutdown command received from main thread." -Color Yellow
				$response.StatusCode = 200	# OK
				$content = [System.Text.Encoding]::UTF8.GetBytes("Shutting down HTTP server")
				$response.ContentLength64 = $content.Length
				$response.OutputStream.Write($content, 0, $content.Length)
				$response.Close()
				$listener.Stop()
				$listener.Close()
				Write-Log "[DEBUG] HTTP server shut down gracefully" -Color Yellow
				Exit 0
			}

			$filePath = Join-Path $Config['PXEServerRoot'] $urlPath

			if ($urlPath -eq "GetPxeScript") {
				$filePath = "$($Config['PXEServerRoot'])\NBP\uefi.cfg"
			}

			if (Test-Path $filePath) {
				$fileBytes = [System.IO.File]::ReadAllBytes($filePath)
				$response.ContentType = "application/octet-stream"
				$response.ContentLength64 = $fileBytes.Length
				$response.OutputStream.Write($fileBytes, 0, $fileBytes.Length)
				Write-Log "[DEBUG] Served file: $filePath ($($fileBytes.Length) bytes) via HTTP" -Color Yellow
			}
			else {
				$response.StatusCode = 404
				$content = [System.Text.Encoding]::UTF8.GetBytes("404 - File not found: $urlPath")
				$response.ContentLength64 = $content.Length
				$response.OutputStream.Write($content, 0, $content.Length)
				Write-Log "[ERROR] HTTP 404: File not found - $filePath" -Color Red
			}

			$response.Close()
			if ($urlPath -match ".*boot\.wim") {
				$completedEndpoint = $request.RemoteEndPoint
				$regex = [regex]".*(?=:)"
				$completedBootIP = $regex.Match($completedEndpoint).Value
				Write-Log "[INFO] $completedBootIP received bootfiles" -Color Green
			}
			else {
				Write-Log "[DEBUG] HTTP response closed for $urlPath" -Color Yellow
			}
		}
	}
	catch {
		Write-Log "[ERROR] HTTP Server error: $_" -Color Red
	}
	finally {
		if ($listener.IsListening) {
			$listener.Stop()
			$listener.Close()
		}
	}
}

function Start-HttpJob {
	param (
		[ref]$HttpJobRef
	)
	if ($HttpJobRef.Value) {
		try {
			Remove-Job -Job $HttpJobRef.Value -Force -ErrorAction SilentlyContinue
		}
		catch {
			Write-Log "[WARNING] Failed to remove old HTTP job: $_" -Color Yellow
		}
	}
	$HttpJobRef.Value = Start-Job -ScriptBlock $httpScriptBlock -ArgumentList $Config
	Write-Log "[DEBUG] HTTP job started with ID: $($HttpJobRef.Value.Id)" -Color Yellow
}

# Initialize background HTTP job
$httpJob = $null
Start-HttpJob -HttpJobRef ([ref]$httpJob)
$clientOptions = @{}
$httpCheckInterval = 5	# Check every 5 seconds to make sure http server is up, client disconnect/reboot during download crashes server, job relaunch is faster than client can reconnect ;)
$lastHttpCheck = [DateTime]::Now

if(!($Config.DebugMode)){
	Clear-Host
}

# Main loop
Write-Log "[INFO] PXE Server Running [DHCP, ProxyDHCP, DNS, TFTP, HTTP] [SecureBoot Support: $(if ($SecureBootCompatibility) { 'ON' } else { 'OFF' })]" -Color White
Write-Log "[INFO] Server IP: $($Config.PXEServerIP), Subnet: $($Config.SubnetMask), Client Pool: $($serverSubnet[0..2] -join '.').$($Config.StartIP) - $($Config.EndIP)" -Color White
Write-Log "[INFO] Press ESC to exit" -Color White

try {
	while ($true) {
		if ([Console]::KeyAvailable) {
			$key = [Console]::ReadKey($true)
			if ($key.Key -eq [ConsoleKey]::Escape) {
				Write-Log "[INFO] ESC pressed - Initiating Shutdown" -Color White
				break
			}
		}

		$httpConsoleOutput = Receive-Job -Job $httpJob -ErrorAction SilentlyContinue
		if ($httpConsoleOutput) {
			foreach ($line in $httpConsoleOutput) {
				if ($Config.DebugMode) {
					Write-Host $line
				} else {
					if ($line -NotLike "*DEBUG*") {
						Write-Host $line
					}
				}
			}
		}

		if (([DateTime]::Now - $lastHttpCheck).TotalSeconds -ge $httpCheckInterval) {
			$jobState = (Get-Job -Id $httpJob.Id -ErrorAction SilentlyContinue).State
			if ($jobState -ne "Running") {
				Write-Log "[WARNING] HTTP job (ID: $($httpJob.Id)) is not running (State: $jobState). Restarting..." -Color Yellow
				Start-HttpJob -HttpJobRef ([ref]$httpJob)
			}
			$lastHttpCheck = [DateTime]::Now
		}

		if ($dnsSocket.Available -gt 0) {
			Write-Log "[DEBUG] DNS data available, attempting to receive" -Color Yellow
			try {
				$clientEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
				$query = $dnsSocket.Receive([ref]$clientEndpoint)
				Write-Log "[DEBUG] DNS query received from $($clientEndpoint.Address):$($clientEndpoint.Port), length: $($query.Length)" -Color Yellow
				Handle-DNSQuery -ClientEndpoint $clientEndpoint -Query $query
			}
			catch {
				Write-Log "[DEBUG] DNS Receive error: $_" -Color Yellow
			}
		}

		if ($dhcpSocket.Available -gt 0) {
			try {
				$clientEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
				$packet = $dhcpSocket.Receive([ref]$clientEndpoint)
				Write-Log "[DEBUG] Received DHCP packet from $($clientEndpoint.Address):$($clientEndpoint.Port), length: $($packet.Length)" -Color Yellow
				$packetHex = [BitConverter]::ToString($packet).Replace('-', ' ')
				Write-Log "[DEBUG] DHCP Packet XID: $([BitConverter]::ToString($packet[4..7]).Replace('-',''))" -Color Yellow
				if ($Config.DebugMode) { 
					Write-Log "[DEBUG] DHCP Packet Content (Hex): $packetHex" -Color Cyan
				}
				if ($packet.Length -ge 240 -and $packet[0] -eq 1) {
					$mac = [BitConverter]::ToString($packet[28..33]).Replace('-','')
					$xid = $packet[4..7]
					$optionsOffset = 240
					$dhcpMessageType = $null
					$requestedIP = $null
					$pxeClient = $false
					$isUEFI = $false
					$i = $optionsOffset
					while ($i -lt $packet.Length -and $packet[$i] -ne 255) {
						$option = $packet[$i]
						$len = $packet[$i + 1]
						if ($i + 2 + $len -gt $packet.Length) { break }
						$valueBytes = $packet[($i + 2)..($i + 1 + $len)]
						switch ($option) {
							53 { $dhcpMessageType = $valueBytes[0] }
							50 { if ($len -eq 4) { $requestedIP = [System.Net.IPAddress]::new($valueBytes).ToString() } }
							60 {
								$vendorClass = [System.Text.Encoding]::ASCII.GetString($valueBytes)
								if ($vendorClass -like "PXEClient*") {
									$pxeClient = $true
									Write-Log "[DEBUG] Detected PXEClient (Vendor Class: $vendorClass) for MAC $mac" -Color Yellow
								}
							}
							93 {
								if ($len -eq 2) {
									$archType = ($valueBytes[0] -shl 8) + $valueBytes[1]
									if ($archType -eq 0x0007) {
										$isUEFI = $true
										Write-Log "[DEBUG] Detected UEFI client (Arch: 0x$($archType.ToString('X4'))) for MAC $mac" -Color Yellow
									}
									elseif ($archType -eq 0x0000) {
										Write-Log "[DEBUG] Detected BIOS client (Arch: 0x$($archType.ToString('X4'))) for MAC $mac" -Color Yellow
									}
									else {
										Write-Log "[DEBUG] Detected unknown architecture (Arch: 0x$($archType.ToString('X4'))) for MAC $mac" -Color Yellow
									}
								}
							}
						}
						$i += 2 + $len
					}

					if (-not $pxeClient) {
						Write-Log "[DEBUG] Ignoring DHCP request from MAC $mac - no PXEClient identifier" -Color Yellow
						continue
					}

					if ($dhcpMessageType -eq 1) {
						Write-Log "[DEBUG] Processing DHCP DISCOVER from MAC $mac" -Color Yellow
						$existingIp = $ipAssignments.Keys | Where-Object { $ipAssignments[$_] -eq $mac } | Select-Object -First 1
						if ($existingIp) {
							$ip = $existingIp
						}
						else {
							$ip = $ipPool | Where-Object {
								if (-not $ipAssignments.ContainsKey($_)) {
									$ping = Test-Connection -ComputerName $_ -Count 1 -Quiet -ErrorAction SilentlyContinue
									if (-not $ping) { $ipAssignments.TryAdd($_, $mac) }
									-not $ping
								}
								else { $false }
							} | Select-Object -First 1
						}
						if ($ip) {
							Send-DHCPOffer -ClientEndpoint $clientEndpoint -AssignedIP $ip -ClientMAC $packet[28..33] -TransactionID $xid -IsUEFI $isUEFI
							Write-Log "[DEBUG] DHCP assigned $ip to MAC $mac" -Color Yellow
							if ($pxeClient -and $proxyDhcpSocket) {
								Send-ProxyDHCPOffer -ClientEndpoint $clientEndpoint -AssignedIP $ip -ClientMAC $packet[28..33] -TransactionID $xid -IsUEFI $isUEFI
								Write-Log "[DEBUG] Sent ProxyDHCP OFFER for DISCOVER to $ip, TID $([BitConverter]::ToString($xid).Replace('-',''))" -Color Yellow
							}
						}
						else {
							Write-Log "[ERROR] No available IP for MAC $mac" -Color Red
						}
					}
					elseif ($dhcpMessageType -eq 3) {
						Write-Log "[DEBUG] Processing DHCP REQUEST from MAC $mac" -Color Yellow
						$ip = $ipAssignments.Keys | Where-Object { $ipAssignments[$_] -eq $mac } | Select-Object -First 1
						if (-not $ip -and $requestedIP -and $ipPool.Contains($requestedIP)) {
							$ping = Test-Connection -ComputerName $requestedIP -Count 1 -Quiet -ErrorAction SilentlyContinue
							if (-not $ping -and $ipAssignments.TryAdd($requestedIP, $mac)) { $ip = $requestedIP }
						}
						if ($ip) {
							Send-DHCPAck -ClientEndpoint $clientEndpoint -AssignedIP $ip -ClientMAC $packet[28..33] -TransactionID $xid -IsUEFI $isUEFI
							Write-Log "[DEBUG] DHCP ACK sent for $ip to MAC $mac" -Color Yellow
						}
						else {
							Write-Log "[ERROR] No valid IP assignment for DHCP REQUEST from MAC $mac" -Color Red
						}
					}
				}
			}
			catch {
				Write-Log "[DEBUG] DHCP Receive error: $_" -Color Yellow
			}
		}

		if ($tftpSocket.Available -gt 0) {
			try {
				$tftpResult = Receive-TFTPPacket
				if (-not $tftpResult.Data) { continue }

				$packet = $tftpResult.Data
				$endpoint = $tftpResult.Endpoint
				$filename = $tftpResult.Filename
				$mode = $tftpResult.Mode
				$options = $tftpResult.Options
				$endpointKey = "$($endpoint.Address):$($endpoint.Port)"
				$clientIP = $endpoint.Address.ToString()

				if ($packet[0] -eq 0 -and $packet[1] -eq 1) {
					Write-Log "[DEBUG] TFTP RRQ for $filename from $endpointKey" -Color Yellow
					$fileToServe = $null
					switch -RegEx ($filename) {
						"$global:BIOSBootfileName" { $fileToServe = "$($Config.PXEServerRoot)\NBP\$global:BIOSBootfileName" }
						"$global:UEFIBootfileName" { $fileToServe = "$($Config.PXEServerRoot)\NBP\$global:UEFIBootfileName" }
					}

					if ($fileToServe) {
						if (-not (Test-Path $fileToServe)) {
							Write-Log "[ERROR] File not found at path: $fileToServe" -Color Red
							$errorPacket = [byte[]](0,5, 0,1) + [System.Text.Encoding]::ASCII.GetBytes("File not found") + [byte]0
							$tftpSocket.Send($errorPacket, $errorPacket.Length, $endpoint) | Out-Null
							continue
						}

						$blockSize = 512
						$timeoutMs = 2000
						if ($options["blksize"]) { $blockSize = [Math]::Min([int]$options["blksize"], 1468) }
						if ($options["timeout"]) { $timeoutMs = [int]$options["timeout"] * 1000 }
						if ($options["tsize"] -and $options["tsize"] -eq "0") {
							$fileSize = (Get-Item $fileToServe).Length.ToString()
							$options["tsize"] = $fileSize
						}

						$clientOptions[$endpointKey] = @{
							BlockSize = $blockSize
							TimeoutMs = $timeoutMs
							FilePath  = $fileToServe
						}

						if ($options.Count -gt 0) {
							$oack = [byte[]](0,6)
							if ($options["blksize"]) { $oack += [System.Text.Encoding]::ASCII.GetBytes("blksize") + [byte]0 + [System.Text.Encoding]::ASCII.GetBytes($blockSize.ToString()) + [byte]0 }
							if ($options["tsize"]) { $oack += [System.Text.Encoding]::ASCII.GetBytes("tsize") + [byte]0 + [System.Text.Encoding]::ASCII.GetBytes($options["tsize"]) + [byte]0 }
							if ($options["timeout"]) { $oack += [System.Text.Encoding]::ASCII.GetBytes("timeout") + [byte]0 + [System.Text.Encoding]::ASCII.GetBytes(($timeoutMs / 1000).ToString()) + [byte]0 }
							$tftpSocket.Send($oack, $oack.Length, $endpoint) | Out-Null
						}
						else {
							Send-TFTPFile -ClientEndpoint $endpoint -FilePath $fileToServe -BlockSize $blockSize -TimeoutMs $timeoutMs
						}
					}
					else {
						$errorPacket = [byte[]](0,5, 0,1) + [System.Text.Encoding]::ASCII.GetBytes("File not found") + [byte]0
						$tftpSocket.Send($errorPacket, $errorPacket.Length, $endpoint) | Out-Null
					}
				}
				elseif ($packet[0] -eq 0 -and $packet[1] -eq 4) {
					$blockNum = [BitConverter]::ToUInt16([byte[]]($packet[2], $packet[3]), 0)
					if ($blockNum -eq 0) {
						$clientConfig = $clientOptions[$endpointKey]
						if ($clientConfig) {
							Send-TFTPFile -ClientEndpoint $endpoint -FilePath $clientConfig.FilePath -BlockSize $clientConfig.BlockSize -TimeoutMs $clientConfig.TimeoutMs
						}
					}
				}
			}
			catch {
				Write-Log "[ERROR] TFTP handling error: $_" -Color Red
			}
		}

		if ($proxyDhcpSocket -and $proxyDhcpSocket.Available -gt 1) {
			try {
				$clientEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
				$packet = $proxyDhcpSocket.Receive([ref]$clientEndpoint)
				Write-Log "[DEBUG] Received ProxyDHCP packet from $($clientEndpoint.Address):$($clientEndpoint.Port), length: $($packet.Length)" -Color Yellow
				$packetHex = [BitConverter]::ToString($packet).Replace('-', ' ')
				Write-Log "[DEBUG] ProxyDHCP Packet XID: $([BitConverter]::ToString($packet[4..7]).Replace('-',''))" -Color Yellow
				if ($Config.DebugMode) { 
					Write-Log "[DEBUG] ProxyDHCP Packet Content (Hex): $packetHex" -Color Cyan
				}
				if ($packet.Length -ge 240 -and $packet[0] -eq 1) {
					$mac = $packet[28..33]
					$xid = $packet[4..7]
					$optionsOffset = 240
					$dhcpMessageType = $null
					$isUEFI = $false
					$i = $optionsOffset
					while ($i -lt $packet.Length -and $packet[$i] -ne 255) {
						$option = $packet[$i]
						$len = $packet[$i + 1]
						if ($i + 2 + $len -gt $packet.Length) {
							Write-Log "[DEBUG] ProxyDHCP packet truncated at option $option" -Color Yellow
							break
						}
						$valueBytes = $packet[($i + 2)..($i + 1 + $len)]
						switch ($option) {
							53 { $dhcpMessageType = $valueBytes[0] }
							93 {
								if ($len -eq 2) {
									$archType = ($valueBytes[0] -shl 8) + $valueBytes[1]
									if ($archType -eq 7) {
										$isUEFI = $true
										Write-Log "[DEBUG] Detected UEFI client (Arch: 0x$($archType.ToString('X4')))" -Color Yellow
									}
								}
							}
						}
						$i += 2 + $len
					}
					if ($dhcpMessageType -eq 1) {
						$ip = if ($ipAssignments.ContainsKey($clientEndpoint.Address.ToString())) { $clientEndpoint.Address.ToString() } else { "0.0.0.0" }
						Send-ProxyDHCPOffer -ClientEndpoint $clientEndpoint -AssignedIP $ip -ClientMAC $mac -TransactionID $xid -IsUEFI $isUEFI
						Write-Log "[DEBUG] Sent ProxyDHCP OFFER for DISCOVER to $ip, TID $([BitConverter]::ToString($xid).Replace('-',''))" -Color Yellow
					}
					elseif ($dhcpMessageType -eq 3) {
						$ip = $clientEndpoint.Address.ToString()
						Send-ProxyDHCPOffer -ClientEndpoint $clientEndpoint -AssignedIP $ip -ClientMAC $mac -TransactionID $xid -IsUEFI $isUEFI
						Write-Log "[DEBUG] Sent ProxyDHCP OFFER for REQUEST to $ip, TID $([BitConverter]::ToString($xid).Replace('-',''))" -Color Yellow
					}
				}
			}
			catch {
				Write-Log "[ERROR] ProxyDHCP handling failed: $_" -Color Red
			}
		}
	}
}
catch {
	Write-Log "[ERROR] Server Error: $_" -Color Red
}
finally {
	try {
		if ($dhcpSocket) { $dhcpSocket.Close(); $dhcpSocket.Dispose() }
		if ($tftpSocket) { $tftpSocket.Close(); $tftpSocket.Dispose() }
		if ($proxyDhcpSocket) { $proxyDhcpSocket.Close(); $proxyDhcpSocket.Dispose() }
		if ($dnsSocket) { $dnsSocket.Close(); $dnsSocket.Dispose() }
		if ($httpJob) {
			try {
				Set-Variable ProgressPreference SilentlyContinue
				iwr "http://$($Config.PXEServerIP):$($Config.HttpPort)/shutdown" -ErrorAction SilentlyContinue | Out-Null
				Set-Variable ProgressPreference Continue
				if ($Config.DebugMode){
					$httpConsoleOutput = Receive-Job -Job $httpJob -ErrorAction SilentlyContinue | Out-Null
					if ($httpConsoleOutput) {
						foreach ($line in $httpConsoleOutput) {
							Write-Host $line
						}
					}
				}
			}
			catch {
				Write-Log "[ERROR] Error stopping HTTP job gracefully: $_" -Color Yellow
				$jobInfo = Get-Job -Id $httpJob.Id -ErrorAction SilentlyContinue
				if ($jobInfo) {
					$processId = $jobInfo.ChildJobs[0].JobStateInfo.ProcessId
					if ($processId) {
						Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
						Write-Log "[DEBUG] HTTP job process (PID: $processId) forcefully terminated" -Color White
					}
				}
				Remove-Job -Job $httpJob -ErrorAction SilentlyContinue
			}
		}
		Write-Log "[INFO] Sockets (DHCP, TFTP, ProxyDHCP, DNS, HTTP) closed and disposed" -Color White
	}
	catch {
		Write-Log "[WARNING] Error closing sockets: $_" -Color Yellow
	}
	Remove-NetIPAddress -InterfaceAlias "$adapter" -IPAddress $($Config.PXEServerIP) -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
	netsh interface ipv4 set interface "$adapter" dhcpstaticipcoexistence=disabled | Out-Null
    try {
		Set-Variable ProgressPreference SilentlyContinue
		Remove-NetFirewallRule -DisplayName "PXEServer Services*" -ErrorAction SilentlyContinue | Out-Null
		Set-Variable ProgressPreference Continue
		Write-Log "[DEBUG] Firewall rules matching 'PXEServer Services*' removed" -Color White
    } catch {
        Write-Log "[ERROR] Failed to remove firewall rules: $_" -Color Yellow
    }
	Write-Log "[INFO] Shutdown complete" -Color White
	Write-Host "`n`nPress any key to exit..." -ForegroundColor White
	[void][System.Console]::ReadKey($true)
}