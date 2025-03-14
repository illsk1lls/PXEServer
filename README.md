<h1 align="center">A Powershell PXEServer [DHCP/ProxyDHCP/DNS/TFTP/HTTP]</h1>
 
BIOS/UEFI PXEBoot supported.
 
Download a ZIP of the repository, and extract the contents to C:\PXE<br> 

File structure should look like:<br> 

C:\PXE\NBP\ipxe2.efi <== This file is NOT included! (or needed) Use the below method to get/rename this file for SecureBoot compatibility<br> 
C:\PXE\NBP\ipxe.efi<br> 
C:\PXE\NBP\undionly.kpxe<br> 
C:\PXE\NBP\undionly2.kpxe<br> 
C:\PXE\NBP\wimboot<br> 
C:\PXE\PXEServer.ps1<br> 
C:\PXE\x-Install.ps1<br> 
C:\PXE\x-Uninstall.ps1<br> 
C:\PXE\README.md<br> 
C:\PXE\LICENSE<br> 

SecureBoot compatibility can be enabled, but provides less NIC support(drivers). During testing, if network boot would fail due to limited drivers, the client would create an error along the lines of x/xxx/xxRtk.xxxx.cp (in this case indicating an issue with some Realtek drivers) somewhere on the screen immediately after attempting DHCP. In cases where boot is not completing disable SecureBoot on the clients and turn SecureBoot Compatibility support off on the server.

TO ENABLE SECUREBOOT SUPPORT navigate to the following page: <a href="https://knowledge.broadcom.com/external/article/280113/updated-64bit-ipxeefi-ipxe-v1211+-binari.html">https://knowledge.broadcom.com/external/article/280113/updated-64bit-ipxeefi-ipxe-v1211+-binari.html</a><br>
Scroll to the bottom of the page, and click the 64bit_ipxe_efi.zip download button to get a signed copy of ipxe.efi (Thank you Broadcom)<br>

Extract ipxe.efi from 64bit_ipxe_efi.zip AND RENAME IT TO ==> ipxe2.efi<br>
Assuming your PXEServer is located at C:\PXE, place the new ipxe2.efi in C:\PXE\NBP\

If C:\PXE\NBP\ipxe2.efi exists SecureBoot compatibility mode will be enabled during launch<br>

The following components are included within the script:<br> 

1.) DHCP/ProxyDHCP listener, that only responds to PXEClients<br>
2.) DNS server<br>
3.) TFTP server<br>
4.) HTTP file server<br> 

All are required for the full PXE boot process. (Except DNS during SecureBoot sessions) <br> 

Run x-Install.ps1 to configure your machine with the default settings, this will DISABLE your firewall<br> 
(Ensure to take appropriate precautions as needed)<br> 

MOUNT YOUR WINPE ISO AND COPY ALL FILES TO C:\PXE\ <br> 
(THIS HAS BEEN TESTED USING WIN10PESE AND WIN10XPE BOOTABLE ISO's)<br>

Win10XPE can be found here: <a href="https://github.com/ChrisRfr/Win10XPE">https://github.com/ChrisRfr/Win10XPE</a> <br>
(To make a successful vanilla build with this version, without having to make edits, disable: Apps>HD Tasks>AOMEI Partition Assistant, and, Apps>Network>Google Chrome) 

Run PXEServer.ps1 and network boot!<br> 

------------------------------------<br> 

Press Esc to Exit, and to remove PXEServer settings and turn Windows Firewall back on run x-Uninstall.ps1<br> 

------------------------------------<br> 

This is a work in progress and proof of concept.. please don't take it too seriously ;P<br> 
NOTE: If the program is forcibly closed while the Http background job is running, the background process will remain open,<br>
for now either restart the server and close it properly, or manually close the background powershell processes using task manager<br>

Stability updates and fixes coming soon. And any help is appreciated/welcomed.

Powered by iPXE (https://github.com/ipxe/ipxe)
