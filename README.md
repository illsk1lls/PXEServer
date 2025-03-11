<h1 align="center">A Powershell PXEServer [DHCP,ProxyDHCP,DNS,TFTP,HTTP]</h1>
 
 BIOS/UEFI PXEBoot supported. Powered by iPXE
 
SecureBoot compatility can be enabled, but provides less NIC support(drivers), if you are having network issues try leaving SecureBoot Compatibility disabled<br>

	TO ENABLE SECUREBOOT SUPPORT navigate to the following page: <a href="https://knowledge.broadcom.com/external/article/280113/updated-64bit-ipxeefi-ipxe-v1211+-binari.html">https://knowledge.broadcom.com/external/article/280113/updated-64bit-ipxeefi-ipxe-v1211+-binari.html</a><br>
	Scroll to the bottom of the page, and click the 64bit_ipxe_efi.zip download button to get a signed copy of ipxe.efi (Thank you Broadcom)<br>
	
	Extract ipxe.efi from 64bit_ipxe_efi.zip AND RENAME IT TO ==> ipxe2.efi<br>
	Assuming your PXEServer is located at C:\PXE, place the new ipxe2.efi in C:\PXE\NBP\
	
	If C:\PXE\NBP\ipxe2.efi exists SecureBoot compatibility mode will be enabled during launch<br>

The following components are included within the script:

1.) DHCP/ProxyDHCP listener, that only responds to PXEClients<br>
2.) DNS server
3.) TFTP server
4.) HTTP file server 

All are required for the full PXE boot process.

Download a ZIP of the repository, and extract the contents to C:\PXE

File structure should look like:

C:\PXE\NBP\ipxe2.efi <== Use the above method to get/rename this file for secureboot compatibility
C:\PXE\NBP\ipxe.efi
C:\PXE\NBP\undionly.kpxe
C:\PXE\NBP\undionly2.kpxe
C:\PXE\NBP\wimboot
C:\PXE\PXEServer.ps1
C:\PXE\x-Install.ps1
C:\PXE\x-Uninstall.ps1
C:\PXE\PXEServer.ps1
C:\PXE\README.md
C:\PXE\LICENSE

Run x-Install.ps1 to configure your machine with the default settings, this will DISABLE your firewall
(Ensure to take appropriate precautions as needed)

MOUNT YOUR WINPE ISO AND COPY THE FILES TO C:\PXE

Run PXEServer.ps1 and network boot!

------------------------------------

To remove PXEServer settings and turn Windows Firewall back on run x-Uninstall.ps1

------------------------------------

This is a work in progress and proof of concept.. please don't take it too seriously ;P