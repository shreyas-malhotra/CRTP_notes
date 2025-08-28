- A Security Support Provider (SSP) is a DLL, which provides ways for an application to obtain an authenticated connection. Some SSP packages by Microsoft are:
	- NTLM
	- Kerberos
	- Wdigest
	- CredSSP
	- CloudAP (Used by Azure AD/ Entra AD)
- If we have administrative access on a machine, not just the DC, any member machine, we can inject a custom SSP, for example a PoC SSP that comes with mimikatz, `mimilib.dll`. This SSP logs local logons, service account and machine account passwords in clear text on the target server.
- Not that for our use case, DA persistence, we will need to have DA access on the DC itself and then inject a custom SSP on the DC, the above statement just highlights the fact that we can use Custom SSPs on regular machines as well.
- We can use it in either of the following ways:
	- Drop the `mimilib.dll` to `system32` and add `mimilib` to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` by changing some registry keys:
		- ```$packages = Get-ItemProperty
		  HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages'
		  $packages += "mimilib"
		  Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
		  Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages```
	- Using mimikatz, inject into LSASS (Not super stable with Server 2019 and Server 2022, but still usable, not prone to crashing, but may fail to work at times):
		- `SafetyKatz.exe -Command '"misc::memssp"'`

#### Downsides of using Custom SSPs
- An issue with using Custom SSPs would be that by doing so, we are downgrading the security of the target environment, since the credentials are being logged in clear-text on the DC at `C:\Windows\system32\mimilsa.log`.
- Another issue we may face with this persistence technique is that we need DA privileges to use the persistence we set up, since we need to read the credentials from the log file.
	- A way out of this issue would be to save the log in the `SYSVOL` (since it is a world-readable file-share on the DC), instead of in the `mimilsa.log` directory under `system32` on the DC.
		- This will kill the security of the target environment, and should not be used in real life engagements.
	- The actual way of using Custom SSPs is to modify the `mimilib.dll` (or other Custom SSP DLL we may be using), and include code to exfiltrate the logs to a remote server or repository, to be able to read the credential logs without needing DA privileges.