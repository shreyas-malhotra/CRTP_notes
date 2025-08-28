- In an AD environment, there are multiple scenarios which can lead to privilege escalation. We had a look at the following:
	- Hunting for Local Admin access on other machines
	- Hunting for high privilege domain accounts (like a Domain Administrator)
- Let's also look for Local Privilege Escalation to escalate privileges on our foothold machine.
- ![[image.png]]

#### Local Privilege Escalation
- There are various ways of escalating privileges locally on a Windows box:
	- Missing patches
	- Automated deployment (for example `unattend.xml`) and AutoLogon passwords in clear-text
		- AutoLogon passwords are a registry key that contains credentials, usually Admin credentials, in clear-text.
		- Where are AutoLogon passwords used?
			- In scenarios where there is no one present to logon to a machine and start an application, for example, billboards, kiosks, medical devices etc.
			- In many such devices, the operators are just expected to turn on the system and the machines are expected to login as a user and run an application by itself.
	- AlwaysInstallElevated (Any user can run MSI as system)
		- Used to be popular early on, not as popular now.
		- It is a registry setting that allow every user to run an installer file as SYSTEM.
	- Misconfigured services
		- Evergreen method of PrivEsc.
		- Services that have overly permissive ACLs, services where we can just go on and overwrite the service binary or change the parameters to the service executable and so on.
	- DLL Hijacking, DLL Sideloading and more
	- Kerberos and NTLM Relaying
		- Microsoft claims that Kerberos and NTLM Relaying would hopefully soon be a thing of the past.
- We can use the tools given below for complete coverage of the PrivEsc vectors
	- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
	- [PrivescCheck](https://github.com/itm4n/PrivescCheck)
	- [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

#### PrivEsc using misconfigured services
- Finding the pathname for all the services on a machine. 
	- `Get-WmiObject -Class win32_service | select pathname`
	- If we find an unquoted pathname with a whitespace in it, it can be used to execute an arbitrary binary and perform PrivEsc due to how windows behaves with whitespace characters in paths, that is it executes the first binary it find with the name set as the string before the whitespace, in the specified path.
	- Pathname: `C:\WebServer\Abyss Web Server\abyssws.exe -service`
	- If we create a malicious binary named `Abyss.exe` at `C:\WebServer\`, and restart the service, Windows will execute the `Abyss.exe` binary instead of the specified binary in the pathname.
	- Mitigation: Enquote the path name with double quotes, as follows `"C:\WebServer\Abyss Web Server\abyssws.exe" -service`.
- Get services with unquoted paths and a space in their name with PowerUp
	- `Get-ServiceUnquoted -Verbose`
- Get services where the current user can write to its binary path or change arguments to the binary with PowerUp
	- `Get-ModifiableServiceFile -Verbose`
	- We can modify the binary in a malicious manner to perform PrivEsc locally.
- Get the services whose configuration the current user can modify with PowerUp
	- `Get-ModifiableService -Verbose`
	- We can modify the service arguments in a malicious manner to perform PrivEsc locally.
- Overly permissive ACL for services
	- `sc.exe sdshow snmptrap`
		- `snmptrap` is a built in Windows service, but for the lab it is made intentionally vulnerable.
		- If we list the ACL of the service, we can see the following DACL:
			- `D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)`
			- ACL glossary
				- D = DACL
				- A = Allow
				- SY= Local System
				- BA = Built-in Administrators
				- IU = Interactive Users
				- SU = Service Logon Users
				- WD = Everyone (World)
				- Rights (abbreviated):
					- CC = Create Child
					- DC = Delete Child
					- LC = List Children
					- SW = Self Write
					- RP = Read Property
					- WP = Write Property
					- DT = Delete Tree
					- LO = List Object
					- CR = Control Access
					- SD = Standard Delete
					- RC = Read Control
					- WD = Write DAC
					- WO = Write Owner
			- Permissions set on the service:

| **Trustee**             | **Permissions Description**                | **Notes**                         |
| ----------------------- | ------------------------------------------ | --------------------------------- |
| **`SY` (Local System)** | Read, Write, Create, Delete, Control       | Full control                      |
| **`BA` (Admins)**       | All permissions                            | Full control                      |
| **`IU` (Interactive)**  | Read, List, limited control                | Read-only                         |
| **`SU` (Services)**     | Same as Interactive                        | Read-only                         |
| **`WD` (Everyone)**     | Full access incl. write, delete, ownership | Overly permissive - security risk |
	- After checking the permission table, we can see that `WD` (Everyone) have overly permissive rights, equivalent to the Built-In Administrator.
	- These rights include the rights to reconfigure the `snmptrap` service, which means we can actually go ahead and change the executable for the `snmptrap` service to our own payload.
	- Will using misconfigured services for PrivEsc be detected by EDRs?
		- EDR based detection may or may not occur, depending on the payload we are trying to execute and the EDR deployed on the system.
		- Even if EDRs do not detect this specific technique, any changes made to the local Administrators group are so noisy that detection won't even need an EDR.
		- The detection means that this is not a very OPSEC friendly attack.
		- In the lab we modify the local Administrators group on our foothold machine, but if we want to be OPSEC friendly, we can try to spawn a new process with higher privileges during the privilege escalation process.
	- Will this process be detected by MDI/MDE?
		- If we try to perform PrivEsc on a DC using misconfigured services, MDI will pick it up and flag that we are making changes to an existing service, and MDE may also pick this up.
	- Mitigation for PrivEsc by misconfigured services
		- Regular auditing of service ACLs on the organization's machines.
		- Any ACE entry for `WD` (Everyone) should be closely monitored.

#### Privilege Escalation Methodology
- Run all checks from
	- PowerUp
		- `Invoke-AllChecks`
	- PrivEsc
		- `Invoke-PrivEscCheck`
	- PEASS-ng
		- `winPEASx64.exe`