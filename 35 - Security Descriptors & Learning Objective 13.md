- With Administrative privileges, it is possible to modify Security Descriptors (security information like Owner, primary group, DACL and SACL) of multiple remote access methods (securable objects) to allow access to non-admin users.
- This can work as a very useful backdoor mechanism for persistence.
- Practical explanation:
	- There are another set of objects that have ACLs, we have already touched that while trying to perform local privilege escalation using mis-configured services, services that had overly permissive Security Descriptors (ACLs) which we were able to abuse to escalate our privileges.
	- The same concept applies to remoting protocols as well, three of which can be tampered with, by changing certain ACLs on a machine where we have administrative access, to allow access to the machine using these remoting protocols without administrative access being required when connecting to them. The protocols are:
		- PowerShell Remoting
		- WMI
		- Remote Registry
- SDDL (Security Descriptor Definition Language) defines the format which is used to describe a security descriptor. SDDL uses ACE strings for DACL and SACL:
	- `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid`
	- ACE for built-in administrators for WMI namespaces:
		- `A;CI;CCDCLCSWRPWPRCWD;;;SID`
		- `ace_type` is set to Allow.
		- `ace_flags` are set to Container Inherit.
		- `rights` are set to create child (CC) delete child (DC), list child (LC) and so on.
		- `object_guid` and `inherit_object_guid` are not shown here, they are shown if they are there at all.
		- The `account_sid` is also now shown here.
- The most important part of the ACE for us is the `account_sid`, we are going to identify where the ACL needs to be modified to provide us with a backdoor, and modify the `account_sid` with the SID of a user that we control and apply that on the ACLs.
	- This should provide us administrator equivalent access on those services.

#### Persistence using ACLs - Security Descriptors - WMI
- When someone authenticates to a machine using WMI, their ACLs are matched with ACLs present at two places:
	1. Component Services - DCOM Endpoint - `Server Manager>Component Services>Computers>My Computer (Properties)>COM Security>Edit Limits>ACLs`
		- When we first connect to WMI, an ACL is checked here post-authentication.
	2. WMI Namespaces - `Computer Management>Services and Applications>WMI Control (Properties)>Security>Namespace Naviagtion>Root (Security)>ACLs`
		- We may have permissions to connect to the DCOM endpoint, but do we have permissions to connect to a particular namespace?
- If we are going to target the DC for persistence, we would need pre-existing DA privileges.
- Performing the attack, DA privileges required:
	- `. C:\AD\Tools\RACE-master\RACE.ps1`
	- `Set-RemoteWMI -SamAccountName student1 -Verbose`
		- This command reads the existing ACL, for the root namespace,  and the existing ACL for DCOM, and then it adds a new ACL, providing student1 the same ACE (this ACE affects just the service, this does not reflect Privilege Escalation on the DC) as the built-in administrator with the provided user's SID.
			- We can pass the `-Remove` flag with the command given above to undo these changes.
		- To test that this command ran successfully and WMI access is provided, we can try logging in from the student user's machine:
			- `gwmi -class win32_operatingsystem -ComputerName dcorp-dc`
		- From the DC, we can verify this by having a look at the ACL for the WMI root namespace, which should now have an entry for student1.

#### Persistence using ACLs - Security Descriptors - PowerShell Remoting
- Using the RACE toolkit - PS Remoting backdoor not stable after August 2020 patches, it may sometimes crash the WinRM service.
- We can fetch the PS session configuration using the following command:
	- `Get-PSSession-Configuration`
- `microsoft.powershell` is the default configuration we connect to.
- If we have administrative access, we can open the security descriptor (ACL) for this configuration using the following command (while using RDP):
	- `Set-PSSession-Configuration -Name microsoft.powershell -ShowSecurityDescriptorUI`
- As the DA, we can get persistence on the DC by modifying the Security Descriptors for PS Remoting using the RACE toolkit (Requires DA privileges):
	- `Set-RemotePSRemoting -SamAccountName student1 -ComputerName dcorp-dc -Verbose`
		- On executing this command we may get an error stating that "The I/O operation has been aborted because of either a thread exit or an application request.", we do not need to worry about it since this just indicates that our attack has been performed successfully, but the WinRM on the remote machine did not close the connection gracefully.
	- To test whether we can now get access on `dcorp-dc` using PS Remoting:
		- `Enter-PSSession dcorp-dc`
		- `$env:username`
			- This command would show the username as student1.
			- It is not recommended to run the `whoami` command since it will get detected by the AV, but Nikhil ran it in the video to show that our user still had normal user privileges, so we can connect to the DC using WMI or PS-Remoting but not with elevated privileges.
			- So next, we would need to perform local privilege escalation on the DC, we can use any method or tools we want, WinPEAS, PowerUp and so on.
				- We can also check if there is anything present in the root of the C: directory or the `ProgramFiles` directory, since they are readable by users with any privileges, maybe we can find some script or stored credentials.
			- Without elevated privileges, we cannot perform a DCSync attack, we cannot read NTDS.dit, we can read the SAM hive, we cannot do anything that requires elevated privileges.

#### Persistence using ACLs - Security Descriptors - PowerShell Remoting - Remote Registry
- Remote Registry Abuse was presented by Specter Ops at Black Hat USA, the guys who wrote BloodHound. And was originally a part of the DAMP toolkit.
- Remote Registry solves the issue that we face with the other two methods mentioned here, i.e. we are able to have elevate privileges when abusing Remote Registry.
- In this case, once again we modify some ACLs, however, we do not only modify the ACL of the Remote Access Protocol, but also of some of the credentials that are stored in the Registry, like the machine account hash, any local account hashes that may be there, and domain cached credentials.
	- The most interesting thing here is the remote machine account hash, if we have it, we can perform a Silver Ticket attack, which is precisely what we are going to do.
	- If the silver ticket attack is performed on a DC, we are in for a treat, we will be able to create a silver ticket that provides us full access to any resources, since we have full (administrative) access on the DC.
		- And if we have administrative access on the DC, we have full access over the domain, we can even perform a DCSync attack and get credentials for all the accounts in the DC.
- Performing Remote Registry Abuse:
	- Using RACE or DAMP, with admin privileges on the remote machine:
		- `Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose`
	- As student 1, retrieving machine account hash:
		- `Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose`
	- Retrieve local account hash:
		- `Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose`
	- Retrieve domain cached credentials:
		- `Get-RemoteCachedCredential -ComputerName dcorp-dc -Verbose`

#### Learning Objective 13
- Modify security descriptors on `dcorp-dc` to get access using PS Remoting and WMI without requiring administrator credentials.
	- Already covered above.
- Retrieve machine account hash from `dcorp-dc` without using administrator access and use that to execute a Silver Ticket attack to get code execution with WMI.
	- `Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose`
		- We can observe that multiple ACLs for multiple registry keys have been changed.
	- Now that we have a Remote Registry Backdoor, we can use the RACE toolkit as a normal user student1, and get the machine account hash for the DC:
		- `. C:\AD\Tools\RACE.ps1`
		- `Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose`
	- We now have the Machine account hash for the DC and can perform a Silver Ticket attack on it, to access the DC as the administrator if we want.