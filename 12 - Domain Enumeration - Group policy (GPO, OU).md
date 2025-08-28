#### Group Policy (GPOs)
- Group Policy is the de-facto management solution in AD, this is what we use to manage the 50k nodes that our organization may have.
- Group Policy provides the ability to manage configuration and changes easily and centrally in AD.
- A policy setting may only apply on a computer or a user:
	- For Computers: Security settings, start-up and shutdown scripts, assigned applications and more.
	- For Users: Security settings, logon and logoff scripts, assigned applications and more.
- Group Policies apply to OUs (Organizational Units).
- Group Policy settings are contained in a Group Policy Object (GPO).
- "A GPO is a virtual collection of policy settings, security permissions, and scope of management (SOM) that you can apply to users and computers."
	- Basically a GPO is what is applied to a certain set of users or computers.
- GPOs can be linked to domains, sites and organizational units (OUs).
- Overly permissive GPOs can be abused for attacks like privesc, backdoors, persistence etc (for example if a low priv user has a WriteDACL permission).

#### Enumerating GPOs
- Get list of GPO in current domain
	- `Get-DomainGPO`
	- `Get-DomainGPO | select displayname`
	- `Get-DomainGPO -ComputerIdentity dcorp-student1`
	- The resultant settings of the policy are not shown while using the above commands, if we run `rsop.msc`, it shows us the applicable settings on our machine. 
	- If we would like to enumerate the policy settings of another machine, we cannot do so.
- Get GPO(s) which use Restricted Groups or groups.xml for interesting users
	- `Get-DomainGPOLocalGroup`
	- Restricted Groups are used to add Domain Groups to Local Groups.
- Get users which are in a local group of a machine using GPO
	- `Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcorp-student1`
- Get machines where the given user is a member of a specific group
	- `Get-DomainGPOUserLocalGroupMapping -Identity student1 -Verbose`

#### Organizational Units (OUs)
- Organizations use organizational units (OUs) for delegating administration.
- An OU is the lowest-level AD container to which a GPO can be applied.
- Attacks at the OU level due to misconfigured or overly permissive GPOs are most common in enterprise environments.
- System Administrators in different regions of the world are generally granted rights to reset user passwords for I.T. helpdesk tasks, we can create specific OUs as per our requirements to provision these rights in a more granular way.

#### Enumerating OUs
- Get OUs in a domain
	- `Get-DomainOU`
	- `Get-DomainOU | select name`
- Figuring out the GPO applied on an OU:
	- The results from the `Get-DomainOU` command display the results for a value called `gplink`, which mentions the name of the GPO applied to the OU inside a pair of curly brackets, `{}`.
	- We can correlate the name after executing `Get-DomainGPO -Identity '{GPO Name extracted from the details of the OU}'`