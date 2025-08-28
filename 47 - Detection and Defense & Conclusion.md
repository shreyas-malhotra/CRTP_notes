#### Objective - Protect and Limit Domain Admins
- Protect you Domain Admins and minimise the number of Domain Admins in your environment.
	- This is the most sane advice, but it is hard to implement, since it needs a work culture change.
	- The idea is that the DA should not log on to any other machines other than the DCs.
	- There is no need to use DA for daily administrative tasks, we should only use them for emergency scenarios.
	- There should ideally be 2-3 DAs for an organisation with 500 users, one as an emergency, and the second one as a fallback, because Microsoft recommends having a fallback DA.
		- In real environments, every second account has DA access, for both AD and Entra ID. 
	- **AD Security Sin: Never run a service as a Domain Admin. Credential theft protections which we are going to discuss ahead are rendered useless in case of a service account.**
		- In the lab we were running a SQL server service as `svadmin`, who is a DA, this was the root cause for a lot of privilege escalation vectors in the lab.
		- Service account credentials are always present on the host machine, and can always be dumped in clear-text.
		- No EDR, credential guard, or even Protected Users Group is going to save us if we are using Domain Admins to run service accounts!
- How does one limit their DAs?
	- By using the Protected Users Group!
	- Of course there are some issues with using the Protected Users Group, but it is a fantastic piece of technology, and it is very easy to implement (one can do so by just adding users to the Protected Users Group).
#### Protected Users Group
- Protected Users is a group introduced in Server 2012 R2 for "better protection against credential theft" by not caching credentials in insecure ways. A user added to this group has following major device protections:
	- Cannot use CredSSP and WDigest - no more clear-text credential caching
	- NTLM hash is not cached
	- Kerberos does not use DES or RC4 keys.
	- No caching of long term keys.
- If the domain functional level is at least Server 2012 R2, following DC protections are available:
	- No NTLM authentication
	- No DES or RC4 keys is Kerberos pre-auth (No ASREP Roasting)
	- No delegation (constrained or unconstrained)
	- No renewal of TGT beyond initial four hour lifetime, hard-coded and un-configurable "Maximum lifetime for user ticket" and "Maximum lifetime for user ticket renewal".
#### Issues with using the Protected Users Group
- If we have mobile users, who are not always in the line of sight of the DCs at all times, we may have a problem implementing Protected Users Group.
- Needs all domain controllers to be at least Server 2008 or later (requirement for AES based authentication)
- Not recommended by MS to add DAs and EAs to this group without testing the "potential impact" of lock out.
- No cached logon i.e. no offline sign-on.
- Having computer and service accounts in this group is useless, as their credentials will always be present on the host machine.

#### Objective - Isolate administrative workstations
#### Privileged Administrative Workstations
- A hardened workstation only for performing sensitive tasks like administration of domain controllers, cloud infrastructure, sensitive business functions etc.
	- One should obviously not use PAWs for non-sensitive or personal tasks to minimise the attack surface, this includes not opening links, accessing emails or social media from a hardened administrative machine set up for specific sensitive tasks
- Can provide protection from phishing attacks, OS vulnerabilities, credential replay attacks.
- Admin jump servers to be accessed only from a PAW, multiple strategies
	- Separate privilege and hardware for administrative and normal tasks
	- Having a VM on a PAW for user tasks
- The concept of PAWs still exists in the privileged access strategy, but PAWs are not the only thing required to access resources, which are replaced by intermediaries, one of which is PAWs.

#### Objective - Secure Local Administrators
#### Local Administrator Password Solution (LAPS)
- Centralised storage of passwords in AD with periodic randomizing where read permissions are access controlled.
- Even today, a lot of organizations use the same password for the local administrator accounts.
- Using LAPS does not come at any additional cost to the organization.
- When LAPS is used, Active Directory manages passwords for the local administrators on each machine.
- Computer objects have two new attributes - `ms-mcs-AdmPwd` attribute stores the clear text password and `ms-mcs-AdmPwdExpirationTime` controls the password change.
- Storage in clear text, transmission is encrypted.
- Note - with careful enumeration of the read permissions (inbound ACL) on `ms-mcs-AdmPwd`, it is possible to retrieve which users can access the clear text password providing a list of attractive targets!
	- Even with this, LAPS is a fantastic security measure and should be implemented, with consideration.

#### Objective - Time Bound Administration
#### JIT (Just In Time)
- Just In Time (JIT) administration provides the ability to grant time-bound administrative access on a per-request basis.
	- JIT never took off though, Just In Time here means that whenever someone wants access to a resource, they have to ask for it, other PAM tools like CyberArk also provide this functionality.
- JIT is very well implemented in EntraID with PIM (Privileged Identity Management).
	- Of course EntraID is a money making machine for Microsoft, but sometimes when we have a look at it and consider the features EntraID provides in comparison to Active Directory, it feels like a lot of security features are implemented better there.
	- Their PIM implementation address JIT very well, though of course one would need to pay Microsoft per user to actually implement it in their environment.
- Check out Temporary Group Membership! (Requires Privileged Access Management Feature to be enabled which can't be turned off later):
	- `Add-ADGroupMember -Identity 'Domain Admins' -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 60)`

#### JEA (Just Enough Administration)
- JEA (Just Enough Administration) provides role based access for PowerShell based remote delegation administration.
	- If the organisation used PowerShell Remoting for remote administration, as it should, JEA is a god-send.
- With JEA non-admin users can connect remotely to machines for doing specific administrative tasks.
	- Not everyone needs full administrative access, a lot of times, people, groups or services need access to perform specific administrative tasks as simple as listing services on a machine.
	- Using JEA we can actually create PowerShell remoting endpoints, where specified users can connect and use very specific commands.
- For example, we can control the command a user can run and even restrict parameters which can be used.
- JEA endpoints have PowerShell transcription and logging enabled.
- Configuring JEA (Example):
	- `$modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\JEARoles`
	- `New-Item $modulePath -ItemType Directory -Force`
	- `New-ModuleManifest -Path (Join-Path $modulePath "JEARoles.psd1") -Description "Contains custom JEA Role Capabilities"`
	- `$roleCapabilityPath = Join-Path $moduleParh "RoleCapabilities"`
	- `New-Item $roleCapabilityPath -ItemType Directory -Force`
	- `New-PSRoleCapabilityFile -Path (Join-Path $roleCapabilityPath "services.psrc") -Author "Admin" -CompanyName "AltSec" -Description "Allows checking services." -ModulesToImport "Microsoft.PowerShell.Core" -VisibleCmdlets @{ Name = "Get-Service"; Parameters = @{ Name = "Name"}}`
	- `$Group = "dcorp\RDPUsers"`
	- `New-PSSessionConfigurationFile -Path C:\ProgramData\Services.pssc -SessionType RestrictedRemoteServer -TranscriptDirectory C:\ProgramData\JEAConfiguration\Transcripts\ -RunAsVirtualAccount -RoleDefinitions @{Group = @{ RoleCapabilities = 'Services' };}`
	- `Register-PSSessionConfiguration -Name Services -Path C:\ProgramData\Services.pssc -Force`
- If any member of the RDPUsers group, tries to access the DC with PSRemoting, of course they will get access denied, since we do not have admin access on it.
	- `Enter-PSSession dcorp-dc`
	- But if we add the configuration named Services to it, we'd be able to connect to the DC, but only be able to execute the commands explicitly allowed by the JEA configuration.
		- `Enter-PSSession dcorp-dc -ConfigurationName Services`

#### Objective - Detection and Defence
#### ESAE (Enhanced Security Admin Environment)
- Microsoft used to recommend implementing ESAE (Enhanced Security Admin Environment), also known as the Red Forest, for enterprise security.
- However in 2021, they replaced it with the Privileged Access Strategy.
- ESAE
	- ![[Pasted image 20250824215143.png]]
	- Dedicated administrative forest for managing critical assets like administrative users, groups and computers.
	- Since a forest is considered a security boundary rather than a domain, this model provides enhanced security controls.
	- The administrative forest is also called the Red Forest.
	- Administrative users in a production forest are used as standard non-privileged users in the administrative forest.
	- Selective Authentication to the Red Forest enables stricter security controls on logon of users from non-administrative forests.
	- Microsoft retired ESAE in 2021 and replaced it with Privileged Access Strategy, but it is still worth discussing.
- ESAE - Working:
	- ![[Pasted image 20250824215143.png]]
	- We split the administrative machines and users into three tiers, tier 0, tier 1 and tier 2.
	- Anybody from tier 0 should not be able to login to a lower level
	- Anybody from a lower level should not be able to control anything in the levels above
	- Tier 0 includes Domain Admins, Domain Controllers, AD CS etc.
	- To manage tier 0, we set up an ESAE Admin Forest (also called a Red Forest), which will just have one way access, and SID filtering and other similar security features enabled.
	- The administrators are just meant to login from the Red Forest, manage the resources and get away.
	- This is a gross oversimplification of ESAE, it was very complex in nature, and only a handful of organisations actually enabled it.
	- Microsoft's consultants need to be on the team to get ESAE right.

#### Privileged Access Strategy
- ESAE was replaced by Privileged Access Strategy, because of Azure, and it being easier to enforce licensing.
- Privileged Access Strategy is Microsoft's guidance for securing enterprises now.
- It is quoted by Microsoft to be a broader strategy to move towards a Zero-Trust architecture, focusing on verifying explicitly, using least privilege, and assuming breach.
- Privileged Access Strategy includes and focuses on using Azure services, "Cloud is a source of security".
	- This aligns with Microsoft's tendencies to force their customers to use Azure cloud.
- Privileged Access Strategy also includes Rapid Modernisation Plan (RAMP), so that the organisation can adapt these recommendations and pay more in licensing.
- PAS Working:
	- ![[Pasted image 20250824223639.png]]
	- The idea is that for any of the assets, there should be two paths of access, one privileged and one for the users.
	- For both of these paths, there are some potential attack surface areas.
	- If we are trying to access any of the paths, we can use workstations, accounts, intermediaries like VPNs, App Proxies, PAWs, and the interfaces meant to access these; all of these are also to be considered a part of the attack surface.
	- PAS encourages us to have well defined paths to access each asset, with no unidentified way between user level access and privileged access.
		- In some cases, there should be authorised privilege elevation paths, if a user needs to have privileged access.
		- What can be an authorised privilege elevation path?
			- Things like PIM (Privileged Identity Management) in EntraID, where a user can escalate to the global admin for a couple of hours.
- PAS is too complex to be discussed here, but we just want to consider how Microsoft thinks of enterprise security.

#### Enterprise Access Model
- The Privileged Access Strategy also includes an Enterprise Access Model.
- This replaces the tier model discussed earlier.
- ![[Pasted image 20250824225412.png]]
- This model used different planes:
	- Control Plane
		- Addresses access control
		- Identity is the primary control, instead of perimeter based control like network based access control being prioritised
		- Other controls include network, applications and data
	- Management Plane
		- To manage and monitor asset
		- This is what the I.T. team would use
- Both the Control and the Management Plane provide access to the business assets, which are stored in the Data/Workload Plane.
- Data/Workload Plane
	- Assets with business value like applications, data, workload. IP etc. live here
	- There should be a path to get privileged access to the Workload Plane
- User Access Plane
	- Employee Access, Public Access, B2B etc.
	- The user access plane should only be able to access the Data/Workload plane
	- Even in case of user access, there are two types of access:
		- Human Access
		- API Access
- The idea is to have everything split down everything in different categories, and have certain well defined paths, this is very hard to implement, and as such needs Microsoft's consultants onboard to do so.
- There is a reason why even after more than 2 decades of running on-prem AD, Microsoft does not have a simple, effective and well-defined security strategy.

#### Credential Guard (Endpoint-based)
- Credential Guard is an endpoint based protection tool that can be used to protect credentials.
- However, custom SSPs can bypass this.
- It uses "virtualisation based security to isolate secrets so that only privilege system software can access them".
- Effective in stopping PTH and Over-PTH attacks by restricting access to NTLM hashes and TGTs. It is not possible to write Kerberos tickets to memory even if we have credentials if Credential Guard is in place.
- References: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
- Credentials from local accounts in the SAM and Service account credentials from LSA secrets are NOT protected.
- Credential Guard cannot be enabled on a DC as it breaks authentication.
- Only available on Windows 10 and later Enterprise edition, and Server 2016 and later.
- There are bypasses for Credential Guard, but it is still very effective.

#### Device Guard (WDAC) (White-listing)
- It is a group of features "designed to harden a system against malware attacks, its focus is preventing malicious code from running by ensuring only good known code can run"
- It has three primary components:
	- Configurable Code Integrity - configure only trusted code to run
	- Virtual Secure Mode Protected Code Integrity - Enforces CCI with Kernel Mode (KMCI) and User Mode (UMCI)
		- UMCI is something which interferes with most of the lateral movement attacks we have seen.
		- While it depends on the deployment (discussing which will be too lengthy), many well known application whitelisting bypasses - signed binaries like csc.exe, MSBuild.exe etc. - are useful for bypassing UMCI as well.
		- Check out the [LOLBAS project](lolbas-project.github.io).
	- Platform and UEFI Secure Boot - Ensures boot binaries and firmware integrity
- However as we discussed in LO 5 or 7, use WDAC, not AppLocker for whitelisting.

#### MDI
- MDI is implemented to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions directed at your organisation.
- MDI sensors are installed on DCs and Federation servers. Analysis and alerting is done in the Azure cloud.
- MDI can be used for detecting:
	- Recon
	- Compromised credentials (Brute-Force, Kerberoasting etc.)
	- Lateral movement (PTH, OPTH etc.)
	- Domain Dominance (DCSync, Golden ticket, Skeleton key etc.)
	- Exfiltration
- MDI Bypass:
	- The key is to avoid talking to the DC as long as possible and make appear the traffic we generate as attacker normal.
	- To bypass DCSync detection, go for users which are whitelisted. For example, the user account used for PHS may be whitelisted.
	- Also, if we have NTLM hash of a DC, we can extract NTLM hashes of any machine account using netsync
	- If we forge a Golden Ticket with SID History of the Domain Controllers group and Enterprise Domain Controllers Group, there are less chances of detection by MDI:
		- `SafetyKatz.exe "kerberos::golden /user:dcorp-dc$ /domain:dollarcorp.moneycorp.local /id:1000 /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"`

#### Ticket Forging and Replay
- For all the attacks that include Forging or Replaying Kerberos tickets, the easiest detection is - Access to a privileged or higher tier asset from a lower tier.
- Applies on Golden, Silver, Diamond tickets and a lot of other attacks!
- We can easily forge a ticket, but when we are trying to access a high tier asset using it, there may be a chance of detection.

#### Kerberoasting
- Security Event ID:
	- Service Event ID: 4769 - A Kerberos ticket was requested
- Filtering Kerberos Security Events:
	- Since 4769 is logged very frequently on a DC. We may like to filter results based on the following information from logs:
		- Service name should not be krbtgt
		- Service name does not end with $ (to filter out machine accounts used for services)
		- Account name should not be machine@domain (to filter out requests from machines)
		- Failure code is '0x0' (to filter out failures, 0x0 is success)
		- Most importantly, ticket encryption type is 0x17
- Mitigation:
	- Service Account Passwords should be hard to guess (greater than 35 characters)
	- Use Group Managed Service Accounts (Automatic change of password periodically and delegated SPN Management)

#### Deception
- Deception is a very effective technique in active directory defence.
	- By using decoy domain objects, defenders can trick adversaries to follow a particular attack path which increases chances of detection and increase their cost in terms of time.
	- Traditionally, deception has been limited to leave honey credentials on some boxes and check their usage but we can use it effectively during other phases of an attack.
- Only use an enterprise grade deception platform if the organisation has a very good security posture, if their red security assessments (red team/VAPT) are not driven by compliance.
	- We should set up deception only if we want to find out loopholes, not just to check a mark on the checklist.
- What to target? Adversary mindset of going for the "lowest hanging fruit" and illusive superiority over defenders.
- We must provide the adversaries what they are looking for. For example, what adversaries look for in a user object:
	- A user with high privileges
	- Permissions over other objects
	- Poorly configured ACLs
	- Misconfigured/dangerous user attributes and so on
- Let's create some user objects which can be used for deceiving adversaries. We can use [Deploy-Deception](https://github.com/samratashok/Deploy-Deception) for this.
	- Note that Windows Settings|Security Settings|Advanced Audit Policy Configuration|DS Access|Audit Directory Service Access Group Policy needs to be configured to enable 4662 logging.
- Creates a decoy user whose password never expires and a 4662 is logged whenever `x500uniqueIdentifier` - `d07da11f-8a3d-42b6-b0aa-76c962be719a` property of the user is read.:
	- `Create-DecoyUser -UserFirstName user -UserLastName manager -Password Pass@123 | Deploy-UserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- This property is not read by `net.exe`, WMI classes (like `Win32_UserAccount`) and ActiveDirectory module. But LDAP based tools like PowerView and ADExplorer trigger the logging.