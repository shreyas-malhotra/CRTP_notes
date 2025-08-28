#### Need for, and release of Constrained Delegation
- Microsoft realised that Unconstrained Delegation was not a good look for them, with Server 2008, Microsoft introduced Constrained Delegation.
- We are going to discuss Constrained Delegation specifically with Protocol Transition.
- By 2008, Microsoft's clients had a lot more mobile (not mobile phone, mobile as in tendency to be movable) users, so they would not have the line of sight of the DC most of the time, and if there were web applications that used Kerberos authentication (which there were a lot of), mobile users wouldn't be able to access them.

#### Constrained Delegation with Protocol Transition
- Constrained Delegation allows access only to specified services on specified computers as the authenticated user.
- Protocol Transition is when a user authenticates to a web service without using Kerberos and the web service then makes requests to a DB server to fetch results based on the user's authorisation.

#### Kerberos Extensions used to enable Constrained Delegation
- To impersonate the user, Service for User (S4U) extension is used which itself provides two extensions:
	- Service for User to Self (S4U2self): Allows a service to obtain a forward-able TGS to itself on behalf of a user with just the user principal name, without supplying a password.
	- Service for User to Proxy (S4U2proxy): Allows a service to obtain a TGS to a second service on behalf of the user. Requires the S4U2self ticket beforehand.
		- Which second service?
			- This is controlled by `msDS-AllowedToDelegateTo` attribute, which contains a list of SPNs to which the user tokens can be forwarded to.

#### Authentication Flow
- ![[image 3.png]]
1. A user authenticates to the web server (running with the web service account) using a non-Kerberos compatible authentication mechanism (for example, form based authentication).
	- So the user will use a non-Kerberos authentication mechanism and the web server will transition it to Kerberos authentication, this is why we call it Protocol Transition.
	- The idea was that the web service will accept form based authentication or any other method and then transition the users to Kerberos.
- S4U2self
	2. The web service requests a forward-able ticket (TGS) from the KDC (Key Distribution Center) for the user's account, without supplying a password (thus S4U2self), as the web service account.
	3. The KDC checks if there is Constrained Delegation enabled on the web server, by checking the web service userAccountControl (UAC) value for the `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` attribute, and that the user's account is not blocked for delegation. If both these conditions are satisfied, it returns a forward-able ticket for the user's account. (S4U2self)
- S4U2proxy
	4. The web server then passes this ticket back to the DC, and requests a service ticket (ST) for a specific SPN.
	5. The KDC checks if the SPN is present in an attribute of the web service account (first hop's service account), called `msDS-AllowedToDelegateTo`. If the SPN is listed, it will return a service ticket (ST) for the second hop (DB server in this example) (S4U2proxy).
6. The first hop can now authenticate as the user to the second hop using the supplied TGS.

#### Abuse Vectors - Constrained Delegation with Protocol Transition
- There are two major problems with Constrained Delegation with Protocol Transition:
	- S4U2self does not require the user's password to issue a forward-able ticket. Which means that if the server is compromise, the attacker can just go ahead and request the DC to provide them with a forward-able TGS (as any user, including a DA) to the DC itself.
		- The KDC/DC has no way to verify who initiated the authentication process (It could be a DA, EA or even just a non-privileged user account).
		- The DC here just checks if the first hop is configured for Constrained Delegation, and secondly if the user for whom the TGS is requested is blocked from delegation or not.
		- If we compromise the web server, we can request a ticket to the second hop as any user.
	- In Unconstrained Delegation we at least had to trick or coerce a user to authenticate on the server where it was enabled, but here there is no such requirement, we just need to compromise the web server itself.
- If we have access to the account the service with Constrained Delegation is running as, it is possible to access the services listed in `msDS-AllowedToDelegateTo` of the service account as ANY user.

#### Abusing Constrained Delegation with Protocol Transition
- Enumerate users and computers with Constrained Delegation enabled:
	- Using PowerView:
		- `Get-DomainUser -TrustedToAuth`
		- `Get-DomainComputer -TrustedToAuth`
	- Using AD Module:
		- `Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo`
- Enumeration in Practise:
	- `Get-DomainUser -TrustedToAuth`
		- We will observe that the `websvc` user shows up as a machine with Constrained Delegation enabled, and has the `Trusted_To_Auth_For_Delegation` parameter set under the UAC field, which means Constrained Delegation is configured on it.
		- Is the `websvc` account a service account?
			- Yes because its SPN is not null.
	- We will most importantly see that the `msDS-AllowedToDelegateTo` parameter also shows up clearly defined, which means we can figure out what machine/service we will be able to access by abusing Constrained Delegation on the `websvc` account.
		- The value shows that we can access CIFS (local file system) on `dcorp-mssql` as a DA, if we compromise `websvc`.
		- **Can an attacker modify the `msDS-AllowedToDelegateTo` parameter in the UAC field of the compromised server (first hop)?**
			- Only if we have GenericAll/GenericWrite on the compromised server (first hop).
	- We will observe that we already have the credentials for the `websvc` user, extracted from `dcorp-adminsrv`.
- Performing the attack:
	- We can use the following command to perform the attack (We are requesting a TGT and TGS in a single command):
		- `Rubeus.exe s4u /user:websvc /aes256:<aes256 hash of websvc> /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt`
			- Although it is quite obvious what the flags do from their names, here's a quick pointer:
				- `s4u`: selects the `s4u` Rubeus module
				- `/user`: the service account with Constrained Delegation configured
				- `/aes256`: credentials of the vulnerable service account
				- `/impersonateuser`: the user account we want to impersonate (Default Domain Administrator in this case)
				- `/msdsspn` (msDS SPN): the resource we can get access to by abusing Constrained Delegation
		- `klist`
			- We will see that we have a service ticket (ST) for CIFS on `dcorp-mssql` as the DA.
		- `ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$`
			- This command will of course not execute without the ticket from the attack we just performed.
- Some respite for Defenders:
	- Since the protocol that the ticket can be delegated for, to the second hop, is specified under `msDS-AllowedToDelegateTo`, performing this attack (in this scenario) should only lead to file system access via CIFS, this may not be the case if other protocols are listed under `msDS-AllowedToDelegateTo`.
- Another interesting issue that we have is that the service part of the SPN in the `msDS-AllowedToDelegateTo` field on the first hop is clear-text in nature. Which means that we can go ahead and modify it to whatever we want.
	- We can only change the service name, not the domain computer name in the specified SPN.
	- This means we can have access to any service, as any user, on the machine that Constrained Delegation relays access to!
	- This is disastrous in cases where the access that the service is provided may be low impact in nature, but the machine itself may have a high impact if it gets compromised.
		- An example of this in the lab is:
			- `Get-DomainComputer -TrustedToAuth`
			- We will see that on the `dcorp-adminsrv$` account, there is `msDS-AllowedToDelegateTo` that allows Constrained Delegation on the `TIME` service on `dcorp-dc`.
				- We may smirk and find it idiotic to see that someone has set-up a Constrained Delegation solely for the `TIME` service on the DC, to check the time on the DC machine.
				- However, armed with the knowledge that the service section of the SPN in `msDS-AllowedToDelegateTo` is editable, we can abuse this mis-configuration to get DA privileges on the DC.
				- This issue has been reported to Microsoft, but they claim that Constrained Delegation is working as intended, which implies that this attack vector may not get patched at all.
			- We already have a hash for `dcorp-adminsrv$`, so we will run an elevated CMD shell and perform the attack via Rubeus' S4U module:
				- `C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-adminsrv$ /aes256:<AES256 hash of dcorp-adminsrv$ (first hop)> /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt`
					- `/altservice` is the service we would like to overwrite the original service with, to get access for.
					- Please note that LDAP requests work only for the DC, there is no LDAP service that accepts requests on member servers.
					- When we are looking for the AES256 hash of `dcorp-adminsrv$`, we may come across many different hashes for it, depending on the number of services running on the machine, when evaluating which hash to use, we should focus on the hash's associated SID, `S-1-5-18` is a well known SID for SYSTEM, which is the the machine account in the domain in our case, so we use the hash associated with it.
				- `klist`
			- Once the ticket is injected, we can perform a DCSync attack to extract credentials from the domain.