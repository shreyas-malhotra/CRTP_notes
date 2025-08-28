![[Pasted image 20250727211343.png]]
- The Silver Ticket attack seems to be the ugly sibling of the Golden Ticket attack.
- We targeted step 3 of Kerberos authentication for the Golden Ticket attack, that is, we forced a TGT and sent it to the DC, however in case of a Silver Ticket attack, we forge a ST/TGS instead.
- For the Silver Ticket attack, we need to acquire AES key or NTLM hash of the target service account, and then forge the ST or TGS, using the secret of the target service account.
- **Difference in Access:** In case of a Golden Ticket attack, we get access to all the resources, that is, any service on any computer in the domain. Whereas, in the case of a Silver Ticket, we get access to a particular service on a particular machine.
- **Difference in Persistence:** For the krbtgt account, the secrets do not rotate automatically, but for the target service account, the secrets may rotate automatically every 30 days by default; and it is more of a direction, than enforcement, in a lot of scenarios the secrets could be set to rotate even earlier than 30 days.
- What is the most common type of account used to run services?
	- The Machine account, for example, if we look at anything that is locally seen as SYSTEM, network service or local service, all of them use the machine account as the service account.
	- In case of the domain, the machine account is represented by the machine name, for example, if there is a machine called `dcorp-ci`, the machine account for it is going to be `dcorp-ci$`.
- Extracting Machine account credentials:
	- When we extract the credentials from a DC, we can see that all the machine account's credentials are present on the DC. These are what are used to encrypt the service tickets.
	- If we have access to a machine account credentials, we can forge Silver Tickets.
	- How do we get access to machine account credentials?
		- By getting administrative access on a machine.
		- When we had access on `dcorp-adminsrv`, and extracted credentials from it using mimikatz, we also came across the credentials for `dcorp-adminsrv$`.
		- If we have the `dcorp-adminsrv$` credentials, we can access a service on that machine as any user, including as a DA.

#### Where do Silver Ticket attacks shine?
- Something that has been repeatedly brought up is how we need to avoid interacting with the DC to maintain OPSEC during the engagements.
- Detection tools like MDI focus specifically on the DC.
- Imagine we are targeting a machine like `dcorp-ci`:
	- Is it a DC?
		- No.
	- Would it be protected by MDI?
		- No. Even if we want, we cannot set it up to be protected by the MDI.
	- Is it then more OPSEC safe to opt for the Silver Ticket attack?
		- Yes, definitely.
- MDI considers ST/TGS (`AP-REQ`) to be so useless, that even if we target a service on the DC itself, MDI is not going to detect our Silver Ticket attack.
- Tools like `SilverFort` detect Silver Ticket attacks on services running on the DC, however if we are not targeting the DC, we should still be fine.

#### Silver Ticket and Optional PAC Validation
- Optional PAC Validation may defeat the Silver Ticket attack, but it is rarely enabled.

#### Forging a Silver Ticket
- Forging a Silver Ticket using Rubeus:
	- `C:\AD\Tools\Rubeus.exe silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:<RC4/NTLM hash of the machine account> /sid:<SID of the domain> /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt`
		- Just like the Golden Ticket attack, the `/ldap` option queries the DC for information related to the user.
		- The only difference between the Golden and the Silver Ticket command options for Rubeus is going to be that the Silver Ticket command requires the SPN (Service Principal Name).
		- The SPN consists of the service name, and the machine name. In the command above, we are targeting `http` on the DC, `dcorp-dc.dollarcorp.moneycorp.local`.
		- What does HTTP allow us to access?
			- The WinRM protocol, which provides access for winrs and PowerShell Remoting.
		- What other services can we target?
			- HOST (provides access to the scheduled tasks etc. on the machine), HOST+RPCSS (provides access to WMI), CIFS (provides access to the File System), LDAP (for the DC, enables us to run the DCSync attack) and many more services.
		- Why do we resort to using RC4/NTLM hash in this case?
			- Using RC4 is acceptable for the service tickets.
			- Because computer accounts, that is, the most widely used service accounts, still use RC4 many times, so using RC4 does not stand out as an anomaly.

#### Learning Objective 9
- If we have any additional lab time:
	- We can try to get command execution on the DC by creating silver tickets for:
		- HTTP
		- WMI (HOST+RPCSS)

#### Practical Demonstration - Forging a Silver Ticket
- First we will list the currently cached Kerberos tickets using `klist`, then we will purge any currently cached tickets.
	- `klist`
	- `klist purge`
	- `klist`
- Forging a Silver Ticket using Rubeus:
	- `C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:<RC4 of the DC's machine account> /sid:<sid of the domain> /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt`
	- Ticket creation can be verified using `klist`, we should now have a service ticket for the Domain Administrator, for the service specified earlier:
		- `klist`
	- Accessing the DC using winrs, now that we have the appropriate privileges using the Silver Ticket.
		- `winrs -r:dcorp-dc.dollarcorp.moneycorp.local cmd`
			- `set username`
			- `exit`
	- However, since the ticket is only for the HTTP service, if we try to list a drive on the DC, it will shows us an access denied error, because we did not perform a Silver Ticket attack for the CIFS service required for this use case.
		- `dir \\dcorp-dc.dollarcorp.moneycorp.local\c$`
			- This command is supposed to fail here.
- Note: Some very aggressive EDRs may have a problem with us even just using `klist`, in which case we can use Rubeus' `klist` option to have the same functionality in an OPSEC friendly way.