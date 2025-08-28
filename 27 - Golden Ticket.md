#### Persistence - Golden Ticket
- Golden Ticket is one of the most popular attacks when it comes to Active Directory.
- It may or may not come in handy during an engagement, but we **should** know about it.
- A golden ticket is signed and encrypted by the hash of krbtgt account, which makes it a valid TGT ticket.
- The krbtgt user hash could be used to impersonate any user with any privileges, from even a non-domain machine.
- As a good practice, it is recommended to change the secret of the krbtgt account twice during a reset, as secret history is maintained for the account.
	- If we submit a TGT and the KDC cannot decrypt it with the current krbtgt secret, it tries decrypting it with the previous one.
	- Microsoft recommends changing the krbtgt secret within 48 hours of compromise, because if the organisation has mobile users that do not have direct communication with the DC, we may want to give them a time period to renew their TGTs.

#### Golden Ticket - Working
![[Pasted image 20250727022230.png]]
- As we discussed earlier, during step 3, almost the only validation done by the DC is verifying if it can decrypt the TGT using the secrets of the krbtgt account.
	- This vulnerability is exactly what the Golden Ticket attack takes advantage of.
- Remember, that we are in the persistence section of the course, that is, we assume we have DA privileges already.
- Before step 3 of Kerberos authentication, and exactly after step 2, we perform a couple of attack steps:
	1. We acquire AES key of the krbtgt account. (the NTLM hash can also be used, but the steps mentioned here will try to present OPSEC friendly techniques where possible.)
	2. We then forge the TGT using AES key of the krbtgt account to get our desired privileges (which generally are DA privileges, since we are considering this attack as a persistence mechanism).
	3. This forged ticket is then sent to the DC, where the only validation performed is checking if the ticket can be decrypted using the krbtgt account's secrets.
	4. The DC responds back with a ST/TGS with DA privileges, encrypted with the target service's secret.

#### Performing the Attack
- Getting the AES key for the krbtgt account:
	- Execute mimikatz (or a variant of it) on the DC as DA to get the krbtgt hash:
		- `C:\AD\Tools\SafetyKatz.exe '"lsadump::lsa /patch"'`
	- To use the DCSync feature for getting AES keys for krbtgt account. Use the below command with DA privileges (or a user that has replication rights on the domain object):
		- `C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync/user:dcorp\krbtgt" "exit"`
	- Using the DCSync option needs no code execution on the target DC.
- There are multiple ways of forging a TGT, Microsoft has been consistently making it harder to use Golden Tickets.
	- The easiest and the best way to forge Golden Tickets is using Rubeus:
		- `C:\AD\Tools\Rubeus.exe golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd`
			- The `golden` parameter is to indicate that we want to perform a Golden Ticket attack.
			- The `/aes256` option is used to specify the AES key of the krbtgt account.
			- The `/sid` option is used to specify the SID of the current domain.
			- The `/user` option is used to specify the user that we would like to forge the ticket for.
				- **Always** forge a ticket for an **active** DA account, not a dormant account, **if** we want to target a DA at all.
				- The DA is tier-0 in terms of security, with even more focus put to it with the use of hybrid identity these days, where in it puts not only the on-prem infrastructure at risk, but also the cloud infrastructure.
			- The `/ldap` parameter is used to request the required information for the attack to take place from the DC, using LDAP.
				- The Rubeus command generates the ticket forging command. Note that 3 LDAP queries are sent to the DC to retrieve the values:
					- To retrieve flags for user specified in `/user`.
					- To retrieve `/groups`, `/pgid`, `/minpassage` and `/maxpassage`.
					- To retrieve `/netbios` of the current domain.
				- If we have already enumerated the values mentioned above, we should specify them manually in the forging command, to be  a bit more OPSEC friendly.
		- The Golden ticket forging command looks like this:
			- `C:\AD\Tools\Rubeus.exe golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA84 8 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:33:55 AM" /minpassage:1 /logoncount:2453 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt`
			- ![[Pasted image 20250727034437.png]]
			- ![[Pasted image 20250727034511.png]]
#### How is a Golden Ticket attack better than DA access?
- A DA account needs to be compliant with the password policy, whereas the secrets of the krbtgt account doesn't.
	- The krbtgt account's secrets don't change by default, unless they are explicitly required to.
	- In real life engagements, we may say krbtgt account's working with the same secrets for even a decade or more.
	- No one touches the krbtgt account either, because of how mission critical it is, and how severe implications changing the krbtgt account's secrets may have.
- We don't even need to be joined to a domain machine, all we need is line-of-sight with network access to the port 8008 (Kerberos). If we have just this much access, we can forge a TGT and access it.
- Can we query the DC to get the last time the krbtgt account's credentials were changed?
	- Yes, if we run `Get-DomainUser`, we get information about the krbtgt account as well, it is the third account on the DC; RID 500 is for the default DA, RID 501 is for the Guest, and RID 502 is for the krbtgt account.
- The persistence timeline for a Golden Ticket attack is very long, even if we assume that an organisation is following Microsoft's recommendations of changing the krbtgt account's credentials every 6 months, it is still very long in terms of a persistence timeline.