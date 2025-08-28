- There is much more to Active Directory than "just" getting Domain Admin.
- But now that we have Domain Admin privileges, new avenues of persistence, escalation to Enterprise Admin, and attacks across trusts open up.
- Let's have a look at abusing trust within domain, across domains and forests, and various attacks on Kerberos.

#### OPSEC considerations after getting Domain Admin
- Using Domain Admin privileges in an engagement is not OPSEC-friendly, and should be avoided if OPSEC is a consideration.
- The moment we try to compromise a Domain Admin, we are putting the entire engagement in danger, don't go for it, it's not worth the risk.

#### Persisting Domain Admin Privileges
- However, if we want to compromise the Domain Admin, let's take a look at how we can hold onto it.
	- Let's learn persistence as a concept, from politicians who try to do everything they can to hold onto their privileges.

#### About Kerberos
- Kerberos is the basis of authentication in a Windows AD environment.
- Clients (programs on behalf of a user) need to obtain tickets from Key Distribution Center (KDC) which is a service running on the domain controller. These tickets represent the client's credentials!
- Therefore, Kerberos is understandably a very interesting target for abuse!

#### Kerberos Architecture
![[Pasted image 20250726220728.png]]
- The way Kerberos works is that:
1. A client, on behalf of a user sends a timestamp which is encrypted with the secret (AES Key/NTLM Hash) of the user; to the Key Distribution Center or the Domain Controller.
	- Can the DC decrypt the timestamp at this stage? Yes, because it has access to all the secrets in the domain.
	- The DC decrypts the timestamp, matches it with the clock, and responds back with a TGT (Ticket Granting Ticket).
2. The TGT is signed and encrypted using the secret of a special account on the DC, called the krbtgt account; and delivered to the user (AS-REP).
	- Can the client decrypt the TGT? No, since the client does not have access to the krbtgt account.
3. The client send the encrypted TGT back to the DC, as a sign of possession (possession of the TGT here means that the client is authenticated), and requests a TGS ticket, also called a service ticket (ST). (TGS-REQ)
	- The DC receives the encrypted TGT, and almost the only validation that it does on the TGT is to check if the DC can decrypt the TGT (which can only be done using the secret of the krbtgt account).
	- If the TGT can be decrypted, the DC assumes that almost everything written in the TGT is valid.
4. The DC responds back with a ST/TGS, encrypted using the target service account's secret (AES Key/NTLM Hash).
	- The client now receives the service ticket (ST) or the TGS.
5. The client connects to the server hosting the target service and presents the ST/TGS. (AP-REQ)
	- Can the target service decrypt the TGS? Yes, because it has access to its own secrets, which were used to encrypt the TGS/ST.
	- The target service decrypts the TGS, and determines the access level.
	- Authorisation is determined by the target service.
	- Authentication is determined by the DC.
6. (Optional) Optional Mutual Authentication: There is an optional step 6 to avoid sending tickets to a rogue application server.
- **Note: A fun thing to observe is that all the steps from 1 to 5 are vulnerable to different types of attacks!**
#### PAC Validation
- (Optional) Optional PAC Validation can occur between the DC and the Application server.
	- PAC here stands for Privileges Attribute Certificate.
	- PAC contains the information that can be used to verify if the user/client is what they are claiming to be in the TGS.
	- If PAC Validation is enabled, Authorisation is determined by the DC as well.
	- PAC Validation is rarely enabled in production environments, because PAC Validation requests have the potential to hog resources on the DC.
	- If PAC Validation is enabled, PAC is a part of the Kerberos ticket that is sent for validation to the DC.