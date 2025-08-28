#### Mimikatz - Legacy
- Do not be tool dependent, unless that tool is Mimikatz!
- Mimikatz single-handedly changed Microsoft's approach to Windows security.
- Before Mimikatz was released to the public in June 2012, attacks like Golden Ticket or SID History Injection etc. were known but only to a closed circuit of professionals, Mimikatz brought it to the masses! This forced Microsoft's hand to making tons of changes to Windows security.
- The Wired magazine, in 2016, [published a chilling story](https://www.wired.com/story/how-mimikatz-became-go-to-hacker-tool/) about the public release of Mimikatz.
	- I'm not transcribing the story in my notes lulz, but it is a good read regardless, even [the Wikipedia article on Mimikatz](https://en.wikipedia.org/wiki/Mimikatz) mentions a lot of it.
	- A grossly boiled down summary of how Mimikatz was open-sourced: https://xkcd.com/538/

#### Mimikatz - Introduction
- Mimikatz can be used to extract credentials, tickets, replay credentials, play with AD security, and perform many more interesting attacks!
- It is the most widely known red team tool, and is therefore heavily fingerprinted.
- There are multiple tools that implement full or partial functionality of Mimikatz.

#### Mimikatz - Usage
- Dumping credentials on a machine using Mimikatz
	- `mimikatz.exe -Command "sekurlsa::ekeys"`
- Using `SafetyKatz`, to try to avoid fingerprinting (Minidump of LSASS and `PELoader` to run Mimikatz)
	- `SafetyKatz.exe "sekurlsa::ekeys"`
	- Loader.exe is used to run tools like `SafetyKatz` in memory to be able to evade EDR, Windows Defender will tear it apart otherwise.
- From a Linux attacking machine, we can use the Impacket suite instead.

#### Lateral Movement - OverPass-The-Hash using Mimikatz (For Kerberos)
- Pass-The-Hash involves replaying the NTLM hash of a local user, to try to access resources accessible via NTLM authentication.
	- Pass-The-Hash attacks may not work on modern system like Windows Server 2025 or later, where NTLM authentication is more likely than not to be disabled. OverPass-The-Hash may still work though.
- On the other hand, in case of OverPass-The-Hash, we are using a domain user's credentials, to try to impersonate the user and access resources protected by Kerberos.
- Over Pass the hash (OPTH) generates Kerberos tokens from hashes or keys of a domain user. Needs elevation (Run as administrator).
- If we have the AES keys, or NTLM hash (RC4-HMAC) of the domain administrator, we can use the following command to start a process with the ticket of a domain administrator:
	- `SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:dollarcorp.moneycorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"`
	- The above command starts a process with a logon type 9 (same as runas/netonly).
	- Logon type 9 is new credential, in case of logon type 9, if we execute `whoami` in the newly started CMD process, we will still be shown the student user or whatever the current user is, but if we try to access a remote resource, the new credentials will be used.
	- To know more about logon types, we can refer to [this blog post](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).


#### Lateral Movement - OverPass-The-Hash using Rubeus
- We can use Rubeus to perform OverPass-The-Hash attack **without** local administrator access.
	- `Rubeus.exe asktgt /user:administrator /rc4:<ntlm hash> /ptt`
	- However, doing so overwrites our current tickets.
	- The `/rc4` or `/aes256` option can be used to specify the RC4 NTLM hash or Kerberos AES Keys respectively.
- We can also use Rubeus to perform OverPass-The-Hash attack **with** local administrator access, if we want to start a new process with the compromised domain user's privileges.
	- `Rubeus.exe asktgt /user:administrator /aes256:<aes256keys> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`
		- The `/opsec` flag indicates Rubeus to avoid using noisier techniques.
		- The `/createneonly` flag limits the scope of the compromised domain user's privilege to the process initiated.
		- The `/show` flag makes it so that the CMD windows is initialised and shown on screen when the attack is performed successfully.

#### Lateral Movement - DCSync
- To extract credentials from the DC without code execution on it, we can use DCSync.
- To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges for dcorp domain:
	- `SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"`
- By default, Domain Admins, Enterprise Admins or Domain Controller privileges are required to run DCSync.