- Think of PowerShell Remoting (PSRemoting) as psexec on steroids, but much more silent and super fast!
- PSRemoting uses Windows Remote Management (WinRM) which is Microsoft's implementation of WS-Management.
	- WS-Management is an industry standard for inventory management.
- Enabled by default on Server 2012 onwards with a firewall exception added to Windows firewall.
- Uses WinRM and listens by default on 5985 (HTTP) and 5986 (HTTPS).
- It is the recommended way to manage Windows Core servers.
- The remoting process runs as a high integrity process. That is, you get an elevated shell.

#### Considerations about using PowerShell Remoting
- If our target organization tracks or logs the usage of PowerShell, we may have to consider evasion techniques as demonstrated in the "Tradecraft" section of this note.
#### Using PowerShell Remoting
- There are two ways of using PowerShell Remoting
- Admin privileges on the remote machine are required to use `PSRemoting`
	- One-to-One
		- `PSSession`
			- Log on interactively to a machine (logon type 3)
			- Interactive
			- Runs in a new process (`wsmprovhost`)
			- Is Stateful
		- Useful cmdlets:
			- `New-PSSession`
			- `Enter-PSSession`
		- We saw earlier that we have access to dcorp-adminsrv, we may get a `PSSession` on it using the following command:
			- `Enter-PSSession dcorp-adminsrv`
	- One-to-Many
		- Also known as Fan-out remoting.
		- Non-interactive.
		- Executes commands parallelly.
		- Useful cmdlets:
			- `Invoke-Command`
		- Using `Invoke-Command`:
			- `Invoke-Command -ScriptBlock($env:computername;$env:username) -ComputerName dcorp-adminsrv`
			- `Invoke-Command -ScriptBlock($env:computername;$env:username) -ComputerName (cat C:\AD\Tools\servers.txt)`
			- We many not want to run commands like `hostname` or `whoami` using Invoke-Command because they are prone to detection.

#### PowerShell Remoting Use Cases
- Checking for local admin access
	- The `Find-PSRemotingLocalAdminAccess` script utilizes PS Remoting to scan for local admin access.
	- The script is an old one and is executing the easy-to-detect `hostname` command, scenarios like these gives us even the more reason to verify the content of scripts before we try to execute them.
- Executing commands or script blocks:
	- `Invoke-Command -ScriptBlock {Get-Process} -ComputerName (Get-Content <list_of_servers>)`
- Executing scripts from files:
	- `Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)`
- Executing locally loaded functions on the remote machines:
	- `Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)`
	- In case we want to pass arguments to the functions, we can use the following command, but only with positional arguments.
		- `Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList`
- Executing "Stateful" commands using `Invoke-Command`
	- `$Sess = New-PSSession -ComputerName Server1
	  `Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process}`
	  `Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}`

#### PowerShell Remoting - Tradecraft
- If our target organization tracks or logs the usage of PowerShell, we may have to consider evasion techniques as demonstrated here.
- PowerShell remoting supports system-wide transcripts, AMSI and deep script block logging, which makes it very prone to detection.
- If we use PowerShell Remoting to execute commands on the DC, MDI (Microsoft Defender for Identity) will detect it.
- If we use PowerShell Remoting to execute commands on other member machines, MDE (Microsoft Defender for Endpoint) will detect it.
- We can use `winrs` in place of PS Remoting to evade system-wide transcription, AMSI and logging (and still reap the benefits of 5985 being allowed between hosts):
	- `winrs -remote:server1 -u:server1\administrator -p:Pass@1234 set computername`
	- If our implicit credentials work, we may be able to skip providing the credentials in the `winrs` command.
- MDI has a problem with `winrs`, but MDE has no issues with it.
- We can also use winrm.vbs and COM objects of WSMan object - https://github.com/bohops/WSMan-WinRM.