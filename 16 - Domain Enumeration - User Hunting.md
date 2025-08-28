#### Need for Hunting Users
- All the enumeration we have done up until enumerating trusts, with an exception of enumerating shares has been relatively silent, with less chances of triggering any detection tools since we were talking to the DC like a normal user, but user hunting is a noisy and greedy process from a Red Team perspective.
- The foothold user that we have, student X, does not have Local Administrator access on our foothold machine.
- However, it is possible that student X has Administrator access on other machines, it is possible that our foothold user doesn't have privileged access on our foothold machine, but has administrative access on other machines.

#### User Hunting for Local Admin Access
![[Pasted image 20250610010400.png]]
- Find all machines on the current domain where the current user has local admin access
	- `Find-LocalAdminAccess -Verbose`
- This function queries the DC of the current or provided domain for a list of computers (`Get-NetComputer`) and then use multi-threaded `Invoke-CheckLocalAdminAccess` on each machine.
- This can also be done with the help of remote administration tools like WMI and PowerShell remoting. Pretty useful in case the ports used by `Find-LocalAdminAccess` (RPC and SMB) are blocked.
- See `Find-WMILocalAdminAccess.ps1` and `Find-PSRemotingLocalAdminAccess.ps1`.
- This process is not silent, since on each machine in the domain, we will leave a 4624 (logon) and a 4634 (logoff) log, and if we do find admin access, we will leave a 4672 log as well.
- Leaving 4624 and 4634 on a large number of machines in rapid succession will lead to detection, to avoid that we can:
	- Run the script on a set of machine at a time, instead of all at once.

#### User Hunting for Active Sessions
- A session here means that a Domain Admin is either interactively logged on (using RDP or other services), or in some way where we can extract the credentials of the target user (in this case the Domain Admin).
- Hunting active sessions is also noisy in a similar fashion to hunting local admin accounts, and the script executes in a similar fashion, that is querying for computers in the domain, and then enumerating active session and logged on users for each machine in the domain individually.
- Enumerating Active Sessions leaves the usual 4624 (log on), 4634 (log off) and 4672 logs left behind while enumerating local admin users, as well as triggers the MDI sensor since in this case the list of computers includes the DC itself at the top of the list, and enumerating the active sessions and logged on users on the DC is extremely noisy and non-preferable. The MDI detection shows up as "User and IP address reconnaissance (SMB)".
- To avoid detection we can simply exclude the DC from the list of machines we want to scan for active sessions.
- ![[Pasted image 20250610173728.png]]
- Find computers where a domain admin (or a specified user/group) has sessions
	- `Find-DomainUserLocation -Verbose`
	- `Find-DomainUserLocation -UserGroupIdentity "RDPUsers"`
	- This function queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using `Get-DomainGroupMember`, gets a list of computers `Get-DomainComputer` and list sessions and logged on users `Get-NetSession`/`Get-NetLoggedon` from each machine.
- Find computers where a domain admin session is available and current user has admin access (uses `Test-AdminAccess`).
	- `Find-DomainUserLocation -CheckAccess`
- Find computers (File servers & Distributed file servers) where a domain admin session is available.
	- `Find-DomainUserLocation -Stealth`
- Note that for Server 2019 and onwards, local administrator privileges are required on remote machines to list sessions (basically to use `Find-DomainUserLocation`).

#### User Hunting for Active Sessions using `Invoke-SessionHunter` instead (does not require local admin access on remote machines like `Find-DomainUserLocation` does)
- List sessions on remote machines (https://github.com/Leo4j/Invoke-SessionHunter)
	- `Invoke-SessionHunter -FailSafe`
	- Above command doesn't need admin access on remote machines. Uses Remote Registry and queries `HKEY_USERS` hive.
	- An OPSEC friendly command would be (avoid connecting to all the target machines by specifying targets)
		- `Invoke-SessionHunter -NoPortScan -Targets C:\AD\Tools\servers.txt`
		- As should be common knowledge by now, avoid enumerating the DC directly, especially using SMB, so remove any DCs from the servers.txt file.