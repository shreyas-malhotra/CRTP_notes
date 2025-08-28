#### BloodHound
> Defenders think in lists, attackers think in graphs!
- Provides GUI for AD entities and relationships for the data collected by its ingestors.
- Uses Graph Theory for providing the capability of mapping shortest path for interesting things like Domain Admins.
- There are built-in queries for frequently used actions.
- Also supports custom Cypher queries.
- BloodHound is very useful for Blue Teamers as well as penetration testers.
- Similar tools to BloodHound are **[PurpleKnight](https://www.semperis.com/purple-knight/)** and **[PingCastle](https://www.pingcastle.com/)**.
- For Red Teaming, BloodHound should be absolutely avoided unless we know what we are doing, because it gets detected quite easily by tools like MDI due to the amount of data it enumerates.
- BloodHound uses collectors and ingestors to enumerate the required data
- There are two free versions of BloodHound, and one paid one, BloodHound Enterprise
	- **[BloodHound Legacy](https://github.com/BloodHoundAD/BloodHound)**
		- BloodHound Legacy is present in the `C:\AD\Tools` directory of the student VM.
	- **[BloodHound CE (Community Edition)](https://github.com/SpecterOps/BloodHound)**
		- We have RO Access to the prep-populated BloodHound CE at https://crtpbloodhound-altsecdashboard.msappproxy.net
		- BloodHound CE is not provisioned in the lab, since it uses significant computational resources
		- We cannot upload data to it, but we can use the pre-populated data to analyse it and run Cypher queries and so on
		- We need to use the credentials for crtpreader@altsecdashboard.onmicrosoft.com from the lab portal - https://adlab.enterprisesecurity.io/

#### Using BloodHound Legacy
- Supplying data to BloodHound Legacy
	- `C:\AD\Tools\Loader.exe -Path C:\AD\Tools\BloodHound-master\BloodHound-master\Collectors\SharpHound.exe -args --collectionmethods All`
- The gathered data can be uploaded to BloodHound Legacy

#### Using BloodHound CE
- Supplying data to BloodHound CE
	- `C:\AD\Tools\Loader.exe -Path C:\AD\Tools\Sharphound\SharpHound.exe -args --collectionmethods All`
- The gathered data can be uploaded to BloodHound CE
- Remember that you have RO access to the shared Web-UI in the lab.
- We can search for specific objects, like the user, "Student1" in the Web-UI, and look up specific information in a graphical and tabular format about it.
- We can also use Cypher queries, both built-in and custom ones.

#### Collecting data stealthily
- To make BloodHound collection stealthy, remove noisy collection methods like RDP, DCOM, PSRemote and LocalAdmin.
- Use the `-ExcludeDCs` flag to minimize detection by MDI, this skips Sessions and SMB enumeration on the DCs:
	- `C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SharpHound\SharpHound.exe -args --collectionmethods Group,GPOLocalGroup,Session,Trusts,ACL,Container,ObjectProps,SPNTargets,CertServices --ExcludeDCs`
	- Enumerating `Session` here could be hit or miss for evading detection.
- It is essential to remove the `CertServices` collection method when using BloodHound Legacy collector.
- MDI is extra noisy about file-share enumeration and session enumeration attempts on the DC.
- What we need to enumerate from the DC are users, ACLs, groups, computers etc.

#### SOAPHound
- The protocol used to make collection requests in BloodHound is LDAP
- We can use SOAPHound for even more stealth.
- SOAPHound talks directly to AD WS (Active Directory Web Services - Port 9389) instead of sending LDAP queries to AD DS, AD WS is the same thing that the AD Module uses.
- SOAPHound allows for stealth with almost no network-based detection (like MDI).
- It retrieves information about all objects (objectGuid=\*) and then processes them, which means limited LDAP queries, and lower chances of endpoint detection.

#### Using SOAPHound
- Build a cache that includes basic information about domain objects
	- `SOAPHound.exe --buildcache -c C:\AD\Tools\cache.txt`
- Collect BloodHound compatible data
	- `SOAPHound.exe -c C:\AD\Tools\cache.txt --bhdump -o C:\AD\Tools\bloodhound-output --nolaps`

#### Consideration of the right tool to use
- Avoid using SOAPHound if the target environment is not mature enough, only use it if you want to be stealthier, since BloodHound provides a more complete set of information, even if its at the expense of OPSEC.
- Prefer using SOAPHound only where the stealth is a primary motive.
- To actually perform operations in a stealthy manner, we need to limit the scans to 5-10 machines for each scan as well to avoid triggering defensive tools, which may take a lot of time in big corporate environments.