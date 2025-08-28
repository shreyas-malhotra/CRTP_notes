- Enumerate following for the dollarcorp domain:
	- ACLs for the Domain Admins group
	- ACLs where the student X has interesting permissions
- Analyse the permissions for student X in BloodHound UI

#### Enumerating ACLs using the CLI
- `Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -verbose`
	- Each entry shown in the ACL results is an ACE.
	- To analyse the ACE entries, we need to focus on the `ObjectDN` (Object Distinguished Name), `SecurityIdentifier` and `ActiveDirectoryRights`.
	- We read an ACE entry as follows: `SecurityIdentifier has ActiveDirectoryRights on ObjectDN.`
	- `S-1-5-18 has GenericAll on Domain Admins.`
		- `S-1-5-18` is a well-known SID value for `SYSTEM`.