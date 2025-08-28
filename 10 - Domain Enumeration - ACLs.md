#### Access Control Model
- ACLs are at the core of the Access Control Model.
- ACLs enable control on the ability of a process to access objects and other resources in AD based on:
	- Access Tokens (Security context of a process - Identity and Privs of the user and the object we are trying to access)
	- Security Descriptors (SID of the owner, Discretionary ACL (DACL) and System ACL (SACL)).
- Everything in Windows has an ACL which commands how one is able to access it.

#### Real-life example of ACLs
- For example, when we try to enter our office with an ID card, the card has your identity and your privileges, i.e. the areas of the office you have and do not have to access to.
- When we present the card to a card reader, the card reader would have lists based on which they determine who has access to what area, and verify that your access is denied or blocked, along with optionally logging your access attempt.

#### Access Control List (ACL)
- It is a list of Access Control Entries (ACE) - ACE corresponds to individual permission or audit's access, which specifies what permissions does one have, and what actions one can perform.
- There are two types of ACLs:
	- Discretionary ACL (DACL) - Defines the permissions a user or group has for an object
	- System ACL (SACL) - Logs success and failure of access attempts
- ACLs are vital to AD Security.
- An access denied (blacklisting) entry takes precedence when evaluating permissions of a user or group during ACLs.
![[Pasted image 20250605011647.png]]
- Thread A gets denied because of a Access Denied (blacklisting) rule in ACE 1.
- Thread B gets Write access via ACE 2's Write permission for Group A. It also gets Read and Execute permissions due to ACE 3, which allows Read and Execute permissions to everybody.

#### ACL Permissions Mind-map
- The Mind-map defines what actions we can take over each type of objects if we have a specific permission type for them.
![[Pasted image 20250605202213.png]]
- The ACLs define the role and privilege of a user, we can say that the ACLs are what make the Domain Admin the Domain Admin.
- In the properties of a user entity, under the Security tab > advanced option, the first tab "Permissions", is the DACL, which is a list of ACEs.
	- Example DACL Entry: `Type: Allow, Principal: SYSTEM, Access: Full Control, Inherited from: None, Applies to: This object only`
- The "Auditing" tab on the other hand is the SACL, which logs success or failure state for actions on this object.

#### Importance of ACLs for Attackers
- Decades ago a method of persistence used to be adding a user to the Domain Admins Group for the domain, but it is not an effective persistence measure now.
- Instead of adding a user to the Domain Admins Group, we can instead provide full control of the Domain Admins Group to a user we already control, like "Student X".
- We may not now be a member of the Domain Admin Group, but now we may have a `GenericAll` permission set on a Group, which allows us to:
	- Add/Remove Members
	- Add Ownership
	- Reset Password of Members
	- Grant Rights (including GenericAll)
- The `Add/Remove Members`, and `Reset Password of Members` functionalities in the ACL now enable our low-level user "Student X" to Add or remove a user from the Domain Admins Group, as well as Reset the Passwords of Domain Admins.
- ACL relationships also show up in BloodHound as `Inbound Object Control` and `Outbound Object Control`.
	- Inbound Object Control - "Who has control on me?"
	- Outbound Object Control - "Where do I have control?"
- To note that `Student 1` is a member of the group `RDPUSERS`, which has many interesting roles.

#### Is adding an ACL to the Domain Admins group a valid mechanism for persistence?
- SDProp (Security Descriptor Propagation) is a sanitization mechanism on Domain Controllers.
- There is a set of high value groups, called the `Protected Groups`.
- There is a special container called `AdminSDHolder`, the ACL of `AdminSDHolder` overwrites the ACL of all the protected groups and members each hour by default, which means that adding ACLs to the Domain Admins group is not a valid mechanism for persistence.

#### ACL Enumeration
- Get the ACLs associated with the specified object
	- `Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs`
	- The command can be run against a name, a prefix and even a distinguished name.
-  Get the ACLs associated with the specified prefix to be used for search
	- `Get-DomainObjectAcl -SearchBase "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose`
- Get the ACLs associated with the specified path
	- `Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"`
- Enumerating ACLs using the AD module (doesn't resolve GUIDs)
	- `(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access`
- Since there are thousands of ACLs in an environment, we need to filter out ACLs that may be of interest to us.
	- `Find-InterestingDomainAcl -ResolveGUIDs`
	- The best way to enumerate interesting ACLs is to use `BloodHound`'s graphs.