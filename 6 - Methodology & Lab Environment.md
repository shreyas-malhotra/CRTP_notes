![[Pasted image 20250331140357.png]]

> "It is more likely that an organization has already been compromised, but just hasn't discovered it yet."
#### Assumed Breach
- Assumed Breach is also a part of Microsoft's Enterprise Access model, the Privileged Access strategy, which replaced the legacy ESAE (Enhanced Security Admin Environment) architecure.
- Microsoft argues that focusing solely on Perimeter based security measures is a reactive approach.
- Instead assuming that one's organization is already compromised, but the vector hasn't been detected yet is a proactive approach to security assessment.
- Instead of assuming that there is a trustworthy internal environment, assumptions should be made that a breach has already been made, and no entity or object should be trusted.
- Every user and machine should be treated as a potential adversary and asked to verify their identity.
- Objectives to focus on for the class:
	- Red Teaming
	- Insider Attack Simulation
	- Blue Teaming

#### Insider Attack Simulation
- Insider Attack Simulation is an important part of the Assume Breach Execution Cycle.
- In this class, we are going to use the Assume Breach Methodology on an Active Directory Environment and use internal access available with an adversary to perform further attacks.

#### Attack Methodology
![[Pasted image 20250331141730.png]]
- The Recon phase would be skipped, so that more important aspects of the Attack Methodology life-cycle are stressed upon.
- It being a cyclic process, multiple steps in the life-cycle can be repeated as required.

#### The Lab Environment
![[Pasted image 20250331142307.png]]
- The target Active Directory environment is of a fictional financial services company called 'moneycorp'.
- Moneycorp has:
	- Fully patched Server 2022 machines with Windows Defender.
	- Server 2016 Forest Functional Level.
	- Multiple forests and multiple domains.
	- Fully patched environment as of November 2024.
- Minimal firewall usage so that we focus more on concepts, instead of specific tools or vulnerabilities.\
- moneycorp, although designed to be vulnerable can be claimed to be safer than 90% of production environments being used.
- As a student, we get access to a student VM in the dolllarcorp.moneycorp.local domain.
	- There are multiple machines present on the domain,
	- A child domain (us.dollarcorp.moneycorp.local),
	- And a forest root (moneycorp.local).
	- An external trust with another forest (eurocorp.local)
#### Tips on Evading Detection
- Tools used for the attack process may need modification, gone are the times when a given tool used to work undetected for years.
- Metasploit was one such tool that had to face an issue with rapidly developed signature for detection.
- Focus on techniques and methods, figure out ways that a given technique may get detected, and how it needs to be performed to evade detection.
- If a tool is getting detected, obfuscate it, rebuild it or patch it to evade detection.
- Try not to get careless or lazy while performing red-team operations.