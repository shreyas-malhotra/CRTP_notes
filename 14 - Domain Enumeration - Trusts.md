#### Domain Trusts
- In any AD environment, a trust relationship is between two domains or forests.
- It allows users from one domain or forest to access resources in the other and vice versa.
- A trust can be automatic (parent-child, same forest etc.) or explicitly established (forest, external).
- TDOs (Trusted Domain Objects), represent trust relationships in AD.

#### Attributes of Trusts
- Trust Direction
	- One-way Trusts: In the case of a one-way trust, the direction of access is always opposite to the direction of the trust. If the trust is from the trusting domain to the trusted domain, direction of access would be the other way around.
		- ![[Pasted image 20250608125910.png]]
	- Bi-directional Trusts: In Bi-directional Trusts, users from both the domains can access resources from each other.
		- ![[Pasted image 20250608130002.png]]
- Transitivity
	- Transitivity in Algebra refers to the property of `if a=b & b=c; then a=c`, this here means that if Domain A has a bidirectional trust with Domain B, and Domain B has a bidirectional trust with Domain C; this means that Domain A also transitively has a bidirectional trust with Domain C.
	- As an attacker it means that if Domain C has been compromised, we can go from it to Domain B, and then to Domain A. 
	- ![[Pasted image 20250608130352.png]]
	- Transitive: Can be extended to establish trust relationships with other domains.
		- All the default intra-forest trust relationships (Tree-root, Parent-Child) between domains within the same forest are transitive two-way trusts.
	- Nontransitive: Explicitly established (external) trusts are generally nontransitive in nature. Nontransitive trusts cannot be extended to other domains in the forest. Nontransitive trusts can be two-way or one-way.
		- This is the default trust (called external trust) between two domains in different forests when their forests do not have a trust relationship.

#### Types of Trusts
- Default/Automatic Trusts
	- Parent-child trust
		- It is created automatically between the new domain and the domain that precedes it in the namespace hierarchy, whenever a new domain is added in a tree. For example, `dollarcorp.moneycorp.local` is a child of `moneycorp.local`; and `us.dollarcorp.moneycorp.local` is a child of `dollarcorp.moneycorp.local`.
		- This trust is always a two-way transitive trust.
	- Tree-root trust
		- ![[Pasted image 20250608134705.png]]
		- When a new Domain tree is added to a Forest root, a Tree-root trust is created automatically between them.
		- This is an intra-forest trust, which means since the two domain tree's are at the forest root, within a single forest, the trust is always a two-way transitive trust.
		- As an attacker, we can compromise any domain in the second domain tree if we have compromised any domain in the first domain tree, and so on.
		- We should remember that the forest is the security boundary, which means even if a single domain in the entire forest is compromised, we can potentially compromise the whole forest.
- External Trusts
	- ![[Pasted image 20250608140315.png]]
	- An External trust is a trust relationship between two domains of different Forests, where at least one of the domain is not a Forest root, and the forests do not have a trust relationship.
	- A trust relationship between Forest root domains is known as a Forest trust, it is not known as an External trust.
	- External trusts can be one-way or two-way and are non-transitive.
	- An External trust is always explicitly established.
	-  The Forest is the security boundary, if the child domain in Forest 2 is compromised, it may lead to the compromise of its parent domain, but exposure to domains in Forest 1 would still be limited since only explicitly shared resources would be accessible, even to any of the Domain admins.
		- The best an attacker can do in this scenario is just to enumerate.
- Forest Trusts
	- If there is a trust relationship between forest root domains, it is called a Forest trust.
	- If we want, we can configure a Forest trust to be transitive, which means a domain in Forest 1 can access resources across another domain.
	- ![[Pasted image 20250608204158.png]]
	- There is no implicit trust in Forest trusts, which means if Forest 1 and Forest 2 have a bidirectional transitive trust, and Forest 2 and Forest 3 have a bidirectional transitive trust, Forest 1 and Forest 3 will NOT have an implicit trust.
	- Forest trusts are lenient (less secure) than External trusts because we can configure transitivity across Forest trusts.

#### Can we go from a domain on Forest 2 to a domain on Forest 1 and then move within Forest 1?
- We cannot do that unless we are in a scenario where we have access to a resource on the compromised domain in Forest 1 that enables us to PrivEsc, for example, provides us with credentials for the Domain Admin for Forest 1.
- This is because external trusts are not transitive, unless we provide explicit credentials to move in Forest 1, we would not be able to move within Forest 1.
- Let's assume there is a share called "files" on the domain in Forest 2, unless the ACL of the "files" share allows users from the domain present in Forest 1, they won't be able to access it. Only explicitly specified resources can be accessed.

#### Note on AD Forest Deployments
- Ideally there should never be a single forest environment for multiple domains, whenever we think of AD we should think of the environment in terms of a Forest, because the forest is the security boundary.
- A single forest should not be used for multiple domains, any organization that needs more than one domain should go for multiple forests, so that they can cut down on implicit attack paths.
- Mature organizations may have multi-forest environments, but a single forest environment is still the most common form of deployment.
- The most secure to allow access over multiple forests is External trusts, even though it leads to a lot of I.T. overhead.
- Forest trusts are lenient (less secure) than External trusts because we can configure transitivity across Forest trusts.

#### Is a Forest compromised if any domain present in it is compromised?
- Essentially yes, since even if we try to isolate the compromised domain and change its credentials, the attacker would already have the credentials from the other domains, there is a race condition here.
- The only way to get trust back in your forest is to rebuild it.
- A lot of organizations have tried to resecure their compromised forests, but the trust in the forest remains shaky, and the deployment of such a forest depends on the risk appetite of the organization.

#### Is it beneficial to have a disconnected DC which syncs after a specific amount of time as a backup/fallback DC?
- Not really, since it would have the same credentials, but there are specific cases where it might be helpful, for example, an organization affected by a ransomware attack had their whole domain credentials encrypted by the ransomware, but were able to leverage a disconnected DC (due to power failure at that specific time) to retrieve the required credentials in an unencrypted format.

#### What should an organization do in case of a full Forest compromise?
- Start from scratch
- Start from a backup: Bring in experts to help establish a timeline and recover from a backup

#### Is this issue not present in AAD (Azure AD)?
- There is nothing that brings you back from a Global Administrator compromise, which is the topmost role in EntraID.
- In case of AD and Domain Admins/Enterprise admins, you may have a hammer to smash the servers with, or be able to unplug them, you can't even do that w/ the cloud!
- If you're using hybrid identity, and my Domain Admin, or Enterprise Admin or Global Admin gets compromised, pivot your job to farming! :)
- Hybrid identity are an unimaginably complicated mess of identities from your cloud and on-prem deployments.

#### Enumerating Trusts
- BloodHound
	- BloodHound can also be used to map the trusts between on-prem and AD.
	- We can use the `Map Domain Trusts` Cypher query.
		- 1 `MATCH p=(n:Domain)-[:TrustedBy]->(m:Domain)`
		- 2 `RETURN p`
		- 3 `LIMIT 1000`
- PowerView
	- Get a list of all domain trusts for the current domain
		- `Get-DomainTrust`
			- The `TrustDirection` field shows the direction of the trust.
			- The `TrustAttributes` field shows whether the trust is an External trust or not.
				- `WITHIN_FOREST` means that the trust is not an external trust, whereas `FILTER_SIDS` means that the trust is an external trust.
		- `Get-DomainTrust -Domain us.dollarcorp.moneycorp.local`
- AD Module
	- Get a list of all domain trusts for the current domain
		- `Get-ADTrust`
		- `Get-ADTrust -Identity us.dollarcorp.moneycorp.local`

#### Enumerating Forests
- PowerView
	- Get details about the current Forest
		- `Get-Forest`
		- `Get-Forest -Forest eurocorp.local`
	- Get all domains in the current Forest
		- `Get-ForestDomain`
		- `Get-ForestDomain -Forest eurocorp.local`
	- Get all global catalogs for the current Forest
		- `Get-ForestGlobalCatalog`
		- `Get-ForestGlobalCatalog -Forest eurocorp.local`
	- Map trusts of a forest (no Forest trusts in the lab)
		- `Get-ForestTrust`
		- `Get-ForestTrust -Forest eurocorp.local`
- AD Module
	- Get details about the current Forest
		- `Get-ADForest`
		- `Get-ADForest -Identity eurocorp.local`
	- Get all domains in the current Forest
		- `(Get-ADForest).Domains`
	- Get all global catalogs for the current Forest
		- `Get-ADForest | select -ExpandProperty GlobalCatalogs`
	- Map trusts of a forest (no Forest trusts in the lab)
		- `Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne $null'`