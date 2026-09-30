# Hosts

A PrivX host is a known connection target: a machine or service users can reach through PrivX. Each host entry holds basic identity (name, address), one or more services that define how to connect, and accounts that define who may connect and as which identity on the target. Hosts can be added manually, imported from cloud directories via tags, or registered with a deploy script. Users only see and can open hosts their roles authorize.

Services describe the access method—commonly SSH, RDP, or Web, and also VNC or database. Accounts map PrivX roles to target identities. An account may be a fixed username (explicit), the user's directory login (personal Unix or Windows name), or a username the user supplies when connecting. Several roles can share one target account; one role can map to several accounts.

Hosts that PrivX cannot reach directly can be addressed through Extenders or similar gateways so traffic is relayed into protected networks. When auditing is enabled on a host, administrators can review recordings of completed sessions. PrivX may also check whether known targets are reachable.

***
Related resource examples: `host`, `connection`.
