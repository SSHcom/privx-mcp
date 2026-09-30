# Users and roles

PrivX identities are local users or accounts imported from directories (LDAP, Active Directory, or OpenID Connect). Capability is never attached directly to a user: it comes from roles. A user or API client receives every permission of the roles they belong to. All users start in the built-in `privx-user` role; membership in `privx-admin` grants full administration and the ability to connect to any host.

Roles carry named permissions such as viewing or managing users, hosts, connections, workflows, secrets, and audit data. Granting `roles-manage` is effectively superuser-level because it allows assigning any role. Host- and connection-management permissions can be limited to an access group when the role is associated with one; other permissions are global.

Membership is either mapped or explicit. Mapped members are included by the role's rules (filters against directory attributes or groups) and can only be removed by changing those rules. Explicit membership is assigned outside those rules: admins can grant a role to a user directly, or a user can request a role through an approval workflow. Memberships may be time-restricted. A request succeeds only when every required approval is collected; one denial rejects the whole request. Only mapped members of an approver role may decide, and users cannot approve their own requests. OpenID Connect users cannot request role memberships. Changes usually apply within a few minutes.

Separately from management permissions, session access to a host requires that at least one of the user's roles is mapped to a target account on that host. Several roles can share one target account; one role can map to several accounts, and the user then chooses which account to use when connecting.

***
Related resource examples: `user`, `role`, `role-member`, `request (access)`.
