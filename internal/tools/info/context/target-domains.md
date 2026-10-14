# Target domains

A target domain is an AD or Entra directory that PrivX scans for accounts whose passwords it rotates. A managed account is a scanned directory user that PrivX manages: its username and password live once on the domain and every host that connects as that account reuses them, so one rotation reaches all of those hosts. An explicit account stored on a single host keeps its own password and is a separate object.

Setup order: create a password policy (`password-policy-*`), create the domain with at least one endpoint (`target-domain-create`), run `target-domain-scan` so PrivX reads the directory, then turn a scanned user into a managed account with `target-domain-managed-account-create`.

An endpoint is either AD/LDAP (address, base DN, bind account, user filter) or Entra (tenant, application id, client secret). Use one kind per domain, because AD and Entra store different values for the same attributes. Scan priorities must be unique; the scan reads endpoints in priority order and stops at the first success. Rotation priority is an integer that picks where password changes are written (the UI shows Primary, Secondary, or Disabled), and at least one endpoint must be used for rotation. Bind passwords and client secrets are write-only: send them on create or update, and list and get strip them. The `target-domain` example shows both endpoint shapes.

A managed account has rotation on or off, a password policy, and optional explicit checkout; set them with `target-domain-managed-account-create` and change them with `target-domain-managed-account-update`. List and get omit checkout password versions. `target-domain-managed-account-rotate` starts a rotation under the account's policy and does not return the new password.

`target-domain-managed-account-checkout` returns the latest password for the account under the named domain only. Pass the domain id and either the account id or a username containing `@`. It works only when explicit checkout is on and the account is already added to a host with a role. With a rotate-on-release policy, releasing the last checkout rotates the password again. Call it only from a client allowed to see secrets, and keep the password out of logs, tickets, and chat.

Password-free login is configured on the host with `host-create` or `host-update` (`hosts-manage`): the host account's `target_domain` names the domain. Those tools accept only `principal` and `roles` per principal, and sending `principals` rebuilds every account, so a stored `target_domain` is dropped. Leave such host accounts unchanged until the hosts tools accept `target_domain`.

Keep accounts that people use to sign in to PrivX itself outside the scanned subtree, so rotation cannot change their passwords.

All target domain tools are: `target-domain-list/get/view/create/update`/`delete`/`scan` and `target-domain-managed-account-list/get/create`/`update/rotate/checkout`. If a tool is not available, it was filtered due to configuration.

---

Related resource examples: `target-domain`, `managed-account`.