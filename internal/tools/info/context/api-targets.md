# API targets

An API target is an HTTP(S) backend that users reach through PrivX's API proxy rather than as an SSH/RDP session or a network-target tunnel. PrivX checks the caller's roles, then forwards only requests that match authorized endpoints (host, protocols, methods, and paths). Unauthorized endpoints are explicit denials. Each target belongs to an access group and lists the roles whose members may use it.

Users authenticate to the proxy with account-specific API proxy credentials. Members of all directories except the default OIDC directory can use those credentials. OIDC users can access API targets only when Expire Implicit Roles is enabled on their OIDC directory.

A target may present a credential to the backend (for example a token, or an ephemeral certificate). TLS verification against the backend can be skipped. Auditing, when enabled, records proxied API access.

***
Related resource example: `api-target`.
