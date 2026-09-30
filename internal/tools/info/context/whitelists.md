# SSH command whitelists

SSH command restrictions limit what users may execute on a target SSH account to commands matching whitelist patterns. They apply to the SSH shell (via PrivX restricted shell) and to SSH exec. Prefer native target access control—accounts, groups, file permissions, and sudo—when possible. Use restrictions when the target cannot be reconfigured, or when matched or unmatched commands should generate audit events.

A whitelist has a unique name, a pattern type (`glob` or `regex`), a list of patterns, and an optional comment. Each SSH account may have a default whitelist for all users of that account, plus extra role-based whitelists. A user may run any command allowed by the default whitelist or by a whitelist that matches their roles. Regex patterns must start with `^`. Prefer glob; use regex only when glob cannot express the pattern. Always test patterns so they do not accidentally allow extra commands.

Restrictions are enabled per host account: choose the default whitelist, the login-shell variant (`bash` or `posix`), and policies such as whether unmatched commands are allowed. Commands are split into normalized sub-commands; every sub-command must match. Do not whitelist child shells, directory traversal, or command substitution that can run arbitrary commands. Only members of the `privx-admin` role can manage whitelists.

***
Related resource example: `whitelist`.
