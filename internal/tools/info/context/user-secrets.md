# User secrets

A secret is named data stored on the PrivX Secrets page. Name is unique. Access is a scope plus roles: Personal means the creator can read and modify it; Global means only the read-access and write-access roles can. These tools use the same inputs for both. Omit `user_id` for global (`/vault/api/v1/secrets`). Set `user_id` for personal (`/vault/api/v1/user/{userID}/secrets`). `owner_id` is set only on the personal call, from `user_id`, and is omitted from the global request rather than sent as `null`.

Secret data defaults to a JSON object. Custom secret types are a Settings → Secrets Vault schema (`settings-view` and `settings-manage`) and are not these tools. `data` is that object.

PrivX administrators can view and manage Personal secrets, so they are not a place for credentials that should stay private to one person.

PrivX permissions, as the product defines them: `vault-add` allows adding secrets. `vault-manage` allows adding, deleting, changing metadata and contents, listing, and viewing metadata. Any PrivX user can create a Personal secret; `vault-add` is what allows a secret that grants read/write roles.

MCP tool mapping: `user-secret-create` requires `vault-add`. `user-secret-list`, `user-secret-get`, `user-secret-update`, and `user-secret-delete` require `vault-manage`. The tools are absent until sensitive data tools are enabled, and read-only mode still drops create, update, and delete.

***

Related resource example: `user-secret`.
