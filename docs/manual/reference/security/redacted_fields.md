# Redacted fields

These fields are removed from tool responses before the payload is returned. Removal still happens when `raw` is set and when a caller names the field in a field list. A missing path is left untouched. Other fields on the same object stay.

## Hosts

`host-get`, `host-list`, and `host-search`.

| Path                                          | What is removed                 |
| --------------------------------------------- | ------------------------------- |
| `host_certificate_raw`                        | Raw host certificate            |
| `host_certificate`                            | Parsed host certificate         |
| `ssh_host_public_keys`                        | SSH host public keys            |
| `password_rotation`                           | Password-rotation metadata      |
| `password_rotation_enabled`                   | Password-rotation flag          |
| `services[].use_for_password_rotation`        | Service rotation flag           |
| `services[].certificate_template`             | Service certificate template    |
| `services[].db.tls_certificate_trust_anchors` | Database TLS trust anchors      |
| `services[].db.tls_certificate_validation`    | Database TLS validation setting |
| `principals[].passphrase`                     | Principal passphrase            |
| `principals[].use_for_password_rotation`      | Principal rotation flag         |
| `principals[].rotate`                         | Principal rotate flag           |

## Users

`user-get`, `user-list`, `user-search`, and `role-members`. `role-members` returns user records and uses the same removal.

| Path                                        | What is removed                              |
| ------------------------------------------- | -------------------------------------------- |
| `password`                                  | Password                                     |
| `settings`                                  | User settings object                         |
| `authorized_keys`                           | Authorized keys                              |
| `webauthn_credentials`                      | WebAuthn credentials                         |
| `mfa.seed`                                  | MFA seed. The rest of `mfa` stays.           |
| `attributes[]` where `key` is `windows_sid` | That attribute entry. Other attributes stay. |
| `roles[].principal_public_key_strings`      | Public keys on a role nested in the user     |
| `roles[].context.ip_masks`                  | IP masks on a role nested in the user        |

## Roles

`role-get`, `role-list`, and `user-get-roles`. On `user-get-roles`, `context.ip_masks` is removed even when `contextFields` asks for it.

| Path                           | What is removed       |
| ------------------------------ | --------------------- |
| `principal_public_key_strings` | Role public keys      |
| `context.ip_masks`             | Role context IP masks |

`role-create` and `role-update` still accept `context.ip_masks` as input. The value is not returned by the read tools above.

## Access groups

`access-group-get` and `access-group-list`.

| Path                                   | What is removed                         |
| -------------------------------------- | --------------------------------------- |
| `host_certificate_trust_anchors`       | Host certificate trust anchors          |
| `db_host_certificate_trust_anchors`    | Database host certificate trust anchors |
| `winrm_host_certificate_trust_anchors` | WinRM host certificate trust anchors    |

`key_type` stays.

## API targets

`api-target-get` and `api-target-list`.

| Path                                    | What is removed     |
| --------------------------------------- | ------------------- |
| `tls_trust_anchors`                     | TLS trust anchors   |
| `target_credential.basic_auth_password` | Basic-auth password |
| `target_credential.bearer_token`        | Bearer token        |
| `target_credential.certificate`         | Client certificate  |
| `target_credential.private_key`         | Client private key  |

Other `target_credential` fields, including certificate template and subject fields, stay.

## Connections

`connection-get`, `connection-list`, and `connection-search`, only when `raw` is true. The compact connection view does not include `target_host_data` or `user_data`.

The nested host is not passed through the host list above. Only these paths are removed:

| Path                                                           | What is removed                                     |
| -------------------------------------------------------------- | --------------------------------------------------- |
| `target_host_data.host_certificate_raw`                        | Raw host certificate                                |
| `target_host_data.ssh_host_public_keys[].key`                  | SSH host public key material. The key object stays. |
| `target_host_data.ssh_host_public_keys[].fingerprint`          | Fingerprint on the same key object                  |
| `target_host_data.principals[].passphrase`                     | Principal passphrase                                |
| `target_host_data.services[].db.tls_certificate_trust_anchors` | Database TLS trust anchors                          |
| `user_data.mfa.seed`                                           | MFA seed. The rest of `mfa` stays.                  |
| `user_data.attributes[]` where `key` is `windows_sid`          | That attribute entry. Other attributes stay.        |

Flags and settings on the nested host stay, including `password_rotation_enabled`, `certificate_template`, and `services[].db.tls_certificate_validation`.
