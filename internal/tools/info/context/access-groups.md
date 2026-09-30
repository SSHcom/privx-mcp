# Access groups

An access group is a partition of PrivX targets—hosts and similar resources—so that management of those targets can be delegated to specific roles instead of applying globally. A role associated with an access group has its host- and connection-management permissions limited to targets in that group; other permissions remain global.

Each host belongs to one access group. Cloud-imported hosts take the group from tags `privx-access-group` or `privx-access-group-id`; script-deployed hosts are registered into a group.

A subadmin is a user whose role is bound to an access group and carries `access-roles-manage` and `roles-view`, plus view and manage permissions for the target types in that group (for example `hosts-view` and `hosts-manage`). Within the group they can manage permissionless roles and map them to targets so team members can connect, but they cannot grant PrivX administration permissions. `roles-view` is global: it shows all roles in PrivX, not only those in the group.

***
Related resource example: `access-group`.
