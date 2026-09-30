# Audit events

PrivX monitoring covers platform activity such as global audit events, sessions (for example by API clients), and instance status. Global audit events record control-plane actions inside PrivX—for example authentication, role and user changes, host changes, API-client lifecycle, and configuration updates. Audit trails for host access live under connections, not in the global audit stream.

Each audit event names the originating microservice and action, and typically includes severity, timestamp, and the acting user and session. Additional fields vary by microservice and event type. There are many named events; treat them as a catalog of discrete actions rather than one fixed payload shape for every entry.

***
Related resource example: `audit-event`, `audit-event-codes`.
