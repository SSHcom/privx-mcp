# Network targets

Network targets let PrivX users reach services or subnets over arbitrary TCP/IP protocols, with access gated by PrivX. Unlike hosts (which define SSH, RDP, Web, and similar session types), a network target authorizes traffic to destinations once the user has an active network session. Traffic from users to those destinations is expected to go through a PrivX router.

Each network target has a unique name, roles whose members may use it, and one or more destinations (single addresses or IP ranges). Destinations may be direct, or mapped through NAT so users connect to virtual addresses that the router translates to real targets.

Users open an allowed network target to start a session, then use their own clients against the destination addresses for as long as that session remains active.

***
Related resource example: `network-target`.
