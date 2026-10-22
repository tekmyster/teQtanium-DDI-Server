# Historical Hyper-V development lab

The 12–13 October 2026 lab used two Linux guests on one Hyper-V host with isolated client fixtures. It was a development deployment, not production HA. Exact VM identities, addresses, credentials, administrative source paths, captures and machine receipts remain private. This public guide does not describe the current live topology or authorize changes to any host.

The historical exercises covered native cluster enrollment, DNS zone transfer/resolution, independent DHCP owner allocations and lease replication, shared synthetic security evidence, IPAM reconciliation, service restart and clean VM reboot. The later [automatic failover retest](AUTOMATIC-FAILOVER-TEST.md) covered bounded fenced takeover and post-ACK crash durability. Those outcomes retain their original version, workload and source-path limits.

The guests shared one host, so this lab could not demonstrate host-failure availability. Full OS DHCP lifecycle, all administrative sources, long partitions, pool exhaustion, WAN/load, DHCPv6 and production detection accuracy were not established. A purpose-built wire client is not a complete client interoperability matrix.

For a new authorized lab, allocate isolated test networks and unique identities, retain current authority and backups, verify fresh affected-source authentication/privileges after access changes and preserve original sessions until those checks pass. Recovering a former owner requires a separately reviewed ownership workflow; starting or unfencing it is not failback. See [controller boundaries](HYPERV-FAILOVER.md), [feature status](FEATURE-MATRIX.md) and [current scoped status](DEPLOYMENT-STATUS.md).
