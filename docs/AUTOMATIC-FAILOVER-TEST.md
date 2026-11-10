# Historical automatic failover test summary

These are historical development-lab results from 12–13 October 2026, not current production acceptance. Deployment inventory, addresses, captures and exact machine receipts remain private. See [current status](DEPLOYMENT-STATUS.md) for the later VMware quarantine and incomplete recovery.

## Initial failure and corrected retest

The initial two-guest test showed new-client allocation from each owner's own sequence and DNS fallback, but no takeover of an existing failed-owner lease and no automatic promotion. Abrupt VM power loss also left an acknowledged lease recorded only as an offer. No duplicate lease was observed; loss of acknowledged protection was a production blocker.

The corrected Linux implementation synchronized the containing directory on journal commit and accepted a staged snapshot only when its hash matched the durable watermark. The historical retest reported three abrupt post-ACK power cuts retaining lease addresses and expirations. An opt-in Hyper-V controller then passed bounded service-failure and VM-power-loss fenced takeover, existing-lease renewal, new allocation, DNS and native promotion. One recovery took approximately 92 seconds including donor boot and access checks; this is a single historical measurement, not a failover guarantee.

The first test's seven distinct allocations and short partition exercise were not exhaustive split-brain, pool-exhaustion or OS-client qualification. Retest evidence does not establish current lab state, current production loaded binaries, redundant controllers, automatic rejoin/failback, destroyed donor disks, regional failures, throughput or every platform crash point. Historical task names and per-host final state are deliberately not operational instructions.

Original administrative sessions were retained through separate fresh SSH privilege and HTTPS administrative checks on the exercised host-source path. Other authorized sources remained untested. Intended lease/authority outcomes were checked separately from login. Future changes require their own affected-source fresh-session and functional checks. See [lab scope](HYPERV-LAB.md), [controller boundaries](HYPERV-FAILOVER.md) and [DHCP implementation](DHCP-SYNCHRONIZATION.md).
