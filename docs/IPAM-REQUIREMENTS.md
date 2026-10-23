# IPAM acceptance criteria

The operator-provided Infoblox-style DDI model is the functional baseline. IPAM manages address inventory and allocation intent; it does not route traffic or configure a device merely because an address is recorded.

| Capability | Current implementation and remaining work |
| --- | --- |
| Network views and containers | Separate overlapping spaces, IPv4/IPv6 containers and leaf networks; automatic DDI population currently uses the default view. |
| Automatic population | Configured DHCP subnet masks, conventional reverse-zone prefixes, fixed addresses, gateways and authoritative DNS records. No manual import is required. |
| Address provenance | Source-labelled configured records, operator intent, expiring local and synchronized DHCP observations. A DNS record is not evidence that a device is online. |
| DHCP ranges and exclusions | Inspection shows pools/exclusions; static Next Available skips them and existing allocations/observations using interval arithmetic. |
| Fixed addresses | Managed DHCP reservations populate inventory; an IPAM Reserved record alone does not configure DHCP. |
| Allocations | Revision-checked, durable unique intent writes prevent two simultaneous saves claiming the same address within a view. Next Available is a suggestion until saved. |
| Service provisioning | Existing DNS/DHCP APIs configure their services. Reviewed standalone IPv4 host provisioning with acknowledgement, conditional recovery and native holds is implemented and accepted in isolated local scope; production and broader destinations remain pending. |
| External integration | Reviewed DDI-owned NetBox publication exists; live activation, continuous publication and expanded object mappings remain pending. |
| Physical network discovery | Bounded approved-scope manual TCP, SNMP device/ARP and Azure NIC collectors store timestamped typed observations separately from intent. Isolated qualification is distinct from pending live activation; recorded free space is not a guarantee about unmanaged devices. |
| Device configuration | VM/OS interface, router, VLAN and routing changes require explicit automation or integrations. |

Automatic discovery preserves operator allocations and metadata. It never converts an active DHCP lease, or a lingering DNS record inside an active dynamic pool, into permanent static intent. It does not infer subnet masks from forward DNS alone or merge ambiguous overlaps. Before a separately authorized production transition, back up existing records and verify the intended/observed distinction; this requirement is not evidence that a current transition was completed.

Verification covers empty-store startup, unattended background updates, reservation/DNS evidence, lease expiry, revision stability, operator intent preservation, DHCP pool exclusion, persistence failure, overlap handling, backup/migration and fresh authenticated administrative reads/writes. Remote deployment and active network collectors require their own evidence.
