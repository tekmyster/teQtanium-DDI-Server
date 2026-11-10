# teQtanium DDI Server

DNS, IPv4 DHCP, IPv4/IPv6 IPAM and shared security evidence, developed as an alpha fork of Technitium DNS Server. Feature coverage and production qualification vary by workflow; vendor parity and enterprise HA are not established.

The GPL-covered application retains its GPL permissions for all users. Commercial offering terms apply only to separately licensable private components or services; a feature name does not establish a paid gate. See [license and edition policy](LICENSE.md).

Built by Tekmyster Industries, LLC. Fork of Technitium DNS Server — original copyright retained. See LICENSE.md.

---

**Current version: 0.1.0-alpha.4.** See [feature status](docs/FEATURE-MATRIX.md) for implemented capabilities and remaining work.

<img src="docs/branding/teqtanium-original.svg" alt="teQtanium logo" width="96" height="96" />

## Package formats

| Platform | Package |
| --- | --- |
| Windows x64 | Setup ZIP or self-contained portable ZIP |
| Linux x64 / ARM64 | Self-contained tar.gz and systemd installer |
| Windows / Linux / macOS / Raspberry Pi | Portable ZIP or tar.gz; requires the .NET 10 ASP.NET Core Runtime |
| Docker | Loadable Linux x64 image archive and Compose example |

The packaging scripts describe the formats below; this table is not a claim that current public downloads are available. Public binary releases remain held. Locally prepared release candidates include SHA256SUMS. The installers use separate teQtanium services and configuration directories, generate an initial admin credential, and leave host DNS and firewall settings unchanged. Windows setup is unsigned. Existing deployments require the [backup and migration workflow](docs/BACKUP-MIGRATION.md); the alpha installers do not replace them automatically.

## Console

The screenshots below show an isolated demonstration with example data.

![teQtanium IP address inventory](docs/screenshots/ipam.png)

![teQtanium security evidence](docs/screenshots/security.png)

![teQtanium About page](docs/screenshots/about.png)

![teQtanium syslog forwarding](docs/screenshots/syslog.png)

## Capabilities

- Authoritative and recursive DNS, DNSSEC and encrypted DNS transports.
- Distributed IPv4 DHCP allocation across stable owners, with durable offers/leases. The latest synchronization parser repair is locally accepted and undeployed; working automatic recovery remains incomplete and Disabled. Historical Hyper-V tests are lab evidence.
- IPv4/IPv6 IPAM inventory, network views, assignments, utilization and DNS/DHCP reconciliation.
- Previewed publication of managed prefixes and address intent to NetBox; live application activation remains pending.
- Local threat indicators, asynchronous MISP enrichment, shared DNS/DHCP evidence and analyst investigations.
- Explainable tunneling and DGA-pattern suspicion, periodic DNS observations and visible sampling limits.
- Optional Chat Completions-compatible event explanations, including separately operated local GPU model servers. Explanations are advisory and cannot change protection.
- Native configuration backups, migration previews and policy rollback.
- Native [UDP/TCP syslog forwarding](docs/SYSLOG.md) for system/DHCP logs, security events and optional DNS queries.

Predictive intelligence, trained classifiers, learned baselines, DHCPv6 and several HA/IPAM workflows remain in development. Read [the feature matrix](docs/FEATURE-MATRIX.md), [dated deployment status](docs/DEPLOYMENT-STATUS.md) and [security roadmap](docs/SECURITY-ROADMAP.md) before planning a deployment.

## App stores

In Apps, open **App stores** and select **Technitium** to use its existing in-console catalog, or **teQtanium** to visit [tectanium.tekmyster.com](https://tectanium.tekmyster.com). ZIP installation remains available.

![App store choices](docs/screenshots/app-stores.jpg) The teQtanium portal entry does not imply that a hosted catalog has been deployed or verified.

## Documentation

- [Build from source](build.md)
- [HTTP API](APIDOCS.md)
- [Environment variables](DockerEnvironmentVariables.md)
- [IPAM](docs/IPAM.md)
- [DHCP synchronization](docs/DHCP-SYNCHRONIZATION.md)
- [Backup and migration](docs/BACKUP-MIGRATION.md)
- [Optional model assistance](docs/SECURITY-LLM.md)
- [Product UX contract](docs/PRODUCT-UX.md)
- [Original logo and variants](docs/branding/README.md)

## License

See [the edition terms](LICENSE.md), [upstream GPL v3](LICENSE-GPL3), and [license boundaries](docs/LICENSE-BOUNDARIES.md). Existing GPL components retain their GPL license. Original copyright and required attribution are preserved in source headers and [third-party notices](THIRD-PARTY-NOTICES.md). Product versioning is independent of the retained engine compatibility identity used by existing APIs, applications and cluster checks.


## Support the project

If you find teQtanium useful and would like to support its development, you can [support the project on Patreon](https://www.patreon.com/teQtanium). Thank you for your support!
