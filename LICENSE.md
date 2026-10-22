# teQtanium license and edition policy

teQtanium DDI Server is developed by Tekmyster Industries, LLC and derives from Technitium DNS Server by Shreyas Zare and its contributors. Original copyrights and notices are retained. See [third-party notices](THIRD-PARTY-NOTICES.md).

## Domain A: GPL-covered application

The root [LICENSE](LICENSE) and identical [LICENSE-GPL3](LICENSE-GPL3) contain GNU GPL v3. Upstream files, their modifications and previously GPL-distributed files retain their applicable GPL terms and original headers. The existing `Tectanium.WindowsService/Program.cs` and project file remain GPL-covered despite their directory name. Third-party materials retain their own notices, including the Public Suffix List's MPL 2.0 notice.

The commercial thresholds, key policy, SaaS/OEM restrictions and edition descriptions below do not restrict GPL permissions. Organization size, query rate, use of HA/MISP/SSO, and commercial or hosted operation do not by themselves impose an additional proprietary license on GPL-covered code. Do not replace GPL notices or classify existing GPL features as proprietary.

## Domain B: private development and separately licensable components

Reserved commercial paths and the private inventory are defined in [license boundaries](docs/LICENSE-BOUNDARIES.md). These are confidentiality and review rules. A new file, copyright header, folder, service boundary or in-process interface does not by itself establish legal independence from the GPL application. Domain B terms can apply only to components that are independently licensable and supplied under applicable separate terms. This document grants no GPL linking exception or proprietary relicensing right.

## Owner's commercial offering policy

The owner describes the following terms for separately licensable private components and commercial services. They are offering policy, not proof that an implementation, entitlement service, signing identity, support SLA or production capability is available.

| Offering | Intended eligibility and terms |
| --- | --- |
| Community private-component use | Homelab/personal, education/research, and small businesses with fewer than 250 managed IPs AND less than 5,000 DNS qps at the 95th percentile; no key required under the owner's policy |
| Non-profit Enterprise | Verified 501(c)(3) or international equivalent; owner's policy offers unlimited use at no charge, with a free non-expiring key after verification |
| Commercial Enterprise / OEM | Businesses at 250+ managed IPs or 5,000+ qps, MSP/MSSP use and hosted third-party SaaS/OEM use require applicable separate commercial terms for private components/services |

HA, MISP, SSO, signed installers and SLA/support are not made proprietary merely by appearing in an Enterprise offering description. Check [feature status](docs/FEATURE-MATRIX.md) for actual implementation and qualification. Licensing feedback must remain a banner; failure must never stop DNS or DHCP.

Commercial inquiries: licensing@tekmyster.com. Non-profit verification: nonprofits@tekmyster.com. [Tekmyster Industries, LLC](https://tekmyster.com).

## Publication

Reviewed eligible community GPL source may be published publicly. Private components and operational material remain private; commercial publication requires explicit PRIVATE repository verification before every private push. Public binary releases remain held. Publication policy does not revoke previously granted GPL rights. See [license boundaries](docs/LICENSE-BOUNDARIES.md).
