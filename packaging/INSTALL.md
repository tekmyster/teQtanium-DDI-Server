# Install teQtanium DDI Server

This guide describes alpha package formats; it is not evidence that a current download exists. Public binary releases remain held. A separately authorized private candidate must have an exact manifest, relevant acceptance and a deployment plan before installation. [Dated status](../docs/DEPLOYMENT-STATUS.md) distinguishes local source from deployment acceptance.

These alpha packages contain the teQtanium application, not server configuration or model weights. Verify SHA256SUMS before installation. Export a backup before changing an existing deployment.

| Download | Use |
| --- | --- |
| Windows x64 setup ZIP | Extract and run the setup executable as an administrator on an isolated Windows host. |
| Windows x64 portable ZIP | Extract and run DnsServerApp.exe. Includes its .NET runtime. |
| Portable ZIP or tar.gz | Windows, Linux, macOS and supported Raspberry Pi devices with the .NET 10 ASP.NET Core Runtime installed. Run start.cmd or start.sh. |
| Linux x64 / ARM64 tar.gz | Extract and run DnsServerApp with a separate configuration directory. Includes its .NET runtime; distribution dependencies such as ICU are still required. |
| Docker image archive | Load with docker load; use the included Compose example. |

The Windows installer registers the TectaniumDDI service, uses Program Files for binaries and ProgramData for configuration, and binds its console to 127.0.0.1:5380. It creates a random initial admin credential in the protected configuration directory. Read initial-admin-password.txt as an administrator, then sign in and set your preferred credential. It does not change adapter DNS or firewall rules. Existing deployments and occupied service ports are rejected. Configuration is retained on uninstall.

The Linux installer creates tectanium-ddi.service with a dedicated service account, separate application/configuration/log directories and a console on 127.0.0.1:5380. Connect through an SSH tunnel to reach that loopback console. The initial admin credential is in /etc/teqtanium-ddi/initial-admin-password.txt. Existing services are not replaced. --stage-only verifies and stages a new version without activating it; perform upgrades through the documented backup and migration workflow.

For a manual portable launch, run `dotnet DnsServerApp.dll --portable-app /absolute/configuration/path`, or the native executable for a self-contained package. The upstream API/environment identifiers remain available. Configure an initial credential with DNS_SERVER_ADMIN_PASSWORD_FILE before first start. New configuration without an explicit credential retains the engine's admin/admin default; change it before granting network access. The automatic service installers supply a random credential instead.

See [feature status](../docs/FEATURE-MATRIX.md), [backup/migration](../docs/BACKUP-MIGRATION.md), and [model connections](../docs/SECURITY-LLM.md). Keep the original administrative session through any credential/access change; a separate fresh session must prove intended credentials, privileges and target-seen source before closing it. Installation success alone does not verify service, lease or repair outcomes. Windows setup is an unsigned alpha installer. macOS and ARM packages require their own platform execution checks before deployment.
