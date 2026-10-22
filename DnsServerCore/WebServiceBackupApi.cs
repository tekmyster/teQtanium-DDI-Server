// Modified by Tekmyster Industries, LLC — remains GPL-3.0
// SPDX-License-Identifier: GPL-3.0-or-later
using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore;

public partial class DnsWebService
{
    EncryptedBackupStore _backups;
    CancellationTokenSource _backupStop;
    Task _backupLoop;
    internal Action<string> _backupCheckpoint;

    void StartBackups()
    {
        _backups = new EncryptedBackupStore(_configFolder, async authorize =>
        {
            if (!await _migrationGate.WaitAsync(TimeSpan.FromSeconds(10))) throw new InvalidOperationException("Configuration import is busy. Retry the backup after it completes.");
            try { authorize(); byte[] package = await BuildMigrationPackageAsync(); _backupCheckpoint?.Invoke("Captured"); return package; } finally { _migrationGate.Release(); }
        }, bytes => ReadMigration(bytes));
        _backupStop = new CancellationTokenSource();
        _backupLoop = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
            try
            {
                while (await timer.WaitForNextTickAsync(_backupStop.Token))
                {
                    if (await _migrationGate.WaitAsync(0))
                    {
                        try { foreach (var id in _migrationReviews.Where(p => p.Value.Expires < DateTime.UtcNow).Select(p => p.Key).ToArray()) { CryptographicOperations.ZeroMemory(_migrationReviews[id].Package); _migrationReviews.Remove(id); } }
                        finally { _migrationGate.Release(); }
                    }
                    try { await _backups.RunAsync(null, scheduled: true); }
                    catch { _log.Write("Encrypted backup did not complete. Review backup status; DNS and DHCP remain independent of backup jobs."); }
                }
            }
            catch (OperationCanceledException) { }
        });
    }
    async Task StopBackupsAsync()
    {
        if (_backupStop is null) return;
        _backupStop.Cancel(); await _backupLoop; await _backups.DisposeAsync(); _backupStop.Dispose(); _backupStop = null;
    }
    async Task MigrationStatusAsync(HttpContext context)
    {
        RequireMigrationAdmin(context); await _migrationGate.WaitAsync();
        try
        {
            RequireMigrationAdmin(context); var receipt = MigrationCheckpoint.GetReceipt(_configFolder);
            if (receipt is null || receipt.Actor != GetSessionUser(context).Username || receipt.Operation != context.Request.GetQueryOrForm("operation")) throw new DnsWebServiceException("No migration operation is available for this administrator.");
            RequireMigrationAdmin(context);
            var writer = context.GetCurrentJsonWriter(); writer.WriteString("operation", receipt.Operation); writer.WriteString("state", receipt.State); writer.WriteString("artifactSha256", receipt.ArtifactSha256);
            writer.WriteString("nextStep", receipt.State.StartsWith("RolledBack", StringComparison.Ordinal) ? "The interrupted import was rolled back. Preview the package again before importing." : receipt.State == "Committed" ? "Read back current DNS, configuration and disabled-scope state before cutover." : "Recovery is required before another import.");
        }
        finally { _migrationGate.Release(); }
    }
    async Task BackupStatusAsync(HttpContext context)
    {
        RequireMigrationAdmin(context);
        object status = await _backups.StatusAsync(() => RequireMigrationAdmin(context));
        RequireMigrationAdmin(context);
        context.GetCurrentJsonWriter().WritePropertyName("backup"); JsonSerializer.Serialize(context.GetCurrentJsonWriter(), status);
    }
    async Task ConfigureBackupsAsync(HttpContext context)
    {
        RequireMigrationAdmin(context);
        var form = await context.Request.ReadFormAsync();
        await _backups.ConfigureAsync(new(bool.Parse(form["enabled"]), int.Parse(form["intervalHours"]), int.Parse(form["retain"])), () => RequireMigrationAdmin(context));
    }
    async Task UnlockBackupsAsync(HttpContext context)
    {
        RequireMigrationAdmin(context);
        var form = await context.Request.ReadFormAsync(); byte[] key = EncryptedBackupStore.ParseKey(form["encryptionKey"]);
        // Retain only the session identity, not the request/body, for the bounded in-memory delegation.
        var sessionContext = new DefaultHttpContext(); sessionContext.Items["session"] = context.GetCurrentSession();
        try { await _backups.UnlockAsync(key, () => RequireMigrationAdmin(sessionContext)); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    async Task LockBackupsAsync(HttpContext context)
    { RequireMigrationAdmin(context); await _backups.LockAsync(() => RequireMigrationAdmin(context)); }
    async Task RunBackupAsync(HttpContext context)
    {
        RequireMigrationAdmin(context);
        string id = await _backups.RunAsync(() => RequireMigrationAdmin(context));
        context.GetCurrentJsonWriter().WriteString("artifact", id);
        context.GetCurrentJsonWriter().WriteString("verification", "Authenticated archive readback; native restoration has not been tested by this job.");
    }
    async Task DownloadBackupAsync(HttpContext context)
    {
        RequireMigrationAdmin(context); var form = await context.Request.ReadFormAsync();
        byte[] bytes = await _backups.DownloadAsync(form["artifact"], () => RequireMigrationAdmin(context)); RequireMigrationAdmin(context);
        context.Response.ContentType = "application/octet-stream"; context.Response.Headers.ContentDisposition = "attachment;filename=ddi-backup.tqb";
        context.Response.ContentLength = bytes.Length; await context.Response.Body.WriteAsync(bytes);
    }
}
