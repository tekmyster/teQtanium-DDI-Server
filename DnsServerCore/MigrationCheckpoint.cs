// Modified by Tekmyster Industries, LLC — remains GPL-3.0
// SPDX-License-Identifier: GPL-3.0-or-later
using DnsServerCore.Dhcp;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace DnsServerCore;

// Write-ahead preimage. Recovery is idempotent rollback, never activation or authority transfer.
public static class MigrationCheckpoint
{
    const int FileLimit = 16 * 1024 * 1024;
    const long TotalLimit = 128L * 1024 * 1024;
    const string Pending = "migration-pending.zip";
    const string ReceiptFile = "migration-operation.json";
    public sealed record Receipt(string Operation, string Actor, string ArtifactSha256, string DestinationFingerprint, DateTime StartedUtc, string State, string CheckpointSha256 = null);
    public static Receipt GetReceipt(string folder)
    {
        string path = Path.Combine(folder, ReceiptFile);
        if (!File.Exists(path)) return null;
        if (new FileInfo(path).Length > 16384) throw new InvalidDataException("Migration operation receipt exceeds its size limit.");
        return JsonSerializer.Deserialize<Receipt>(File.ReadAllBytes(path));
    }
    public static void Record(string folder, Receipt receipt) => EncryptedBackupStore.WriteAtomic(Path.Combine(folder, ReceiptFile), JsonSerializer.SerializeToUtf8Bytes(receipt));
    public static bool Allows(string name)
    {
        if (name is "dns.config" or "ipam.json" or "security.json" or "allowed.config" or "blocked.config" or "blocklist.config") return true;
        string[] parts = name.Split('/');
        return parts.Length == 2 && parts[1].Length > 0 && parts[1] is not "." and not ".." &&
            name.IndexOfAny(['\\', ':', '<', '>', '"', '|', '?', '*', '\0']) < 0 &&
            ((parts[0] == "zones" && parts[1].EndsWith(".zone", StringComparison.Ordinal)) ||
             (parts[0] == "scopes" && parts[1].EndsWith(".scope", StringComparison.Ordinal)) || parts[0] == "blocklists");
    }
    public static void EnsureLocalPaths(string folder, IEnumerable<string> names)
    {
        string root = Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        foreach (string name in names.Append("."))
        {
            string path = Path.GetFullPath(Path.Combine(folder, name));
            if (name != "." && !path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Migration paths must stay within the destination configuration folder.");
            while (path.Length >= root.Length - 1)
            {
                if ((File.Exists(path) || Directory.Exists(path)) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Migration does not follow symbolic links or reparse points.");
                path = Path.GetDirectoryName(path); if (path is null) break;
            }
        }
    }
    static Dictionary<string, byte[]> Read(byte[] bytes)
    {
        using var zip = new ZipArchive(new MemoryStream(bytes));
        if (zip.Entries.Count > 2049) throw new InvalidDataException("Recovery checkpoint has too many files.");
        var result = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase); long total = 0;
        foreach (var entry in zip.Entries)
        {
            total += entry.Length;
            if (entry.Length > FileLimit || total > TotalLimit || (entry.FullName != "checkpoint.json" && !Allows(entry.FullName))) throw new InvalidDataException("Recovery checkpoint exceeds its boundary.");
            using var input = entry.Open(); using var output = new MemoryStream(); byte[] buffer = new byte[8192]; int count;
            while ((count = input.Read(buffer)) > 0) { if (output.Length + count > FileLimit) throw new InvalidDataException("Recovery file is too large."); output.Write(buffer, 0, count); }
            if (output.Length != entry.Length || !result.TryAdd(entry.FullName, output.ToArray())) throw new InvalidDataException("Recovery checkpoint is damaged.");
        }
        return result;
    }
    public static byte[] FilterNativeBackup(byte[] bytes)
    {
        using var source = new ZipArchive(new MemoryStream(bytes)); using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true))
            foreach (var entry in source.Entries.Where(e => Allows(e.FullName)))
            { using var input = entry.Open(); using var target = zip.CreateEntry(entry.FullName).Open(); input.CopyTo(target); }
        return output.ToArray();
    }
    public static void Prepare(string folder, byte[] nativePreimage, IEnumerable<string> incoming)
    {
        EnsureLocalPaths(folder, ["zones", "scopes", "blocklists", Pending]);
        if (File.Exists(Path.Combine(folder, Pending))) throw new InvalidOperationException("An unfinished migration requires recovery before another import.");
        var before = Read(FilterNativeBackup(nativePreimage));
        var names = new HashSet<string>(before.Keys, StringComparer.OrdinalIgnoreCase);
        foreach (string name in incoming.Where(Allows)) names.Add(name);
        // Include files that native restore can delete. Disk bytes fill any preimage omitted by native export.
        foreach (string sub in new[] { "zones", "scopes", "blocklists" })
            if (Directory.Exists(Path.Combine(folder, sub)))
                foreach (string path in Directory.GetFiles(Path.Combine(folder, sub)))
                { string name = sub + "/" + Path.GetFileName(path); if (Allows(name)) { names.Add(name); if (!before.ContainsKey(name)) before[name] = File.ReadAllBytes(path); } }
        foreach (string name in new[] { "dns.config", "ipam.json", "security.json", "allowed.config", "blocked.config", "blocklist.config" }) names.Add(name);
        EnsureLocalPaths(folder, names);
        var manifest = names.ToDictionary(n => n, n => before.TryGetValue(n, out var b) ? Convert.ToHexString(SHA256.HashData(b)) : null, StringComparer.OrdinalIgnoreCase);
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true))
        {
            foreach (var entry in before) { using var target = zip.CreateEntry(entry.Key).Open(); target.Write(entry.Value); }
            using var meta = zip.CreateEntry("checkpoint.json").Open(); JsonSerializer.Serialize(meta, manifest);
        }
        byte[] bytes = output.ToArray(); Validate(bytes); EncryptedBackupStore.WriteAtomic(Path.Combine(folder, Pending), bytes);
    }
    static (Dictionary<string, byte[]> Files, Dictionary<string, string> Manifest) Validate(byte[] bytes)
    {
        var files = Read(bytes);
        if (!files.Remove("checkpoint.json", out var meta)) throw new InvalidDataException("Recovery manifest is missing.");
        var manifest = JsonSerializer.Deserialize<Dictionary<string, string>>(meta);
        if (manifest is null || manifest.Count > 2048 || manifest.Any(e => !Allows(e.Key)) || manifest.Keys.Distinct(StringComparer.OrdinalIgnoreCase).Count() != manifest.Count || files.Count != manifest.Values.Count(v => v is not null)) throw new InvalidDataException("Recovery manifest is invalid.");
        foreach (var entry in manifest)
            if (entry.Value is not null && (!files.TryGetValue(entry.Key, out var content) || Convert.ToHexString(SHA256.HashData(content)) != entry.Value)) throw new InvalidDataException("Recovery checksum mismatch.");
        return (files, manifest);
    }
    public static bool Recover(string folder)
    {
        string pending = Path.Combine(folder, Pending);
        if (!File.Exists(pending)) return false;
        if (new FileInfo(pending).Length > TotalLimit + 1024 * 1024) throw new InvalidDataException("Recovery checkpoint exceeds its size limit.");
        var (files, manifest) = Validate(File.ReadAllBytes(pending));
        EnsureLocalPaths(folder, manifest.Keys);
        var receipt = GetReceipt(folder);
        if (receipt?.State == "Committed" && receipt.CheckpointSha256 == Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(pending))))
        { Complete(folder); return false; }
        // Validate the entire checkpoint before touching any destination. Pending remains until every write completes.
        foreach (var entry in manifest)
        {
            string target = Path.Combine(folder, entry.Key);
            if (entry.Value is null) { File.Delete(target); if (Directory.Exists(Path.GetDirectoryName(target))) AllocationDurability.SyncDirectory(Path.GetDirectoryName(target)); }
            else { Directory.CreateDirectory(Path.GetDirectoryName(target)); EncryptedBackupStore.WriteAtomic(target, files[entry.Key]); }
        }
        if (receipt is not null) Record(folder, receipt with { State = "RolledBackAfterInterruption" });
        Complete(folder); return true;
    }
    public static void Complete(string folder)
    { File.Delete(Path.Combine(folder, Pending)); AllocationDurability.SyncDirectory(folder); }
}
