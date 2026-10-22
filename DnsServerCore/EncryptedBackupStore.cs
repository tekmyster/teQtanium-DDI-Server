// Modified by Tekmyster Industries, LLC — remains GPL-3.0
// SPDX-License-Identifier: GPL-3.0-or-later
using DnsServerCore.Dhcp;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore;

// Portable configuration snapshots only. This store never installs DHCP authority.
public sealed class EncryptedBackupStore : IAsyncDisposable
{
    public const int Limit = 16 * 1024 * 1024;
    const int Header = 24, Tag = 16;
    readonly string _folder, _settings;
    readonly Func<Action, Task<byte[]>> _capture;
    readonly Action<byte[]> _verify;
    readonly SemaphoreSlim _gate = new(1, 1);
    byte[] _key;
    Action _authorize;
    bool _disposed;
    Schedule _schedule = new(false, 24, 7);
    DateTime _next;
    long _completed, _failed, _coalesced, _lockedTicks;
    internal Action<string> _checkpoint; // Owned process interruption fixture, never an API parameter.
    string _outcome = "Locked: supply the encryption key after each service restart.";
    public sealed record Schedule(bool Enabled, int IntervalHours, int Retain);

    public EncryptedBackupStore(string configFolder, Func<Action, Task<byte[]>> capture, Action<byte[]> verify)
    {
        _folder = Path.Combine(configFolder, "encrypted-backups");
        _settings = Path.Combine(configFolder, "backup-schedule.json"); _capture = capture; _verify = verify;
        if (File.Exists(_settings))
        {
            try { if (new FileInfo(_settings).Length > 16384) throw new InvalidDataException(); var value = JsonSerializer.Deserialize<Schedule>(File.ReadAllBytes(_settings)); Validate(value); _schedule = value; }
            catch { _outcome = "Schedule could not be loaded. Configure it again; DNS and DHCP continue running."; }
        }
    }
    static void Validate(Schedule value)
    {
        if (value is null || value.IntervalHours is < 1 or > 168 || value.Retain is < 1 or > 30)
            throw new ArgumentException("Choose an interval from 1 to 168 hours and retain 1 to 30 backups.");
    }
    public static byte[] ParseKey(string value)
    {
        if (value is null || value.Length != 44) throw new ArgumentException("Supply a Base64-encoded 32-byte encryption key in the request body.");
        byte[] key;
        try { key = Convert.FromBase64String(value); } catch (FormatException) { throw new ArgumentException("Supply a Base64-encoded 32-byte encryption key in the request body."); }
        if (key.Length != 32) { CryptographicOperations.ZeroMemory(key); throw new ArgumentException("The encryption key must contain exactly 32 bytes."); }
        return key;
    }
    public static bool IsEncrypted(byte[] data) => data.Length >= 4 && data.AsSpan(0, 4).SequenceEqual("TQB1"u8);
    public static byte[] Encrypt(byte[] plain, byte[] key)
    {
        if (plain.Length is < 1 or > Limit || key.Length != 32) throw new InvalidDataException("The backup exceeds its size limit or the key is invalid.");
        byte[] output = new byte[Header + plain.Length + Tag]; "TQB1"u8.CopyTo(output);
        RandomNumberGenerator.Fill(output.AsSpan(4, 12));
        System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(output.AsSpan(16, 8), plain.Length);
        using var aes = new AesGcm(key, Tag);
        aes.Encrypt(output.AsSpan(4, 12), plain, output.AsSpan(Header, plain.Length), output.AsSpan(Header + plain.Length, Tag), output.AsSpan(0, Header));
        return output;
    }
    public static byte[] Decrypt(byte[] data, byte[] key)
    {
        if (key.Length != 32 || data.Length < Header + Tag + 1 || data.Length > Limit + Header + Tag || !IsEncrypted(data) ||
            System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(16, 8)) != data.Length - Header - Tag)
            throw new InvalidDataException("The encrypted backup is invalid or exceeds 16 MiB.");
        byte[] plain = new byte[data.Length - Header - Tag];
        try
        {
            using var aes = new AesGcm(key, Tag);
            aes.Decrypt(data.AsSpan(4, 12), data.AsSpan(Header, plain.Length), data.AsSpan(Header + plain.Length, Tag), plain, data.AsSpan(0, Header));
            return plain;
        }
        catch (CryptographicException) { CryptographicOperations.ZeroMemory(plain); throw new InvalidDataException("The encryption key is incorrect or the backup is damaged."); }
    }
    public async Task ConfigureAsync(Schedule value, Action authorize)
    {
        Validate(value); await _gate.WaitAsync();
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this); authorize();
            WriteAtomic(_settings, JsonSerializer.SerializeToUtf8Bytes(value), beforeCommit: authorize); _schedule = value;
            _next = DateTime.UtcNow; _outcome = value.Enabled ? "Scheduled; encryption key and current administrator authorization are required." : "Schedule disabled.";
        }
        finally { _gate.Release(); }
    }
    public async Task UnlockAsync(byte[] key, Action authorize)
    {
        if (key.Length != 32) throw new ArgumentException("The encryption key must contain exactly 32 bytes.");
        await _gate.WaitAsync();
        try { ObjectDisposedException.ThrowIf(_disposed, this); authorize(); ClearKey(); _key = (byte[])key.Clone(); _authorize = authorize; _next = DateTime.UtcNow; _outcome = "Unlocked for this administrator session; the key is held in memory only."; }
        finally { _gate.Release(); }
    }
    void ClearKey() { if (_key is not null) CryptographicOperations.ZeroMemory(_key); _key = null; _authorize = null; }
    void CheckDelegation() { try { _authorize(); } catch { ClearKey(); throw; } }
    public async Task LockAsync(Action authorize)
    {
        await _gate.WaitAsync(); try { authorize(); ClearKey(); _outcome = "Locked."; } finally { _gate.Release(); }
    }
    public async Task<object> StatusAsync(Action authorize)
    {
        await _gate.WaitAsync();
        try { authorize(); return new { schedule = _schedule, unlocked = _key is not null, nextUtc = _next, outcome = _outcome, completed = _completed, failed = _failed, coalescedTicks = _coalesced, lockedTicks = _lockedTicks, interruptedPendingFiles = Directory.Exists(_folder) ? Directory.GetFiles(_folder, "backup-*.tqb.pending-*").Select(Path.GetFileName).Take(65).ToArray() : [], files = Directory.Exists(_folder) ? Directory.GetFiles(_folder, "backup-*.tqb").Select(Path.GetFileName).Order().Take(65).ToArray() : [] }; }
        finally { _gate.Release(); }
    }
    public async Task<string> RunAsync(Action authorize, bool scheduled = false)
    {
        // Manual overlapping work is rejected; scheduled ticks coalesce without a backlog.
        if (!await _gate.WaitAsync(0)) { if (scheduled) { Interlocked.Increment(ref _coalesced); return null; } throw new InvalidOperationException("A backup operation is already running. Retry after it completes."); }
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (scheduled && (!_schedule.Enabled || DateTime.UtcNow < _next)) return null;
            if (scheduled) _next = DateTime.UtcNow.AddHours(_schedule.IntervalHours);
            authorize?.Invoke();
            if (_key is null) { _outcome = "Locked: no backup was created. Supply the encryption key."; if (scheduled) { _lockedTicks++; return null; } throw new InvalidOperationException(_outcome); }
            CheckDelegation();
            MigrationCheckpoint.EnsureLocalPaths(Path.GetDirectoryName(_folder), [Path.GetFileName(_folder)]);
            Directory.CreateDirectory(_folder);
            // Only exact files created by this namespace are eligible for reconciliation or retention.
            var existing = Directory.GetFiles(_folder).Take(65).ToArray();
            if (existing.Length > 64) throw new IOException("Backup storage needs operator review: more than 64 entries exist.");
            foreach (string temp in existing.Where(p => Path.GetFileName(p).Length == 84 && Path.GetFileName(p).Substring(43, 9) == ".pending-" && ValidId(Path.GetFileName(p).Substring(0, 43)) && Guid.TryParseExact(Path.GetFileName(p).Substring(52), "N", out _)))
            { CheckDelegation(); File.Delete(temp); }
            if (Directory.GetFiles(_folder, "backup-*.tqb").Length > 30) throw new IOException("Backup storage has reached 30 artifacts. Retire an old key's backups explicitly before creating another.");
            byte[] plain = await _capture(() => { CheckDelegation(); authorize?.Invoke(); });
            try
            {
                _verify(plain); byte[] encrypted = Encrypt(plain, _key);
                // A capture can await another configuration operation. Recheck rights before persistence.
                CheckDelegation(); authorize?.Invoke();
                string id = "backup-" + Guid.NewGuid().ToString("N") + ".tqb", destination = Path.Combine(_folder, id);
                WriteAtomic(destination, encrypted, _checkpoint, () => { CheckDelegation(); authorize?.Invoke(); });
                byte[] restored = Decrypt(File.ReadAllBytes(destination), _key);
                try { if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(plain), SHA256.HashData(restored))) throw new InvalidDataException("Stored backup verification failed."); _verify(restored); }
                finally { CryptographicOperations.ZeroMemory(restored); }
                // Retain only after the new encrypted file passes a fresh disk read and full package validation.
                foreach (string old in Directory.GetFiles(_folder, "backup-*.tqb").Where(x => Path.GetFileName(x) != id && ValidId(Path.GetFileName(x))).OrderByDescending(File.GetLastWriteTimeUtc).Skip(_schedule.Retain - 1))
                {
                    CheckDelegation(); MigrationCheckpoint.EnsureLocalPaths(_folder, [Path.GetFileName(old)]);
                    if (new FileInfo(old).Length > Limit + Header + Tag) continue;
                    byte[] retained;
                    try { retained = Decrypt(File.ReadAllBytes(old), _key); } catch (InvalidDataException) { continue; }
                    try { _verify(retained); } catch { continue; } finally { CryptographicOperations.ZeroMemory(retained); }
                    CheckDelegation(); File.Delete(old);
                }
                AllocationDurability.SyncDirectory(_folder);
                _completed++; _outcome = "Encrypted backup archive verified: " + id; return id;
            }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        catch { _failed++; _outcome = "Backup did not finish. Review retained artifacts and storage, supply a current key and authorization, then retry."; throw; }
        finally { _gate.Release(); }
    }
    public async Task<byte[]> DownloadAsync(string id, Action authorize)
    {
        if (!ValidId(id)) throw new ArgumentException("Select an existing encrypted backup.");
        await _gate.WaitAsync();
        try { authorize(); MigrationCheckpoint.EnsureLocalPaths(_folder, [id]); string path = Path.Combine(_folder, id); if (new FileInfo(path).Length > Limit + Header + Tag) throw new InvalidDataException("The backup exceeds its size limit."); return File.ReadAllBytes(path); }
        finally { _gate.Release(); }
    }
    static bool ValidId(string id) => id is not null && id.Length == 43 && id.StartsWith("backup-", StringComparison.Ordinal) && id.EndsWith(".tqb", StringComparison.Ordinal) && Guid.TryParseExact(id.Substring(7, 32), "N", out _);
    internal static void WriteAtomic(string destination, byte[] bytes, Action<string> checkpoint = null, Action beforeCommit = null)
    {
        string temp = destination + ".pending-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { file.Write(bytes); file.Flush(true); }
            checkpoint?.Invoke("Flushed");
            beforeCommit?.Invoke();
            File.Move(temp, destination, true); AllocationDurability.SyncDirectory(Path.GetDirectoryName(destination));
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync(); try { _disposed = true; ClearKey(); } finally { _gate.Release(); }
    }
}
