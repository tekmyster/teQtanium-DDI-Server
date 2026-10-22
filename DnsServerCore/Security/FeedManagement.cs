// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace DnsServerCore.Security
{
    public sealed partial class DdiSecurityManager
    {
        sealed record FeedAttempt(string Configuration, DateTime NextAttempt, int Failures, string AttemptId = "", string Outcome = "Interrupted", DateTime? StartedAt = null, DateTime? CompletedAt = null);
        readonly Func<DateTime> _feedClock;
        readonly Action<string> _feedCheckpoint;
        DateTime FeedNow => _feedClock?.Invoke() ?? DateTime.UtcNow;
        string _runningFeedAttempt;
        readonly HashSet<string> _feedCancelRequested = new(StringComparer.Ordinal);
        readonly Dictionary<string, CancellationTokenSource> _feedCancellation = new(StringComparer.Ordinal);
        bool IsFeedCancellation(string id) { lock (_sync) return id is not null && _feedCancelRequested.Contains(id); }
        public void CancelFeedAttempt(string id)
        {
            lock (_sync)
            {
                if (id is null || !_feedCancellation.TryGetValue(id, out var token)) throw new ArgumentException("Refresh attempt is not running on this node.");
                _feedCancelRequested.Add(id); token.Cancel();
            }
        }
        Dictionary<string, FeedAttempt> _edlSchedule = new(StringComparer.Ordinal);
        long _edlEpoch;
        static string Hash(object value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions))).ToLowerInvariant();
        static string FeedHash(EdlFeed feed) => Hash(feed);
        static string SourceHash(EdlFeed f) => Hash(new { f.Id, f.Kind, f.Url, f.Format, f.RpzZone, f.ApiKeyEnvironment, f.AuthScheme });
        static string SnapshotHash(EdlSnapshot s) => Hash(new { s.FeedId, s.Kind, s.SourceUrl, s.FetchedAt, s.Expires, s.Values, s.Format, s.RpzZone, s.SourceConfiguration, s.Provenance, s.ValidatedAt });
        static bool ValidFeedQuality(EdlFeed f) => f.Format is "Plain" or "RpzQnameNxdomain" && f.SourceConfidence is >= 0 and <= 100 && f.MinimumConfidence is >= 0 and <= 100 && f.MaximumAgeHours is >= 1 and <= 168 && f.Provenance is not null && f.Provenance.Length <= 512 && !f.Provenance.Any(char.IsControl) && (f.Format == "Plain" ? f.RpzZone == "" : f.Kind == "Domain" && ValidRpzZone(f.RpzZone));
        static bool ValidRpzZone(string zone)
        {
            try { return zone is not null && zone.Length > 0 && NormalizeEdlValue("Domain", zone) == zone && !zone.EndsWith('.'); }
            catch (ArgumentException) { return false; }
            catch (FormatException) { return false; }
        }
        static bool ValidSnapshotFormat(EdlSnapshot s) => s.Provenance is not null && s.Provenance.Length <= 512 && !s.Provenance.Any(char.IsControl) && (!s.ValidatedAt.HasValue || s.ValidatedAt.Value.Kind == DateTimeKind.Utc && s.ValidatedAt >= s.FetchedAt && s.ValidatedAt <= DateTime.UtcNow.AddMinutes(1)) && s.SourceConfiguration is not null && (s.SourceConfiguration.Length == 0 || s.SourceConfiguration.Length == 64 && s.SourceConfiguration.All(char.IsAsciiHexDigit)) && s.CommitId is not null && (s.CommitId.Length == 0 || s.CommitId.Length == 32 && s.CommitId.All(char.IsAsciiHexDigit)) && s.ContentSha256 is not null && (s.ContentSha256 == "" || s.ContentSha256.Length == 64 && s.ContentSha256.All(c => char.IsAsciiHexDigit(c))) && (s.Format == "Plain" ? s.RpzZone == "" : s.Format == "RpzQnameNxdomain" && s.Kind == "Domain" && ValidRpzZone(s.RpzZone));
        // The committed snapshot is authoritative when the separate terminal schedule write
        // was lost. Use this same bound receipt for readback and the next failure calculation.
        bool HasCommittedFeedReceipt(EdlFeed feed, FeedAttempt attempt) =>
            attempt is not null && attempt.Configuration == FeedHash(feed) && attempt.AttemptId.Length == 32 &&
            _edlSnapshots.Any(s => s.FeedId == feed.Id && s.Kind == feed.Kind && s.SourceUrl == feed.Url &&
                s.Format == feed.Format && s.RpzZone == feed.RpzZone && s.SourceConfiguration == SourceHash(feed) &&
                s.ContentSha256.Length == 64 && s.CommitId == attempt.AttemptId);
        static DateTime EffectiveExpiry(EdlFeed f, EdlSnapshot s) => new[] { s.Expires, s.FetchedAt.AddHours(f.MaximumAgeHours), s.FetchedAt.AddHours(f.CacheLifetimeHours) }.Min();
        void LoadFeedSchedule()
        {
            string path = Path.Combine(_folder, "security-feed-schedule.json");
            if (!File.Exists(path)) return;
            try
            {
                if (new FileInfo(path).Length > 16384) throw new ArgumentException("Invalid feed schedule size.");
                var schedule = JsonSerializer.Deserialize<Dictionary<string, FeedAttempt>>(File.ReadAllBytes(path), JsonOptions);
                if (schedule is null || schedule.Count > 8 || schedule.Any(p => !EdlId(p.Key) || p.Value is null || p.Value.Configuration?.Length != 64 || p.Value.NextAttempt.Kind != DateTimeKind.Utc || p.Value.NextAttempt > DateTime.UtcNow.AddDays(1) || p.Value.Failures is < 0 or > 16 || p.Value.AttemptId?.Length != 32 || !p.Value.AttemptId.All(char.IsAsciiHexDigit) || p.Value.Outcome is not ("Running" or "Succeeded" or "Failed" or "TimedOut" or "Cancelled" or "Superseded" or "Interrupted") || p.Value.StartedAt?.Kind != DateTimeKind.Utc || p.Value.StartedAt > DateTime.UtcNow.AddMinutes(1) || p.Value.CompletedAt.HasValue && (p.Value.CompletedAt.Value.Kind != DateTimeKind.Utc || p.Value.CompletedAt < p.Value.StartedAt || p.Value.CompletedAt > DateTime.UtcNow.AddMinutes(1)))) throw new ArgumentException("Invalid feed schedule.");
                _edlSchedule = schedule;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is JsonException || ex is ArgumentException) { _edlSchedule.Clear(); }
        }
        string SaveFeedAttempt(EdlFeed feed, DateTime now, bool success)
        {
            int priorFailures = _edlSchedule.TryGetValue(feed.Id, out var old) && old.Configuration == FeedHash(feed) &&
                !HasCommittedFeedReceipt(feed, old) ? old.Failures : 0;
            int failures = success ? 0 : Math.Min(16, priorFailures + 1);
            int seconds = (int)Math.Min(86400L, feed.RefreshSeconds * (1L << Math.Max(0, failures - 1)));
            var schedule = _edlSchedule.Where(p => ReadPolicy().EdlFeeds.Any(f => f.Id == p.Key)).ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
            string id = Guid.NewGuid().ToString("N");
            schedule[feed.Id] = new(FeedHash(feed), now.AddSeconds(seconds), failures, id, "Running", now);
            Save("security-feed-schedule.json", schedule);
            lock (_sync) { _edlSchedule = schedule; _runningFeedAttempt = id; }
            return id;
        }
        void CompleteFeedAttempt(EdlFeed feed, string id, string outcome)
        {
            if (!_edlSchedule.TryGetValue(feed.Id, out var old) || old.AttemptId != id) return;
            var schedule = new Dictionary<string, FeedAttempt>(_edlSchedule, StringComparer.Ordinal);
            schedule[feed.Id] = old with { Outcome = outcome, CompletedAt = FeedNow, Failures = outcome == "Succeeded" ? 0 : old.Failures, NextAttempt = outcome == "Succeeded" ? FeedNow.AddSeconds(feed.RefreshSeconds) : old.NextAttempt };
            Save("security-feed-schedule.json", schedule);
            lock (_sync) _edlSchedule = schedule;
        }
        static bool RpzTtl(string value) => value.Length > 0 && value.All(char.IsAsciiDigit) && uint.TryParse(value, out _);
        static string[] ParseFeedText(EdlFeed feed, string text)
        {
            HashSet<string> values = new(StringComparer.Ordinal); int lines = 0;
            using var reader = new StringReader(text); string line;
            bool origin = false;
            while ((line = reader.ReadLine()) is not null)
            {
                if (++lines > 20000) throw new ArgumentException("Feed exceeds 20000 lines.");
                line = line.Trim();
                if (line.Length == 0 || line.StartsWith('#') && feed.Format == "Plain") continue;
                if (feed.Format == "RpzQnameNxdomain")
                {
                    line = line.Split(';')[0].Trim(); if (line.Length == 0) continue;
                    string[] fields = line.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
                    if (fields.Length == 2 && fields[0] == "$ORIGIN" && fields[1].Equals(feed.RpzZone + ".", StringComparison.OrdinalIgnoreCase)) { origin = true; continue; }
                    if (fields.Length == 2 && fields[0] == "$TTL" && RpzTtl(fields[1])) continue;
                    if (!origin) throw new ArgumentException("RPZ requires the configured explicit $ORIGIN.");
                    // Deliberate record-fragment subset; no implicit owners, directives, metadata or transfers.
                    int cname = fields.Length - 2;
                    if (cname < 1 || cname > 3 || !fields[cname].Equals("CNAME", StringComparison.OrdinalIgnoreCase) || fields[^1] != ".") throw new ArgumentException("Only explicit QNAME CNAME . RPZ records are supported.");
                    bool ttl = false, cls = false;
                    foreach (string option in fields.Skip(1).Take(cname - 1))
                    {
                        if (!cls && option.Equals("IN", StringComparison.OrdinalIgnoreCase)) cls = true;
                        else if (!ttl && RpzTtl(option)) ttl = true;
                        else throw new ArgumentException("Unsupported RPZ record fields.");
                    }
                    line = fields[0].ToLowerInvariant();
                    if (line.EndsWith('.'))
                    {
                        string suffix = "." + feed.RpzZone + ".";
                        if (!line.EndsWith(suffix, StringComparison.Ordinal)) throw new ArgumentException("RPZ owner is outside the configured zone.");
                        line = line[..^suffix.Length];
                    }
                    if (line.Split('.').Any(l => l.StartsWith("rpz-", StringComparison.Ordinal)) || line.Contains('\\') || line == "@") throw new ArgumentException("Unsupported RPZ trigger or escaped owner.");
                }
                values.Add(NormalizeEdlValue(feed.Kind, line));
                if (values.Count > 10000) throw new ArgumentException("Feed exceeds 10000 entries.");
            }
            if (feed.Format == "RpzQnameNxdomain" && !origin) throw new ArgumentException("RPZ origin missing.");
            return values.Order(StringComparer.Ordinal).ToArray();
        }
        // Export only the already explicitly selected Domain publication. Monitor does not become NXDOMAIN.
        public string PublishRpz(string publicationId, string zone)
        {
            return FormatRpz(PublishEdl(publicationId), zone);
        }
        public static string FormatRpz(EdlOutput output, string zone)
        {
            if (!ValidRpzZone(zone)) throw new ArgumentException("Enter a normalized RPZ zone name.");
            if (output.Kind != "Domain" || output.IntendedAction != "Block") throw new ArgumentException("RPZ NXDOMAIN export requires an explicit Domain publication with Block intent.");
            return "$ORIGIN " + zone + ".\n" + string.Join("", output.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(v => v + " CNAME .\n"));
        }
        // Explicit restore uses both policy revision and content token; a successful replay changes the token.
        public string EdlRevision { get { lock (_sync) return Hash(_edlSnapshots); } }
        public void RollbackEdl(byte[] data, long expectedPolicyRevision, string expectedSnapshotRevision, Func<bool> commitAuthorized = null)
        {
            EdlSnapshot[] snapshots = ParseEdlCache(data);
            if (snapshots.Length == 0 || snapshots.Any(s => s.ContentSha256.Length != 64)) throw new ArgumentException("Rollback requires integrity-checked snapshots.");
            using (_persistence.Enter())
            {
                var policy = ReadPolicy();
                if (policy.Revision != expectedPolicyRevision || EdlRevision != expectedSnapshotRevision) throw new InvalidOperationException("Feed state changed; reload before rollback.");
                if (Hash(snapshots) == expectedSnapshotRevision) throw new ArgumentException("Snapshot is already current.");
                if (snapshots.Any(s => !policy.EdlFeeds.Any(f => f.Id == s.FeedId && f.Kind == s.Kind && f.Url == s.SourceUrl && f.Format == s.Format && f.RpzZone == s.RpzZone && (s.SourceConfiguration.Length == 0 || s.SourceConfiguration == SourceHash(f))))) throw new ArgumentException("Snapshot source does not match current configuration.");
                snapshots = snapshots.Select(s => s with { CommitId = Guid.NewGuid().ToString("N") }).ToArray();
                Index index = BuildIndex(policy, edl: snapshots);
                if (commitAuthorized?.Invoke() == false) throw new InvalidOperationException("Feed restore authorization changed; authenticate and retry.");
                Save("security-edl.json", snapshots);
                lock (_sync) { _edlSnapshots = snapshots; _index = index; _edlEpoch++; _edlHealth.Clear(); }
            }
        }
    }
}
