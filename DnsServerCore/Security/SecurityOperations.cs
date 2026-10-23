using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore.Security
{
    public sealed record SecuritySearch(SecurityEvent[] Events, int Scanned, int CorruptLines, bool Truncated);
    public sealed record SecurityDisposition(string EventId, string Status, string Notes, string Actor, DateTime Timestamp);
    public sealed partial class DdiSecurityManager
    {
        SecurityPolicy[] LoadPolicyHistory()
        {
            string file = Path.Combine(_folder, "security-policy-history.json");
            var values = File.Exists(file) ? JsonSerializer.Deserialize<SecurityPolicy[]>(File.ReadAllBytes(file), JsonOptions) : [ReadPolicy()];
            if (values is null || values.Length > 25) throw new InvalidDataException("Invalid policy history.");
            return values.Select(p => ParsePolicy(JsonSerializer.SerializeToUtf8Bytes(p, JsonOptions))).ToArray();
        }
        // Caller holds _persistence. Prepared higher revisions are not retained until active replacement.
        SecurityPolicy[] LoadRetainedPolicyHistory()
        {
            long activeRevision = ReadPolicy().Revision;
            return LoadPolicyHistory().Where(p => p.Revision <= activeRevision).ToArray();
        }
        void SavePolicyHistory(SecurityPolicy next, Action authorizeCommit = null)
        {
            var current = ReadPolicy();
            Save("security-policy-history.json", LoadRetainedPolicyHistory().Where(p => p.Revision != current.Revision && p.Revision != next.Revision).Append(current).Append(next).TakeLast(25).ToArray(), authorizeCommit);
        }
        public SecurityPolicy[] PolicyHistory()
        { using (_persistence.Enter()) return LoadRetainedPolicyHistory().Select(p => p with { Indicators = p.Indicators.ToArray() }).ToArray(); }
        public SecurityDisposition[] Dispositions()
        {
            using (_persistence.Enter())
            {
                return LoadDispositions();
            }
        }
        SecurityDisposition[] LoadDispositions()
        {
            string file = Path.Combine(_folder, "security-dispositions.json");
            return File.Exists(file) ? JsonSerializer.Deserialize<SecurityDisposition[]>(File.ReadAllBytes(file), JsonOptions) ?? [] : [];
        }
        public SecurityDisposition SetDisposition(string eventId, string status, string notes, string actor)
        {
            if (!Guid.TryParse(eventId, out _) || status != "Investigating" && status != "Confirmed" && status != "FalsePositive" && status != "Resolved" || notes?.Length > 2048 || string.IsNullOrWhiteSpace(actor) || actor.Length > 255) throw new ArgumentException("Invalid analyst disposition.");
            eventId = Guid.Parse(eventId).ToString("N");
            using (_persistence.Enter())
            {
                var next = new SecurityDisposition(eventId, status, notes ?? "", actor, DateTime.UtcNow);
                Save("security-dispositions.json", LoadDispositions().Where(d => d.EventId != eventId).Append(next).TakeLast(5000).ToArray()); return next;
            }
        }
        public async Task<SecuritySearch> SearchEventsAsync(DateTime from, DateTime to, string client = "", string query = "", int limit = 200, CancellationToken cancellationToken = default)
        {
            if (from.Kind != DateTimeKind.Utc || to.Kind != DateTimeKind.Utc || from > to || to - from > TimeSpan.FromDays(7) || limit < 1 || limit > 1000 || client?.Length > 255 || query?.Length > 255) throw new ArgumentException("Search requires a UTC interval of at most seven days and a limit of 1–1000.");
            bool Matches(SecurityEvent item) => item.Timestamp >= from && item.Timestamp <= to && (string.IsNullOrEmpty(client) || item.ClientAddress == client || item.Device?.ClientIdentifier == client || item.Device?.HardwareAddress == client) && (string.IsNullOrEmpty(query) || item.Query?.Contains(query, StringComparison.OrdinalIgnoreCase) == true);
            var results = RecentEvents().Where(Matches).ToDictionary(e => e.Id); int scanned = 0, corrupt = 0; long bytes = 0; bool truncated = false;
            foreach (string file in Directory.GetFiles(_folder, "security-events-????????.jsonl").OrderByDescending(p => p))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!DateTime.TryParseExact(Path.GetFileNameWithoutExtension(file)[16..], "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var day) || day.Date < from.Date || day.Date > to.Date) continue;
                using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); using var reader = new StreamReader(stream);
                string line;
                while ((line = await reader.ReadLineAsync(cancellationToken)) is not null)
                {
                    bytes += System.Text.Encoding.UTF8.GetByteCount(line); scanned++;
                    if (bytes > 20 * 1024 * 1024 || scanned > 20000) { truncated = true; break; }
                    if (line.Length > 1024 * 1024) { corrupt++; continue; }
                    try { var item = JsonSerializer.Deserialize<SecurityEvent>(line, JsonOptions); if (item is not null && Matches(item)) results[item.Id] = item; }
                    catch (JsonException) { corrupt++; }
                }
                if (truncated) break;
            }
            if (results.Count > limit) truncated = true;
            return new(results.Values.OrderByDescending(e => e.Timestamp).Take(limit).ToArray(), scanned, corrupt, truncated);
        }
    }
}
