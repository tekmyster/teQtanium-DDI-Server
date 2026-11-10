// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerCore.Security
{
    public sealed record EdlFeed(string Id, string Kind, string Url, bool Enabled = false, string Action = "Monitor", string ApiKeyEnvironment = "", string AuthScheme = "Bearer", int RefreshSeconds = 300, int CacheLifetimeHours = 24)
    {
        public string Format { get; init; } = "Plain";
        public string RpzZone { get; init; } = "";
        public int SourceConfidence { get; init; } = 50;
        public int MinimumConfidence { get; init; } = 0;
        public int MaximumAgeHours { get; init; } = 168;
        public string Provenance { get; init; } = "Operator-configured source; accuracy unverified";
    }
    public sealed record EdlSelection(string Source, string Id);
    public sealed record EdlPublication(string Id, string Kind, EdlSelection[] Selected, bool Enabled = false, string IntendedAction = "Monitor");
    public sealed record EdlSnapshot(string FeedId, string Kind, string SourceUrl, DateTime FetchedAt, DateTime Expires, string[] Values)
    {
        public string Format { get; init; } = "Plain";
        public string RpzZone { get; init; } = "";
        public string ContentSha256 { get; init; } = "";
        public string CommitId { get; init; } = "";
        public string SourceConfiguration { get; init; } = "";
        public string Provenance { get; init; } = "Legacy snapshot; provenance not recorded";
        public DateTime? ValidatedAt { get; init; }
    }
    public sealed record EdlHealth(string FeedId, DateTime? LastSuccess, DateTime? LastAttempt, DateTime? Expires, string Status, int Entries)
    {
        public int RetainedEntries { get; init; }
        public string SnapshotGeneration { get; init; }
        public string IntegrityState { get; init; }
        public DateTime? ValidatedAt { get; init; }
        public string AttemptId { get; init; }
        public string AttemptOutcome { get; init; }
        public DateTime? AttemptStartedAt { get; init; }
        public DateTime? AttemptCompletedAt { get; init; }
        public DateTime? NextAttempt { get; init; }
        public int ConsecutiveFailures { get; init; }
        public string ContentSha256 { get; init; }
        public int SourceConfidence { get; init; }
        public string Provenance { get; init; }
    }
    public sealed record EdlOutput(string Id, string Kind, string IntendedAction, string Text, DateTime GeneratedAt, DateTime? Expires, string State);

    public sealed partial class DdiSecurityManager
    {
        readonly SemaphoreSlim _edlRefresh = new(1, 1);
        EdlSnapshot[] _edlSnapshots = [];
        readonly Dictionary<string, EdlHealth> _edlHealth = new(StringComparer.Ordinal);
        Task _edlRefreshTask;

        static bool EdlId(string id) => !string.IsNullOrEmpty(id) && id.Length <= 64 && id.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');
        static bool EdlKind(string kind) => kind is "Domain" or "Network" or "Url";
        static bool EdlUrl(string url) => url?.Length <= 2048 && Uri.TryCreate(url, UriKind.Absolute, out Uri uri) && uri.Scheme == "https" && uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0;
        static void ValidateEdlPolicy(SecurityPolicy policy)
        {
            if (policy.EdlFeeds is null || policy.EdlPublications is null || policy.EdlFeeds.Length > 8 || policy.EdlPublications.Length > 32) throw new ArgumentException("At most 8 EDL sources and 32 publications are supported.");
            HashSet<string> ids = new(StringComparer.Ordinal);
            foreach (var feed in policy.EdlFeeds)
            {
                if (feed is null || !ValidFeedQuality(feed) || !EdlId(feed.Id) || !ids.Add(feed.Id) || !EdlKind(feed.Kind) || !EdlUrl(feed.Url) || feed.Action is not ("Monitor" or "Block") || feed.RefreshSeconds < 60 || feed.RefreshSeconds > 86400 || feed.CacheLifetimeHours < 1 || feed.CacheLifetimeHours > 168 || feed.AuthScheme is not ("Bearer" or "Basic" or "Raw") || feed.ApiKeyEnvironment is null || (feed.ApiKeyEnvironment.Length > 0 && (feed.ApiKeyEnvironment.Length > 128 || !feed.ApiKeyEnvironment.StartsWith("DDI_EDL_", StringComparison.Ordinal) || !feed.ApiKeyEnvironment.EndsWith("_API_KEY", StringComparison.Ordinal) || feed.ApiKeyEnvironment.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_')))) throw new ArgumentException("Invalid EDL source, HTTPS endpoint, credential reference, action, or limits.");
            }
            ids.Clear();
            foreach (var publication in policy.EdlPublications)
                if (publication is null || !EdlId(publication.Id) || !ids.Add(publication.Id) || !EdlKind(publication.Kind) || publication.IntendedAction is not ("Monitor" or "Block") || publication.Selected is null || publication.Selected.Length > 10000 || publication.Selected.Any(s => s is null || string.IsNullOrEmpty(s.Id) || s.Id.Length > 255 || string.IsNullOrEmpty(s.Source) || s.Source.Length > 255) || publication.Selected.Distinct().Count() != publication.Selected.Length) throw new ArgumentException("Invalid EDL publication or explicit indicator selection.");
        }
        static EdlSnapshot[] ParseEdlCache(byte[] data)
        {
            if (data.Length > IntelligenceCacheByteLimit) throw new ArgumentException("EDL cache exceeds 16 MiB.");
            var snapshots = JsonSerializer.Deserialize<EdlSnapshot[]>(data, JsonOptions) ?? throw new ArgumentException("Invalid EDL cache.");
            if (snapshots.Length > 8 || snapshots.Any(s => s is null) || snapshots.Select(s => s.FeedId).Distinct().Count() != snapshots.Length) throw new ArgumentException("Invalid EDL cache sources.");
            foreach (var snapshot in snapshots)
            {
                if (!ValidSnapshotFormat(snapshot) || !EdlId(snapshot.FeedId) || !EdlKind(snapshot.Kind) || !EdlUrl(snapshot.SourceUrl) || snapshot.FetchedAt.Kind != DateTimeKind.Utc || snapshot.Expires.Kind != DateTimeKind.Utc || snapshot.FetchedAt > DateTime.UtcNow.AddMinutes(1) || snapshot.Expires <= snapshot.FetchedAt || snapshot.Expires - snapshot.FetchedAt > TimeSpan.FromHours(168) || snapshot.Values is null || snapshot.Values.Length > 10000) throw new ArgumentException("Invalid EDL cache lifetime, source, or size.");
                if (snapshot.ContentSha256.Length > 0 && (snapshot.ContentSha256 != SnapshotHash(snapshot) || !snapshot.Values.SequenceEqual(snapshot.Values.Select(v => NormalizeEdlValue(snapshot.Kind, v)).Order(StringComparer.Ordinal)))) throw new ArgumentException("EDL snapshot integrity check failed.");
                if (snapshot.Values.Select(v => NormalizeEdlValue(snapshot.Kind, v)).Distinct(StringComparer.Ordinal).Count() != snapshot.Values.Length) throw new ArgumentException("Invalid or duplicate EDL cache entries.");
            }
            var normalized = snapshots.Select(s => s with { Values = s.Values.Select(v => NormalizeEdlValue(s.Kind, v)).Order(StringComparer.Ordinal).ToArray() }).ToArray();
            ValidateIntelligenceCache(normalized);
            return normalized;
        }
        static string NormalizeEdlValue(string kind, string value)
        {
            if (value is null || value.Length > 2048 || value.Any(c => char.IsControl(c) || char.IsWhiteSpace(c))) throw new ArgumentException("Invalid EDL entry.");
            // Plain typed lists only: no wildcard expansion, URL-to-host conversion or inline comments.
            if (kind == "Domain" && (value.Contains('*') || value.Contains('/') || IPAddress.TryParse(value, out _))) throw new ArgumentException("EDL domain must be an exact DNS name.");
            return Normalize([new("validation", kind, value, "Monitor", "EDL")])[0].Value;
        }
        void LoadEdlCache()
        {
            string path = Path.Combine(_folder, "security-edl.json");
            if (!File.Exists(path)) return;
            try { if (new FileInfo(path).Length > IntelligenceCacheByteLimit) throw new ArgumentException("EDL cache exceeds 16 MiB."); _edlSnapshots = ParseEdlCache(File.ReadAllBytes(path)); }
            catch (Exception ex) when (ex is JsonException || ex is ArgumentException || ex is FormatException || ex is IOException || ex is UnauthorizedAccessException) { _edlSnapshots = []; }
        }
        IEnumerable<ThreatIndicator> EdlIndicators(SecurityPolicy policy, EdlSnapshot[] snapshots = null)
        {
            if (!policy.Enabled) yield break;
            foreach (var feed in policy.EdlFeeds.Where(f => f.Enabled))
            {
                var snapshot = (snapshots ?? _edlSnapshots).SingleOrDefault(s => s.FeedId == feed.Id && s.Kind == feed.Kind && s.SourceUrl == feed.Url && s.Format == feed.Format && s.RpzZone == feed.RpzZone && (s.SourceConfiguration.Length == 0 || s.SourceConfiguration == SourceHash(feed)));
                if (snapshot is null || EffectiveExpiry(feed, snapshot) <= FeedNow || feed.SourceConfidence < feed.MinimumConfidence) continue;
                foreach (var value in snapshot.Values)
                {
                    string id = "edl:" + feed.Id + ":" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
                    string evidence = JsonSerializer.Serialize(new { sourceUrl = snapshot.SourceUrl, fetchedAt = snapshot.FetchedAt, feedId = feed.Id, format = snapshot.Format, contentSha256 = snapshot.ContentSha256, provenance = snapshot.Provenance, configuredProvenance = feed.Provenance, confidenceBasis = "Operator assessment; accuracy unverified" }, JsonOptions);
                    yield return new(id, feed.Kind, value, feed.Action, "EDL:" + feed.Id, feed.SourceConfidence, EffectiveExpiry(feed, snapshot), null, evidence);
                }
            }
        }
        Index BuildIndex(SecurityPolicy policy, IEnumerable<ThreatIndicator> misp = null, EdlSnapshot[] edl = null, CancellationToken cancellationToken = default) => new(policy.Indicators.Concat(misp ?? EnrichmentFor(policy)).Concat(EdlIndicators(policy, edl)), cancellationToken);
        public byte[] ExportEdl() { EdlSnapshot[] snapshots; lock (_sync) snapshots = _edlSnapshots; return SerializeIntelligenceCache(snapshots); }
        public void RestoreEdl(byte[] data)
        {
            EdlSnapshot[] snapshots = ParseEdlCache(data).Select(s => s with { CommitId = Guid.NewGuid().ToString("N") }).ToArray();
            using (_persistence.Enter())
            {
                SecurityPolicy policy = ReadPolicy(); Index index = BuildIndex(policy, edl: snapshots);
                Save("security-edl.json", snapshots);
                lock (_sync) { _edlSnapshots = snapshots; _index = index; _edlHealth.Clear(); _edlEpoch++; }
            }
        }
        public EdlHealth[] EdlStatus()
        {
            lock (_sync) return _policy.EdlFeeds.Select(feed =>
            {
                var snapshot = _edlSnapshots.SingleOrDefault(s => s.FeedId == feed.Id && s.Kind == feed.Kind && s.SourceUrl == feed.Url && s.Format == feed.Format && s.RpzZone == feed.RpzZone && (s.SourceConfiguration.Length == 0 || s.SourceConfiguration == SourceHash(feed)));
                var retained = _edlSnapshots.SingleOrDefault(s => s.FeedId == feed.Id);
                _edlHealth.TryGetValue(feed.Id, out var health);
                bool active = _policy.Enabled && snapshot is not null && EffectiveExpiry(feed, snapshot) > FeedNow && feed.SourceConfidence >= feed.MinimumConfidence;
                _edlSchedule.TryGetValue(feed.Id, out var schedule);
                if (schedule?.Configuration != FeedHash(feed)) schedule = null;
                bool committedReceipt = HasCommittedFeedReceipt(feed, schedule);
                return new EdlHealth(feed.Id, snapshot?.FetchedAt, health?.LastAttempt ?? schedule?.StartedAt, snapshot is null ? null : EffectiveExpiry(feed, snapshot), !_policy.Enabled ? "Policy disabled" : !feed.Enabled ? "Disabled" : snapshot is null ? retained is not null ? "Source changed; retained evidence inactive" : health?.Status ?? "Awaiting first refresh" : !active ? "Expired or below confidence threshold; evidence inactive" : health?.Status ?? "Cached evidence; source refresh required", feed.Enabled && active ? snapshot.Values.Length : 0) { RetainedEntries = retained?.Values.Length ?? 0, SnapshotGeneration = retained?.CommitId, IntegrityState = retained is null ? "None" : retained.ContentSha256.Length == 0 ? "LegacyUnchecked" : "VerifiedSha256", ValidatedAt = retained?.ValidatedAt, AttemptId = schedule?.AttemptId, AttemptOutcome = schedule is null ? "None" : committedReceipt ? "Succeeded" : schedule.Outcome == "Running" && _runningFeedAttempt != schedule.AttemptId ? "Interrupted" : schedule.Outcome, AttemptStartedAt = schedule?.StartedAt, AttemptCompletedAt = schedule?.CompletedAt, NextAttempt = schedule?.NextAttempt, ConsecutiveFailures = committedReceipt ? 0 : schedule?.Failures ?? 0, ContentSha256 = snapshot?.ContentSha256, SourceConfidence = feed.SourceConfidence, Provenance = feed.Provenance };
            }).ToArray();
        }
        public async Task RefreshEdlAsync(CancellationToken cancellationToken = default, bool scheduled = false, Func<bool> commitAuthorized = null, string feedId = null)
        {
            using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
            cancellationToken = lifetime.Token;
            if (!await _edlRefresh.WaitAsync(0, cancellationToken)) return;
            try
            {
                if (!ReadPolicy().Enabled) return;
                foreach (EdlFeed feed in ReadPolicy().EdlFeeds.Where(f => f.Enabled && (feedId is null || f.Id == feedId)))
                {
                    DateTime attempt = FeedNow; long epoch; string attemptId = null; bool committed = false;
                    try
                    {
                        using (await _persistence.EnterAsync(cancellationToken))
                        {
                            if (!ReadPolicy().EdlFeeds.Contains(feed)) continue;
                            lock (_sync) epoch = _edlEpoch;
                            if (scheduled && _edlSchedule.TryGetValue(feed.Id, out var due) && due.Configuration == FeedHash(feed) && due.NextAttempt > attempt) continue;
                            attemptId = SaveFeedAttempt(feed, attempt, false); // durable reservation before any network I/O
                        }
                        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(60));
                        lock (_sync) _feedCancellation[attemptId] = deadline;
                        using HttpRequestMessage request = new(HttpMethod.Get, feed.Url);
                        request.Headers.Accept.ParseAdd("text/plain");
                        if (feed.ApiKeyEnvironment.Length > 0)
                        {
                            string key = Environment.GetEnvironmentVariable(feed.ApiKeyEnvironment);
                            if (!SafeOpaqueCredential(key)) throw new ArgumentException("EDL credential must be a nonempty visible ASCII value without whitespace.");
                            if (feed.AuthScheme == "Raw") request.Headers.TryAddWithoutValidation("Authorization", key);
                            else request.Headers.Add("Authorization", feed.AuthScheme + " " + key);
                        }
                        using var response = await _mispClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
                        if (response.StatusCode != HttpStatusCode.OK) throw new HttpRequestException("EDL source returned a failure or redirect.");
                        if (response.Content.Headers.ContentType?.MediaType != "text/plain") throw new ArgumentException("EDL source must return text/plain.");
                        await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
                        using var bytes = new MemoryStream(); byte[] buffer = new byte[8192]; int read;
                        while ((read = await stream.ReadAsync(buffer, deadline.Token)) > 0) { if (bytes.Length + read > 2 * 1024 * 1024) throw new ArgumentException("EDL response exceeds 2 MiB."); bytes.Write(buffer, 0, read); }
                        string text = new UTF8Encoding(false, true).GetString(bytes.ToArray());
                        _feedCheckpoint?.Invoke("Fetched");
                        string[] values = ParseFeedText(feed, text);
                        _feedCheckpoint?.Invoke("Validated");
                        var snapshot = new EdlSnapshot(feed.Id, feed.Kind, feed.Url, attempt, attempt.AddHours(feed.CacheLifetimeHours), values) { Format = feed.Format, RpzZone = feed.RpzZone, CommitId = attemptId, SourceConfiguration = SourceHash(feed), Provenance = feed.Provenance, ValidatedAt = FeedNow };
                        snapshot = snapshot with { ContentSha256 = SnapshotHash(snapshot) };
                        using (await _persistence.EnterAsync(deadline.Token))
                        {
                            SecurityPolicy policy = ReadPolicy(); if (!policy.EdlFeeds.Contains(feed) || _edlEpoch != epoch || commitAuthorized?.Invoke() == false) { CompleteFeedAttempt(feed, attemptId, "Superseded"); continue; }
                            EdlSnapshot[] snapshots = _edlSnapshots.Where(s => s.FeedId != feed.Id && policy.EdlFeeds.Any(f => f.Id == s.FeedId)).Append(snapshot).ToArray();
                            deadline.Token.ThrowIfCancellationRequested();
                            Index index = BuildIndex(policy, edl: snapshots, cancellationToken: deadline.Token);
                            deadline.Token.ThrowIfCancellationRequested();
                            if (commitAuthorized?.Invoke() == false) { CompleteFeedAttempt(feed, attemptId, "Superseded"); continue; }
                            _feedCheckpoint?.Invoke("BeforePersist");
                            Save("security-edl.json", snapshots);
                            _feedCheckpoint?.Invoke("Persisted");
                            lock (_sync) { _edlSnapshots = snapshots; _index = index; _edlHealth[feed.Id] = new(feed.Id, attempt, attempt, snapshot.Expires, "Available", values.Length); }
                            committed = true;
                            _feedCheckpoint?.Invoke("Activated");
                            try { CompleteFeedAttempt(feed, attemptId, "Succeeded"); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { /* snapshot CommitId is the authoritative success receipt */ }
                        }
                        SharedStateChanged?.Invoke();
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested || IsFeedCancellation(attemptId)) { Finish(committed ? "Succeeded" : "Cancelled"); if (cancellationToken.IsCancellationRequested && !committed) throw; }
                    catch (Exception ex) when (ex is HttpRequestException || ex is IOException || ex is ArgumentException || ex is InvalidOperationException || ex is OperationCanceledException || ex is FormatException || ex is UnauthorizedAccessException)
                    { Finish(committed ? "Succeeded" : ex is OperationCanceledException ? "TimedOut" : "Failed"); lock (_sync) _edlHealth[feed.Id] = new(feed.Id, committed ? attempt : null, attempt, null, committed ? "Snapshot committed; change notification failed" : ex is OperationCanceledException ? "Refresh timed out; unexpired last complete cache retained" : "Refresh failed; unexpired last complete cache retained", 0); }
                    finally { lock (_sync) { _feedCancellation.Remove(attemptId ?? ""); _feedCancelRequested.Remove(attemptId ?? ""); if (_runningFeedAttempt == attemptId) _runningFeedAttempt = null; } }
                    void Finish(string outcome)
                    {
                        if (attemptId is null) return;
                        try
                        {
                            using (_persistence.Enter())
                            {
                                if (_edlSnapshots.Any(s => s.CommitId == attemptId)) outcome = "Succeeded";
                                CompleteFeedAttempt(feed, attemptId, outcome);
                            }
                        }
                        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { /* durable reservation reports interrupted unless snapshot receipt proves commit */ }
                    }
                }
            }
            finally { _edlRefresh.Release(); }
        }
        public EdlOutput PublishEdl(string id)
        {
                SecurityPolicy policy; ThreatIndicator[] misp; EdlSnapshot[] edl;
                lock (_sync) { policy = _policy; misp = EnrichmentFor(policy).ToArray(); edl = _edlSnapshots; }
                var publication = policy.EdlPublications.SingleOrDefault(p => p.Id == id && p.Enabled) ?? throw new ArgumentException("EDL publication is not enabled.");
                var selected = publication.Selected.ToHashSet(); DateTime now = DateTime.UtcNow;
                // Never read events, device signals, observed queries or inventory here.
                var intelligence = policy.Indicators.Concat(misp).Concat(EdlIndicators(policy, edl)).ToArray();
                var allows = policy.Indicators.Where(i => i.Action == "Allow" && string.IsNullOrEmpty(i.ClientNetwork) && (!i.Expires.HasValue || i.Expires > now)).ToArray();
                Index allowIndex = new(allows);
                var allowedUrls = allows.Where(a => a.Kind == "Url").Select(a => a.Value).ToHashSet(StringComparer.Ordinal);
                var allowedNetworks = allows.Where(a => a.Kind == "Network").Select(a => new Ipam.IpamNetwork(a.Value)).GroupBy(n => n.Bits).ToDictionary(g => g.Key, g =>
                {
                    BigInteger last = -1;
                    return g.OrderBy(n => n.First).Select(n => { last = BigInteger.Max(last, n.Last); return (n.First, Last: last); }).ToArray();
                });
                bool Exempt(ThreatIndicator indicator)
                {
                    if (indicator.Kind == "Domain") return allowIndex.Domain(indicator.Value, IPAddress.None, now).Any();
                    if (indicator.Kind == "Url") return allowedUrls.Contains(indicator.Value);
                    var network = new Ipam.IpamNetwork(indicator.Value);
                    if (!allowedNetworks.TryGetValue(network.Bits, out var ranges)) return false;
                    int low = 0, high = ranges.Length;
                    while (low < high) { int middle = (low + high) / 2; if (ranges[middle].First <= network.Last) low = middle + 1; else high = middle; }
                    return low > 0 && ranges[low - 1].Last >= network.First;
                }
                var included = intelligence.Where(i => selected.Contains(new(i.Source, i.Id)) && i.Kind == publication.Kind && i.Action != "Allow" && string.IsNullOrEmpty(i.ClientNetwork) && (!i.Expires.HasValue || i.Expires > now) && !Exempt(i)).ToArray();
                string text = string.Join('\n', included.Select(i => NormalizeEdlValue(i.Kind, i.Value)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));
                if (text.Length > 0) text += "\n";
                DateTime? expires = included.Where(i => i.Expires.HasValue).Select(i => i.Expires).Min();
                var present = included.Select(i => new EdlSelection(i.Source, i.Id)).ToHashSet();
                bool missing = publication.Selected.Any(s => !present.Contains(s));
                return new(id, publication.Kind, publication.IntendedAction, text, now, expires, missing ? "Selected evidence unavailable, expired, exempted, or incompatible" : included.Length == 0 ? "Empty selection" : "Available");
        }
    }
}
