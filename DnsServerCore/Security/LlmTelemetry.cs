// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DnsServerCore.Security
{
    public sealed record LlmTokenUsage(long Input, long Output, long Total);
    public sealed record LlmUsage(string Status, LlmTokenUsage Tokens = null)
    {
        public static LlmUsage Read(JsonElement response)
        {
            if (!response.TryGetProperty("usage", out var usage) || usage.ValueKind == JsonValueKind.Null) return new("Missing");
            bool Count(string name, out long n) { n = 0; return usage.ValueKind == JsonValueKind.Object && usage.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.Number && p.TryGetInt64(out n) && n >= 0 && n <= LlmTelemetry.MaxExact; }
            if (!Count("prompt_tokens", out long input) || !Count("completion_tokens", out long output) || !Count("total_tokens", out long total) || input > LlmTelemetry.MaxExact - output || input + output != total) return new("Invalid");
            return new("Reported", new(input, output, total));
        }
    }
    public sealed record LlmTotals(long Requests, long Success, long Failed, long Cancelled, long TimedOut, long Busy, long UsageReported, long UsageMissing, long UsageInvalid, long? InputTokens, long? OutputTokens, long? TotalTokens, bool Saturated);
    public sealed record LlmLatency(int Samples, double? P50Milliseconds, double? P95Milliseconds);
    public sealed record LlmTrend(DateTime Time, long? Requests, long? Success, long? Failed, long? Cancelled, long? TimedOut, long? Busy, long? InputTokens, long? OutputTokens, long? ReportedTokens, long? UsageReported, long? UsageUnknown);
    public sealed record LlmObservation(string Model, string Source, string Kind, string Outcome, DateTime Timestamp);
    public sealed record LlmMetrics(DateTime StartedAt, DateTime ObservedAt, double ObservedSeconds, int WindowMinutes, bool WindowComplete, bool WindowTruncated, int RetentionLimit, int InFlight, int Capacity, long StartedRequests, LlmTotals SinceRestart, LlmTotals Window, LlmLatency SuccessfulLatency, LlmObservation LastAttempt, LlmObservation LastSuccess, LlmObservation ConfiguredObservation, LlmTrend[] Trend);

    // Process-local, bounded, aggregate-only telemetry. No prompts, replies, addresses or keys are retained.
    public sealed class LlmTelemetry
    {
        public const long MaxExact = 9007199254740991; // JSON/JavaScript exact integer limit.
        readonly object _sync = new();
        readonly TimeProvider _clock;
        readonly int _limit;
        readonly long _started;
        readonly DateTime _startedAt;
        readonly Queue<Sample> _samples = new();
        readonly Dictionary<string, LlmObservation> _connections = new();
        readonly Totals _lifetime = new();
        long _startedRequests;
        long? _lastEvicted;
        int _inFlight;
        LlmObservation _lastAttempt, _lastSuccess;
        public LlmTelemetry(TimeProvider clock = null, int retentionLimit = 4096)
        {
            if (retentionLimit < 1 || retentionLimit > 4096) throw new ArgumentOutOfRangeException(nameof(retentionLimit));
            _clock = clock ?? TimeProvider.System; _limit = retentionLimit; _started = _clock.GetTimestamp(); _startedAt = _clock.GetUtcNow().UtcDateTime;
        }
        static string Identity(LlmSettings s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes((s?.Endpoint ?? "") + "\0" + (s?.Model ?? "") + "\0" + (s?.ApiKeyEnvironment ?? ""))));
        public sealed class Attempt
        {
            internal long Start;
            internal string Identity, Model, Source, Kind;
            internal bool Active, Finished;
        }
        sealed record Sample(long End, double Milliseconds, string Outcome, LlmUsage Usage);
        public Attempt Begin(LlmSettings settings, string kind)
        {
            lock (_sync)
            {
                _startedRequests = Add(_startedRequests, 1);
                string model = settings?.Model;
                if (model is null || model.Length > 128 || model.Any(char.IsControl)) model = "Unavailable";
                bool loopback = Uri.TryCreate(settings?.Endpoint, UriKind.Absolute, out var uri) && System.Net.IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && System.Net.IPAddress.IsLoopback(ip);
                return new() { Start = _clock.GetTimestamp(), Identity = Identity(settings), Model = model, Source = loopback ? "Loopback" : "Network", Kind = kind == "ConnectionTest" ? kind : "EventExplanation" };
            }
        }
        public void Acquired(Attempt request) { lock (_sync) { if (!request.Finished && !request.Active) { request.Active = true; _inFlight++; } } }
        public void Finish(Attempt request, string outcome, LlmUsage usage = null)
        {
            lock (_sync)
            {
                if (request.Finished) return;
                request.Finished = true; if (request.Active) _inFlight--;
                if (outcome is not ("Success" or "Failed" or "Cancelled" or "TimedOut" or "Busy")) outcome = "Failed";
                long now = _clock.GetTimestamp(); usage ??= new("Missing");
                var sample = new Sample(now, Math.Max(0, _clock.GetElapsedTime(request.Start, now).TotalMilliseconds), outcome, usage);
                _lifetime.Include(sample); Prune(now);
                if (_samples.Count == _limit) _lastEvicted = _samples.Dequeue().End;
                _samples.Enqueue(sample);
                _lastAttempt = new(request.Model, request.Source, request.Kind, outcome, _clock.GetUtcNow().UtcDateTime);
                if (outcome == "Success") _lastSuccess = _lastAttempt;
                if (!_connections.ContainsKey(request.Identity) && _connections.Count == 32) _connections.Remove(_connections.MinBy(p => p.Value.Timestamp).Key);
                _connections[request.Identity] = _lastAttempt;
            }
        }
        void Prune(long now) { while (_samples.Count > 0 && _clock.GetElapsedTime(_samples.Peek().End, now).TotalMinutes >= 60) _samples.Dequeue(); }
        static long Add(long a, long b) => a > MaxExact - b ? MaxExact : a + b;
        sealed class Totals
        {
            long _requests, _success, _failed, _cancelled, _timedOut, _busy, _reported, _missing, _invalid, _input, _output, _total;
            bool _saturated;
            void Sum(ref long field, long n) { if (field > MaxExact - n) _saturated = true; field = Add(field, n); }
            public void Include(Sample sample)
            {
                Sum(ref _requests, 1);
                switch (sample.Outcome) { case "Success": Sum(ref _success, 1); break; case "Failed": Sum(ref _failed, 1); break; case "Cancelled": Sum(ref _cancelled, 1); break; case "TimedOut": Sum(ref _timedOut, 1); break; case "Busy": Sum(ref _busy, 1); break; }
                if (sample.Usage.Status == "Reported" && sample.Usage.Tokens is not null) { Sum(ref _reported, 1); Sum(ref _input, sample.Usage.Tokens.Input); Sum(ref _output, sample.Usage.Tokens.Output); Sum(ref _total, sample.Usage.Tokens.Total); }
                else if (sample.Usage.Status == "Invalid") Sum(ref _invalid, 1); else Sum(ref _missing, 1);
            }
            public LlmTotals Read() => new(_requests, _success, _failed, _cancelled, _timedOut, _busy, _reported, _missing, _invalid, _reported > 0 ? _input : null, _reported > 0 ? _output : null, _reported > 0 ? _total : null, _saturated);
        }
        public LlmMetrics Snapshot(LlmSettings configured, int minutes = 60)
        {
            if (minutes is not (15 or 60)) throw new ArgumentException("Choose a 15 or 60 minute window.");
            lock (_sync)
            {
                long now = _clock.GetTimestamp(); Prune(now);
                double uptime = Math.Max(0, _clock.GetElapsedTime(_started, now).TotalSeconds);
                double Age(Sample s) => Math.Max(0, _clock.GetElapsedTime(s.End, now).TotalSeconds);
                var selected = _samples.Where(s => Age(s) < minutes * 60).ToArray();
                var totals = new Totals(); foreach (var sample in selected) totals.Include(sample);
                var latencies = selected.Where(s => s.Outcome == "Success").Select(s => s.Milliseconds).Order().ToArray();
                double? Percentile(double p) => latencies.Length == 0 ? null : latencies[Math.Max(0, (int)Math.Ceiling(latencies.Length * p) - 1)];
                var utc = _clock.GetUtcNow().UtcDateTime;
                var trend = new List<LlmTrend>();
                for (int i = minutes - 1; i >= 0; i--)
                {
                    double low = i * 60, high = (i + 1) * 60;
                    bool covered = uptime > low && (!_lastEvicted.HasValue || _clock.GetElapsedTime(_lastEvicted.Value, now).TotalSeconds >= high);
                    // The newest partial minute includes observations since process start; older uncovered buckets remain gaps.
                    if (i == 0 && uptime > 0 && (!_lastEvicted.HasValue || _clock.GetElapsedTime(_lastEvicted.Value, now).TotalSeconds >= high)) covered = true;
                    var bucket = new Totals(); foreach (var s in selected.Where(s => Age(s) >= low && Age(s) < high)) bucket.Include(s);
                    var t = bucket.Read();
                    trend.Add(new(utc.AddSeconds(-high), covered ? t.Requests : null, covered ? t.Success : null, covered ? t.Failed : null, covered ? t.Cancelled : null, covered ? t.TimedOut : null, covered ? t.Busy : null, covered ? t.InputTokens : null, covered ? t.OutputTokens : null, covered ? t.TotalTokens : null, covered ? t.UsageReported : null, covered ? t.UsageMissing + t.UsageInvalid : null));
                }
                _connections.TryGetValue(Identity(configured), out var observed);
                bool truncated = _lastEvicted.HasValue && _clock.GetElapsedTime(_lastEvicted.Value, now).TotalMinutes < minutes;
                return new(_startedAt, utc, Math.Min(uptime, minutes * 60), minutes, uptime >= minutes * 60 && !truncated, truncated, _limit, _inFlight, 2, _startedRequests, _lifetime.Read(), totals.Read(), new(latencies.Length, Percentile(.5), Percentile(.95)), _lastAttempt, _lastSuccess, observed, trend.ToArray());
            }
        }
    }
}
