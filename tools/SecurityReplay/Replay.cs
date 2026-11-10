// Copyright (c) 2026 Tekmyster Industries, LLC. GPL-3.0; see ../../LICENSE.
using DnsServerCore.Security;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

public sealed record ReplayManifest(int Version, bool Synthetic, string Source, string License,
    string PermissionReference, string PrivacyReference, string ConsentReference, string RevocationReference,
    string Selection, string LabelProvenance, string FeatureProvenance, string PartitionProtocol,
    string Owner, string CollectionMethod, string ProcessingConstraints, string RetentionReference, DateTime ProtocolFrozenAt,
    DateTime RightsCheckedAt, DateTime RightsExpireAt, bool Revoked, DateTime AsOf, DateTime CollectedAt,
    string DetectorSha256, string PslSha256, int AlertThreshold,
    ReplayRow[] Rows, Exposure[] Exposures, Incident[] Incidents);
public sealed record ReplayRow(string Id, string Device, string IndependentGroup, string Partition,
    DateTime At, string Query, string Type, bool NxDomain, string Label, string LabelReference, DateTime? LabelAvailableAt);
public sealed record Exposure(string Device, DateTime Start, DateTime End, string Label,
    bool CompleteObservation, string EvidenceReference);
public sealed record Incident(string Id, string Device, string Domain, DateTime? Start, DateTime End, string LabelReference, double? OnsetUncertaintySeconds);
public sealed record ReplayPrediction(string Id, string Device, DateTime At, string Domain, string Label,
    string Prediction, int Score, int Samples, bool SampleLimited, string Action, string FeatureSha256);

public static class Replay
{
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true
    };
    public static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    static bool Digest(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    static bool Text(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 2048;
    static bool Utc(DateTime t) => t.Kind == DateTimeKind.Utc && t != DateTime.MinValue;
    static bool Label(string? l) => l is "Benign" or "Suspicious" or "Unknown";
    static void Require(bool valid, string reason) { if (!valid) throw new ArgumentException(reason); }

    public static object Run(string manifestPath, string pslPath, CancellationToken cancellation = default)
    {
        byte[] input = BoundedRead(manifestPath, 16 * 1024 * 1024);
        using (var document = JsonDocument.Parse(input)) ValidateJson(document.RootElement);
        var manifest = JsonSerializer.Deserialize<ReplayManifest>(input, Json) ?? throw new ArgumentException("Manifest is missing.");
        byte[] psl = BoundedRead(pslPath, 4 * 1024 * 1024);
        return Evaluate(manifest, input, psl, cancellation);
    }
    public static void CheckPublication(string manifestPath, string expectedHash)
    {
        byte[] current = BoundedRead(manifestPath, 16 * 1024 * 1024);
        Require(Hash(current) == expectedHash, "Input changed or rights were withdrawn during processing; publication refused.");
        var m = JsonSerializer.Deserialize<ReplayManifest>(current, Json)!;
        Require(!m.Revoked && m.RightsCheckedAt <= DateTime.UtcNow && m.RightsExpireAt > DateTime.UtcNow,
            "Rights assertion expired or was revoked; publication refused.");
    }
    public static void VerifyReport(string manifestPath, string reportPath)
    {
        using var report = JsonDocument.Parse(BoundedRead(reportPath, 32 * 1024 * 1024));
        ValidateJson(report.RootElement);
        var envelope = report.RootElement;
        Require(envelope.GetProperty("version").GetInt32() == 1, "Unsupported result envelope version.");
        var payload = envelope.GetProperty("payload");
        Require(payload.GetProperty("protocol").GetString() == "heuristic-offline-replay-v1" &&
            envelope.GetProperty("sha256").GetString() == Hash(JsonSerializer.SerializeToUtf8Bytes(payload)), "Unsupported or corrupt replay report.");
        CheckPublication(manifestPath, payload.GetProperty("inputSha256").GetString()!);
    }
    static byte[] BoundedRead(string path, int max)
    {
        using var stream = File.OpenRead(path);
        Require(stream.Length <= max, "Input exceeds its byte limit.");
        using var data = new MemoryStream();
        byte[] buffer = new byte[8192]; int count;
        while ((count = stream.Read(buffer)) > 0)
        {
            Require(data.Length + count <= max, "Input grew beyond its byte limit.");
            data.Write(buffer, 0, count);
        }
        return data.ToArray();
    }
    static void ValidateJson(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var properties = element.EnumerateObject().ToArray();
            Require(properties.Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == properties.Length, "Duplicate JSON fields are ambiguous.");
            foreach (var p in properties) ValidateJson(p.Value);
        }
        else if (element.ValueKind == JsonValueKind.Array) foreach (var item in element.EnumerateArray()) ValidateJson(item);
    }

    public static object Evaluate(ReplayManifest m, byte[] input, byte[] psl, CancellationToken cancellation = default)
    {
        var budget = Stopwatch.StartNew();
        void CheckBudget()
        {
            cancellation.ThrowIfCancellationRequested();
            if (budget.Elapsed > TimeSpan.FromSeconds(60)) throw new InvalidOperationException("Offline work exceeded its 60-second cooperative limit; no completed result.");
        }
        CheckBudget();
        Require(m.Version == 1 && m.AlertThreshold is >= 1 and <= 100, "Version 1 and an explicit threshold from 1 to 100 are required.");
        Require(new[] { m.Source, m.License, m.PermissionReference, m.PrivacyReference, m.ConsentReference,
            m.RevocationReference, m.Selection, m.LabelProvenance, m.FeatureProvenance, m.PartitionProtocol,
            m.Owner, m.CollectionMethod, m.ProcessingConstraints, m.RetentionReference }.All(Text), "Supply owner/source, processing/retention/rights, privacy/consent/revocation, label, feature, selection and partition references.");
        Require(Utc(m.AsOf) && Utc(m.CollectedAt) && Utc(m.RightsCheckedAt) && Utc(m.RightsExpireAt) &&
            m.CollectedAt <= m.AsOf && m.AsOf <= DateTime.UtcNow && m.RightsCheckedAt <= m.AsOf && m.RightsExpireAt > m.AsOf && !m.Revoked &&
            m.RightsCheckedAt <= DateTime.UtcNow && m.RightsExpireAt > DateTime.UtcNow,
            "Current non-revoked rights assertions and UTC collection/evaluation times are required.");
        Require(Utc(m.ProtocolFrozenAt) && m.ProtocolFrozenAt <= m.RightsCheckedAt && m.ProtocolFrozenAt <= m.AsOf,
            "Record the selection/label/threshold protocol freeze before the processing rights check and evaluation.");
        string core = Hash(File.ReadAllBytes(typeof(BehavioralAnalyzer).Assembly.Location));
        Require(m.DetectorSha256 == core && m.PslSha256 == Hash(psl), "Detector or PSL bytes differ from the frozen manifest.");
        Require(m.Rows is { Length: > 0 and <= 10000 } && m.Exposures is { Length: <= 10000 } && m.Incidents is { Length: <= 1000 }, "Supply bounded rows, exposures and incidents arrays.");
        var rows = m.Rows!;
        Require(rows.All(r => r is not null && Digest(r.Id) && Digest(r.Device) && Digest(r.IndependentGroup) &&
            r.Partition is "Train" or "Validation" or "Test" && Utc(r.At) && r.At <= m.CollectedAt && Label(r.Label) &&
            Text(r.LabelReference) && (r.LabelAvailableAt is null ? r.Label == "Unknown" : Utc(r.LabelAvailableAt.Value) && r.LabelAvailableAt <= m.AsOf) &&
            Text(r.Query) && r.Type is { Length: > 0 and <= 16 } && r.Type.All(c => char.IsAsciiLetterUpper(c) || char.IsAsciiDigit(c))), "Rows require digests, UTC times, partition, known/Unknown label and available label provenance, and DNS input.");
        Require(rows.Select(r => r.Id).Distinct().Count() == rows.Length, "Duplicate observation IDs.");
        Require(rows.Zip(rows.Skip(1), (a, b) => a.At <= b.At).All(x => x), "Rows must already be in chronological replay order.");
        foreach (var group in rows.GroupBy(r => r.Device).Concat(rows.GroupBy(r => r.IndependentGroup)))
        {
            CheckBudget();
            Require(group.Select(r => r.Partition).Distinct().Count() == 1, "Device or independent source/family group leaks across partitions.");
        }
        DateTime? cutoff = null;
        foreach (string partition in new[] { "Train", "Validation", "Test" })
        {
            var subset = rows.Where(r => r.Partition == partition).ToArray();
            if (subset.Length == 0) continue;
            Require(cutoff is null || subset.Min(r => r.At) > cutoff, "Partitions must be strictly separated in time.");
            cutoff = subset.Max(r => r.At);
        }
        var test = rows.Where(r => r.Partition == "Test").ToArray();
        Require(test.Length > 0, "At least one final Test observation is required.");
        var suffixes = new PublicSuffixes(System.Text.Encoding.UTF8.GetString(psl).Split('\n'));
        foreach (var r in rows) PublicSuffixes.Normalize(r.Query);
        Require(rows.Select(r => (r.Device, r.At, Query: PublicSuffixes.Normalize(r.Query), r.Type, r.NxDomain)).Distinct().Count() == rows.Length,
            "Exact repeated observation units require explicit upstream deduplication; new IDs do not establish independence.");
        var exposures = m.Exposures!;
        Require(exposures.All(e => e is not null && Digest(e.Device) && Utc(e.Start) && Utc(e.End) && e.Start < e.End && e.End <= m.CollectedAt && Label(e.Label) && e.CompleteObservation && Text(e.EvidenceReference) && test.Any(r => r.Device == e.Device)), "Exposure needs a test device, positive UTC interval, complete-observation assertion and evidence reference.");
        List<Exposure> union = [];
        foreach (var group in exposures.GroupBy(e => e.Device).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            CheckBudget();
            var ordered = group.OrderBy(e => e.Start).ToArray();
            var current = ordered[0];
            for (int i = 1; i < ordered.Length; i++)
            {
                var next = ordered[i];
                Require(next.Start >= current.End || next.Label == current.Label, "Overlapping coverage has contradictory labels.");
                if (next.Start <= current.End && next.Label == current.Label)
                    current = current with { End = next.End > current.End ? next.End : current.End };
                else { union.Add(current); current = next; }
            }
            union.Add(current);
        }
        // If exposure is supplied, require the whole evaluated cohort to have matching measured coverage.
        Require(exposures.Length == 0 || test.All(r => exposures.Any(e => e.Device == r.Device && e.Start <= r.At && r.At < e.End && e.Label == r.Label)), "Every test row needs matching labeled exposure when an exposure denominator is supplied.");
        var incidents = m.Incidents!;
        Require(incidents.All(i => i is not null && Text(i.Id) && Digest(i.Device) && Text(i.Domain) &&
            (i.Start is null || Utc(i.Start.Value) && i.Start < i.End) && Utc(i.End) && i.End <= m.CollectedAt &&
            (i.OnsetUncertaintySeconds is null || double.IsFinite(i.OnsetUncertaintySeconds.Value) && i.OnsetUncertaintySeconds >= 0) &&
            Text(i.LabelReference) && test.Any(r => r.Device == i.Device)), "Incidents require explicit matching identity, domain, time bounds and label evidence.");
        Require(incidents.Select(i => i.Id).Distinct().Count() == incidents.Length, "Duplicate incident IDs.");
        foreach (var i in incidents)
        {
            CheckBudget();
            Require(suffixes.RegistrableDomain(i.Domain) == i.Domain, "Incident domain must be a normalized registrable domain.");
            Require(!incidents.Any(j => j != i && j.Device == i.Device && j.Domain == i.Domain && j.Start < i.End && i.Start < j.End), "Matching incident intervals overlap.");
            Require(!test.Any(r => r.Device == i.Device && suffixes.RegistrableDomain(r.Query) == i.Domain && r.At >= i.Start && r.At < i.End && r.Label != "Suspicious"), "Incident conflicts with observation labels.");
        }
        var analyzer = new BehavioralAnalyzer(suffixes);
        List<ReplayPrediction> predictions = [];
        var watch = Stopwatch.StartNew();
        foreach (var r in test)
        {
            CheckBudget();
            var score = analyzer.Observe(r.Device, r.Query, r.Type, r.NxDomain, r.At);
            bool alert = score.Score >= m.AlertThreshold;
            predictions.Add(new(r.Id, r.Device, r.At, score.Domain, r.Label, alert ? "Suspicious" : "Benign",
                score.Score, score.Samples, score.SampleLimited, alert ? "Monitor" : "BelowAlertThreshold",
                Hash(JsonSerializer.SerializeToUtf8Bytes(score.FeatureVector, Json))));
        }
        watch.Stop();
        var metrics = Metrics(predictions);
        double totalDays = union.Sum(e => (e.End - e.Start).TotalDays);
        double benignDays = union.Where(e => e.Label == "Benign").Sum(e => (e.End - e.Start).TotalDays);
        var delay = incidents.Select(i =>
        {
            var matched = predictions.Where(p => i.Start.HasValue && p.Device == i.Device && p.Domain == i.Domain && p.At >= i.Start && p.At < i.End && p.Label == "Suspicious").ToArray();
            var first = matched.FirstOrDefault(p => p.Prediction == "Suspicious");
            double followUp = !i.Start.HasValue ? 0 : union.Where(e => e.Device == i.Device && e.Label == "Suspicious" && e.Start < i.End && e.End > i.Start)
                .Sum(e => ((e.End < i.End ? e.End : i.End) - (e.Start > i.Start.Value ? e.Start : i.Start.Value)).TotalSeconds);
            double? horizon = i.Start.HasValue ? (i.End - i.Start.Value).TotalSeconds : null;
            bool covered = horizon.HasValue && Math.Abs(followUp - horizon.Value) < 1e-6;
            return new { i.Id, i.OnsetUncertaintySeconds, ObservedRows = matched.Length, FirstDetection = first?.At,
                DelaySeconds = first is null || !covered ? (double?)null : (first.At - i.Start!.Value).TotalSeconds,
                HorizonSeconds = horizon, ObservedFollowUpSeconds = followUp, CompleteFollowUp = covered,
                RightCensored = first is null && covered,
                PreOnsetAlerts = i.Start.HasValue ? predictions.Count(p => p.Device == i.Device && p.Domain == i.Domain && p.At < i.Start && p.Prediction == "Suspicious") : 0,
                Status = !i.Start.HasValue ? "Onset unavailable" : matched.Length == 0 ? "No matched observations" : !covered ? "Incomplete observation coverage" : first is null ? "Not detected in observed interval" : "Matched detection" };
        }).ToArray();
        CheckBudget();
        return new
        {
            Protocol = "heuristic-offline-replay-v1", Scope = m.Synthetic ? "Synthetic mechanical fixture only; no quality proof" : "Supplied cohort only; rights, labels and representativeness need independent review",
            RunnerSha256 = Hash(File.ReadAllBytes(typeof(Replay).Assembly.Location)),
            RunId = Hash(System.Text.Encoding.UTF8.GetBytes(Hash(input) + core + Hash(psl) + Hash(File.ReadAllBytes(typeof(Replay).Assembly.Location)) + "heuristic-offline-replay-v1")),
            AttemptId = Guid.NewGuid().ToString("N"), ProcessId = Environment.ProcessId, Host = Environment.MachineName,
            Runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            BuildConfiguration = typeof(Replay).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyConfigurationAttribute), false).Cast<System.Reflection.AssemblyConfigurationAttribute>().Single().Configuration,
            Clock = "Each supplied Test observation UTC drives the actual rolling analyzer; state cold at first Test row. Rights checked at actual processing/publication UTC. No timestamp rewrite.",
            EmpiricallyQualified = false, m.Synthetic, m.AsOf, InputBytes = input.Length, InputSha256 = Hash(input), DetectorSha256 = core,
            PslSha256 = Hash(psl), FeatureSourceSha256 = suffixes.VersionSha256,
            FeatureDefinitionSha256 = PredictiveModelRegistry.FeatureDefinitionSha256, m.AlertThreshold,
            Provenance = new { m.Source, m.Owner, m.CollectionMethod, m.License, m.ProcessingConstraints, m.RetentionReference, m.PermissionReference, m.PrivacyReference, m.ConsentReference, m.RevocationReference, m.RightsCheckedAt, m.RightsExpireAt, m.Selection, m.LabelProvenance, m.FeatureProvenance, m.PartitionProtocol, m.ProtocolFrozenAt },
            Partitions = rows.GroupBy(r => r.Partition).Select(g => new { Partition = g.Key, Rows = g.Count(), Devices = g.Select(r => r.Device).Distinct().Count(), First = g.Min(r => r.At), Last = g.Max(r => r.At), Sha256 = Hash(JsonSerializer.SerializeToUtf8Bytes(g.ToArray(), Json)) }).ToArray(),
            Metrics = metrics, ObservedDeviceDays = exposures.Length == 0 ? (double?)null : totalDays,
            BenignObservedDeviceDays = exposures.Length == 0 ? (double?)null : benignDays,
            FalsePositiveAlertsPerObservedDeviceDay = totalDays > 0 ? metrics.FalsePositive / totalDays : (double?)null,
            FalsePositiveAlertsPerBenignObservedDeviceDay = benignDays > 0 ? metrics.FalsePositive / benignDays : (double?)null,
            ExposureSha256 = Hash(JsonSerializer.SerializeToUtf8Bytes(exposures, Json)),
            ExposureUnion = union.Select(e => new { e.Device, e.Start, e.End, e.Label }).ToArray(), Delay = delay,
            Throughput = new { ImportedRows = rows.Length, ProcessedRows = test.Length, NotReplayedPartitionRows = rows.Length - test.Length, DroppedTestRows = 0,
                Seconds = watch.Elapsed.TotalSeconds, RowsPerSecond = watch.Elapsed.TotalSeconds > 0 ? test.Length / watch.Elapsed.TotalSeconds : (double?)null,
                Concurrency = 1, State = "Cold independent analyzer; JIT/cache warmness uncontrolled",
                Scope = "Finite local analyzer loop plus receipt construction; excludes import/validation/report I/O; no production SLA" },
            PolicyDecision = "Not evaluated", LearnedAdvisory = "Not evaluated", Enforcement = "No operational action",
            Predictions = predictions.Select(p => new { p.Id, p.Device, p.At, DomainSha256 = Hash(System.Text.Encoding.UTF8.GetBytes(p.Domain)), p.Label, p.Prediction, p.Score, p.Samples, p.SampleLimited, ConsumerOutcome = p.Action, p.FeatureSha256 }).ToArray(),
            Limitations = new[] { "Cold Test replay only: Train/Validation rows are validated and hashed but never used for fitting, tuning or warmup.", "No learned-model evaluation; the existing served-advice-v2 evaluation remains separate. Heuristic scoring has no abstention: sparse/sampled flags are reported without changing actual decisions.", "Monitor denotes offline heuristic alert consumption only; the policy matcher is not evaluated. No DNS blocking, shared device signals, MISP/EDL input or publication is exercised. Binary negative prediction means below-threshold, not proof the query is benign.", "FP numerator counts benign per-observation alerts, including repeats; exposure is supplied measured coverage, never inferred from query count or first/last observation. Empty exposure means rates unavailable.", "Delay uses supplied device/domain/incident bounds and matched suspicious timestamps only; misses/unobserved incidents remain explicit, not zero-delay samples. Complete supplied coverage across the whole incident horizon is required for delay.", "Digests and grouping are supplied assertions. Independent family/source grouping, privacy, consent, current rights, revocation, sample selection, final-test reuse and representativeness require review. No global dataset-absence or quality claim." }
        };
    }

    public sealed record Counts(int Total, int UnknownLabels, int UnknownPredictedPositive, int TruePositive, int FalsePositive,
        int TrueNegative, int FalseNegative, int AbstainedBenign, int AbstainedSuspicious, int UnknownAbstained)
    {
        public int Known => Total - UnknownLabels;
        public int ClassifiedKnown => TruePositive + FalsePositive + TrueNegative + FalseNegative;
        public int UnknownPredictedNegative => UnknownLabels - UnknownPredictedPositive - UnknownAbstained;
        public double? CoverageKnown => Known == 0 ? null : (double)ClassifiedKnown / Known;
        public double? Precision => TruePositive + FalsePositive == 0 ? null : (double)TruePositive / (TruePositive + FalsePositive);
        public double? RecallAmongClassified => TruePositive + FalseNegative == 0 ? null : (double)TruePositive / (TruePositive + FalseNegative);
        public double? KnownSuspiciousDetectionFraction => TruePositive + FalseNegative + AbstainedSuspicious == 0 ? null : (double)TruePositive / (TruePositive + FalseNegative + AbstainedSuspicious);
    }
    public static Counts Metrics(IEnumerable<ReplayPrediction> values)
    {
        var p = values.ToArray();
        Require(p.All(x => Label(x.Label) && x.Prediction is "Suspicious" or "Benign" or "Abstain"), "Invalid metric label/decision.");
        int Count(string label, string prediction) => p.Count(x => x.Label == label && x.Prediction == prediction);
        return new(p.Length, p.Count(x => x.Label == "Unknown"), Count("Unknown", "Suspicious"), Count("Suspicious", "Suspicious"), Count("Benign", "Suspicious"), Count("Benign", "Benign"), Count("Suspicious", "Benign"), Count("Benign", "Abstain"), Count("Suspicious", "Abstain"), Count("Unknown", "Abstain"));
    }
}
