// Copyright (c) 2026 Tekmyster Industries, LLC.
// This file is part of teQtanium and is licensed under GPL-3.0-or-later.
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
    public sealed record LearningRow(string ObservationSha256, string DeviceGroupSha256, DateTime ObservedAt, string Partition, string Label, double[] Features)
    { public bool SampleLimited { get; init; } }
    public sealed record LearningDataset(string Source, string License, string PermissionBasis, string Selection, string LabelProvenance, string PrivacyBasis, DateTime CollectedAt, bool Synthetic, string FeatureSchema, LearningRow[] Rows)
    { public string FeatureSourceSha256 { get; init; } }
    public sealed record DatasetReceipt(string Sha256, string Source, string License, string PermissionBasis, string Selection, string LabelProvenance, string PrivacyBasis, DateTime CollectedAt, bool Synthetic, int Rows, int TrainRows, int EvaluationRows, int MissingValues, DateTime FirstObservation, DateTime LastObservation)
    {
        public string FeatureSourceSha256 { get; init; }
        public string TrainPartitionSha256 { get; init; }
        public string EvaluationPartitionSha256 { get; init; }
        public int TrainGroups { get; init; }
        public int EvaluationGroups { get; init; }
        public DateTime TrainingCutoff { get; init; }
    }
    public sealed record AbstentionReason(string Reason, int Rows);
    public sealed record HeldOutResults(int TruePositive, int FalsePositive, int TrueNegative, int FalseNegative, string Scope)
    {
        public string Protocol { get; init; }
        public DateTime AsOf { get; init; }
        public int TotalRows { get; init; }
        public int EligibleRows { get; init; }
        public int UnknownLabels { get; init; }
        public int AbstainedBenign { get; init; }
        public int AbstainedSuspicious { get; init; }
        public AbstentionReason[] AbstentionReasons { get; init; } = [];
        public int Classified => TruePositive + FalsePositive + TrueNegative + FalseNegative;
        public int Abstained => AbstainedBenign + AbstainedSuspicious;
        public double? Coverage => EligibleRows == 0 ? null : (double)Classified / EligibleRows;
        public double? Precision => TruePositive + FalsePositive == 0 ? null : (double)TruePositive / (TruePositive + FalsePositive);
        public double? RecallAmongClassified => TruePositive + FalseNegative == 0 ? null : (double)TruePositive / (TruePositive + FalseNegative);
        public double? KnownSuspiciousDetectionFraction => TruePositive + FalseNegative + AbstainedSuspicious == 0 ? null : (double)TruePositive / (TruePositive + FalseNegative + AbstainedSuspicious);
    }
    public sealed record LearnedBaseline(string DeviceGroupSha256, int Samples, DateTime LastObservation, double[] Mean);
    public sealed record AdvisoryModel(string Id, string FeatureSchema, string Algorithm, DateTime CreatedAt, DateTime ExpiresAt, string Actor, DatasetReceipt Dataset, double[] BenignMean, double[] SuspiciousMean, HeldOutResults Evaluation, LearnedBaseline[] Baselines)
    {
        public string FeatureDefinitionSha256 { get; init; } = PredictiveModelRegistry.FeatureDefinitionSha256;
        public string ArtifactSha256 { get; init; } = "";
    }
    public sealed record ModelRegistry(long Revision, string Selected, string Previous, AdvisoryModel[] Models, string Status)
    { public string[] RetiredDatasets { get; init; } = []; }
    public sealed record PredictiveAdvice(string Mode, string Status, string ModelId, string Label, string BaselineStatus, double? BaselineDistance, string Confidence);

    // This registry has no reference to policy, signals, DHCP authority or DNS response actions.
    // Training is an explicit local management operation; inference is requested against retained evidence.
    public sealed class PredictiveModelRegistry
    {
        public const string Schema = "dns-domain-window-v1";
        public const string FeatureDefinition = "dns-domain-window-v1; domain/hour; order=long-label-ratio,high-entropy-ratio,TXT-ratio,NXDOMAIN-ratio,distinct-prefix-fingerprint-ratio,DGA-lexical-ratio,samples/512; units=[0,1]; missing=reject; no imputation/scaling; arithmetic class means; nearest-centroid RMSE; ties=Benign; abstain=min-distance>0.35 or margin<0.05; baseline=benign-training-mean,min20distincttimes,span>=1hour,age<=7days; seed=none; evaluation=served-advice-v2,as-of-training-operation-UTC,shared-observation/model/source/support-gates,abstentions-excluded-from-confusion-and-counted-by-label-and-reason";
        public static string FeatureDefinitionSha256 => Hash(Encoding.UTF8.GetBytes(FeatureDefinition));
        const int Dimensions = 7;
        const int RegistryByteLimit = 4 * 1024 * 1024;
        readonly object _gate = new();
        readonly string _file;
        int _training;
        ModelRegistry _state = new(0, "", "", [], "Empty");
        public PredictiveModelRegistry(string folder)
        {
            _file = Path.Combine(folder, "security-advisory-models.json");
            try
            {
                if (!File.Exists(_file)) return;
                using var stream = new FileStream(_file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (stream.Length > RegistryByteLimit) throw new InvalidDataException("Stored registry exceeds 4 MiB.");
                // Enforce the bound on actual reads as well as initial length: a concurrent
                // writer cannot make File.ReadAllBytes grow beyond the documented limit.
                byte[] bytes = new byte[RegistryByteLimit + 1];
                int count = 0, read;
                while (count < bytes.Length && (read = stream.Read(bytes, count, bytes.Length - count)) > 0) count += read;
                if (count > RegistryByteLimit) throw new InvalidDataException("Stored registry exceeds 4 MiB.");
                var envelope = JsonSerializer.Deserialize<Envelope>(bytes.AsSpan(0, count), DdiSecurityManager.JsonOptions) ?? throw new InvalidDataException("Missing registry envelope.");
                if (envelope.Payload is null || !Digest(envelope.Sha256) || Hash(Encoding.UTF8.GetBytes(envelope.Payload)) != envelope.Sha256) throw new InvalidDataException("Invalid registry payload integrity.");
                var state = JsonSerializer.Deserialize<ModelRegistry>(envelope.Payload, DdiSecurityManager.JsonOptions) ?? throw new InvalidDataException();
                if (!ValidStoredState(state)) throw new InvalidDataException("Invalid or unsupported stored registry.");
                _state = state;
            }
            catch (Exception ex) when (ex is InvalidDataException || ex is IOException || ex is UnauthorizedAccessException || ex is JsonException)
            { _state = new(0, "", "", [], "Invalid stored registry; deterministic fallback"); }
        }
        sealed record Envelope(string Payload, string Sha256);
        static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        static string ModelHash(AdvisoryModel model) => Hash(JsonSerializer.SerializeToUtf8Bytes(model with { ArtifactSha256 = "" }, DdiSecurityManager.JsonOptions));
        static bool Digest(string text) => text is not null && text.Length == 64 && text.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
        static bool Text(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 1024;
        static bool Vector(double[] values) => values is not null && values.Length == Dimensions && values.All(v => double.IsFinite(v) && v >= 0 && v <= 1);
        static double Distance(double[] a, double[] b) => Math.Sqrt(a.Zip(b, (x, y) => (x - y) * (x - y)).Average());
        static double[] Mean(IEnumerable<LearningRow> rows) => Enumerable.Range(0, Dimensions).Select(i => rows.Average(r => r.Features[i])).ToArray();
        static bool Valid(AdvisoryModel m) => m is not null && Digest(m.Id) && m.FeatureSchema == Schema && m.Algorithm == "nearest-centroid-v1" && m.CreatedAt.Kind == DateTimeKind.Utc && m.CreatedAt <= DateTime.MaxValue.AddDays(-30) && m.ExpiresAt.Kind == DateTimeKind.Utc && m.ExpiresAt > m.CreatedAt && m.ExpiresAt <= m.CreatedAt.AddDays(30) && Text(m.Actor) && m.Dataset is not null && Digest(m.Dataset.Sha256) && m.Dataset.CollectedAt <= m.CreatedAt && Vector(m.BenignMean) && Vector(m.SuspiciousMean) && Distance(m.BenignMean, m.SuspiciousMean) >= .05 && m.Evaluation is not null && m.Baselines is not null && m.Baselines.Length <= 1024 && m.Baselines.All(b => b is not null && Digest(b.DeviceGroupSha256) && b.Samples is >= 20 and <= 10000 && Vector(b.Mean) && b.LastObservation.Kind == DateTimeKind.Utc && b.LastObservation <= m.CreatedAt) && m.Baselines.Select(b => b.DeviceGroupSha256).Distinct().Count() == m.Baselines.Length;
        static bool ValidStoredState(ModelRegistry s) => s.Revision >= 0 && s.Selected is not null && s.Previous is not null && s.Status is not null && s.Status.Length <= 2048 &&
            s.RetiredDatasets is not null && s.RetiredDatasets.Length <= 128 && s.RetiredDatasets.All(Digest) && s.RetiredDatasets.Distinct().Count() == s.RetiredDatasets.Length &&
            s.Models is not null && s.Models.Length <= 16 && s.Models.All(m => Valid(m) && ValidReceipt(m.Dataset) && Quality(m) && !s.RetiredDatasets.Contains(m.Id) && m.FeatureDefinitionSha256 == FeatureDefinitionSha256 && Digest(m.ArtifactSha256) && m.ArtifactSha256 == ModelHash(m)) &&
            s.Models.Select(m => m.Id).Distinct().Count() == s.Models.Length && (s.Selected == "" || s.Models.Any(m => m.Id == s.Selected)) && (s.Previous == "" || s.Models.Any(m => m.Id == s.Previous));
        // Shared by held-out reporting and serving. Integrity/admission checks remain outside
        // this kernel because an evaluation report is generated before artifact hashing.
        static (string Label, string Reason) Decide(AdvisoryModel model, double[] features, DateTime observedAt, bool sampleLimited, DateTime now, string featureSourceSha256)
        {
            if (now.Kind != DateTimeKind.Utc || observedAt.Kind != DateTimeKind.Utc || observedAt > now || now - observedAt > TimeSpan.FromHours(1) || sampleLimited || !Vector(features)) return (null, "Missing, stale, sampled or incompatible observations");
            if (model.FeatureDefinitionSha256 != FeatureDefinitionSha256 || model.Dataset.FeatureSourceSha256 != featureSourceSha256 || model.CreatedAt > now || model.ExpiresAt <= now || now - model.Dataset.LastObservation > TimeSpan.FromDays(30)) return (null, "Stale or incompatible model/feature source");
            double benign = Distance(features, model.BenignMean), suspicious = Distance(features, model.SuspiciousMean);
            if (Math.Min(benign, suspicious) > .35 || Math.Abs(benign - suspicious) < .05) return (null, "Outside training support or ambiguous class; deterministic fallback");
            return (benign <= suspicious ? "Benign" : "Suspicious", "Advisory only");
        }
        static bool ValidReceipt(DatasetReceipt d) => Text(d.Source) && Text(d.License) && Text(d.PermissionBasis) && Text(d.Selection) && Text(d.LabelProvenance) && Text(d.PrivacyBasis) && Digest(d.FeatureSourceSha256) && Digest(d.TrainPartitionSha256) && Digest(d.EvaluationPartitionSha256) && d.Rows is >= 60 and <= 10000 && d.TrainRows is >= 40 and <= 10000 && d.EvaluationRows is >= 20 and <= 10000 && d.Rows == d.TrainRows + d.EvaluationRows && d.MissingValues == 0 && d.TrainGroups > 0 && d.TrainGroups <= d.TrainRows && d.EvaluationGroups > 0 && d.EvaluationGroups <= d.EvaluationRows && d.FirstObservation.Kind == DateTimeKind.Utc && d.LastObservation.Kind == DateTimeKind.Utc && d.TrainingCutoff.Kind == DateTimeKind.Utc && d.CollectedAt.Kind == DateTimeKind.Utc && d.FirstObservation <= d.TrainingCutoff && d.TrainingCutoff < d.LastObservation && d.LastObservation <= d.CollectedAt;
        static bool Quality(AdvisoryModel m)
        {
            var e = m.Evaluation;
            // Evaluation is a report, never a tuning/admission signal. No universal accuracy threshold.
            return e.Protocol == "served-advice-v2" && e.AsOf == m.CreatedAt && e.UnknownLabels == 0 && e.EligibleRows == e.TotalRows && e.TotalRows == m.Dataset.EvaluationRows &&
                new[] { e.TruePositive, e.FalseNegative, e.TrueNegative, e.FalsePositive, e.AbstainedBenign, e.AbstainedSuspicious }.All(n => n >= 0 && n <= 10000) &&
                (long)e.Classified + e.Abstained == e.EligibleRows && e.AbstentionReasons is not null && e.AbstentionReasons.Length <= 4 &&
                e.AbstentionReasons.All(r => r is not null && Text(r.Reason) && r.Rows > 0 && r.Rows <= 10000) && e.AbstentionReasons.Sum(r => (long)r.Rows) == e.Abstained;
        }
        public ModelRegistry Snapshot() { lock (_gate) return JsonSerializer.Deserialize<ModelRegistry>(JsonSerializer.Serialize(_state, DdiSecurityManager.JsonOptions), DdiSecurityManager.JsonOptions); }
        void Save(ModelRegistry next, Action authorizeCommit = null)
        {
            string payload = JsonSerializer.Serialize(next, DdiSecurityManager.JsonOptions);
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new Envelope(payload, Hash(Encoding.UTF8.GetBytes(payload))), DdiSecurityManager.JsonOptions);
            if (bytes.Length > 4 * 1024 * 1024) throw new InvalidOperationException("Registry exceeds 4 MiB; current selection retained.");
            // One bounded pending artifact. A failed write is retained for operator inspection;
            // restart ignores it and never treats incomplete work as an active model.
            string temp = _file + ".pending";
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { stream.Write(bytes); stream.Flush(true); }
            // Recheck immediately before atomic publication, after potentially slow storage I/O.
            // A denial retains the bounded pending artifact and leaves active disk/memory state unchanged.
            authorizeCommit?.Invoke();
            File.Move(temp, _file, true); // Publish in memory only after the durable replacement succeeds.
            _state = next;
        }
        public ModelRegistry Train(string json, long expectedRevision, string actor, DateTime now, Action authorizeCommit = null)
        {
            if (Interlocked.CompareExchange(ref _training, 1, 0) != 0) throw new InvalidOperationException("A local training operation is already running; no work was queued.");
            try
            {
            if (now.Kind != DateTimeKind.Utc || !Text(actor) || json is null || Encoding.UTF8.GetByteCount(json) > 4 * 1024 * 1024) throw new ArgumentException("Dataset exceeds 4 MiB or has invalid operation metadata.");
            using (var document = JsonDocument.Parse(json))
                if (document.RootElement.ValueKind != JsonValueKind.Object || !document.RootElement.TryGetProperty("synthetic", out var synthetic) || synthetic.ValueKind is not (JsonValueKind.True or JsonValueKind.False) || document.RootElement.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != document.RootElement.EnumerateObject().Count()) throw new ArgumentException("Explicit synthetic status and unambiguous dataset metadata are required.");
            LearningDataset d = JsonSerializer.Deserialize<LearningDataset>(json, DdiSecurityManager.JsonOptions) ?? throw new ArgumentException("Provide a local dataset.");
            if (d.FeatureSchema != Schema || !Digest(d.FeatureSourceSha256) || !Text(d.Source) || !Text(d.License) || !Text(d.PermissionBasis) || !Text(d.Selection) || !Text(d.LabelProvenance) || !Text(d.PrivacyBasis) || d.CollectedAt.Kind != DateTimeKind.Utc || d.CollectedAt > now || d.Rows is null || d.Rows.Length < 60 || d.Rows.Length > 10000) throw new ArgumentException("Provide source, processing permission, license, selection, label and privacy provenance, UTC collection time, schema/PSL hash and 60–10000 rows.");
            foreach (var r in d.Rows)
                if (r is null || !Digest(r.ObservationSha256) || !Digest(r.DeviceGroupSha256) || r.ObservedAt.Kind != DateTimeKind.Utc || r.ObservedAt > d.CollectedAt || r.ObservedAt > now || (r.Partition != "Train" && r.Partition != "Evaluation") || (r.Label != "Benign" && r.Label != "Suspicious") || !Vector(r.Features)) throw new ArgumentException("Rows require observation/group SHA256, UTC times, explicit partition, label and seven complete normalized features.");
            var train = d.Rows.Where(r => r.Partition == "Train").ToArray();
            var eval = d.Rows.Where(r => r.Partition == "Evaluation").ToArray();
            if (train.Any(r => r.SampleLimited)) throw new ArgumentException("Sample-limited rows cannot fit model parameters or baselines.");
            if (new[] { "Benign", "Suspicious" }.Any(label => train.Count(r => r.Label == label) < 20 || eval.Count(r => r.Label == label) < 10)) throw new ArgumentException("Each label needs 20 training and 10 held-out evaluation rows.");
            if (d.Rows.Select(r => r.ObservationSha256).Distinct().Count() != d.Rows.Length || train.Select(r => r.DeviceGroupSha256).Intersect(eval.Select(r => r.DeviceGroupSha256)).Any() || train.Max(r => r.ObservedAt) >= eval.Min(r => r.ObservedAt)) throw new ArgumentException("Separate observation IDs, device groups and later evaluation times are required to limit leakage.");
            string sha = Hash(Encoding.UTF8.GetBytes(json));
            var receipt = new DatasetReceipt(sha, d.Source, d.License, d.PermissionBasis, d.Selection, d.LabelProvenance, d.PrivacyBasis, d.CollectedAt, d.Synthetic, d.Rows.Length, train.Length, eval.Length, 0, d.Rows.Min(r => r.ObservedAt), d.Rows.Max(r => r.ObservedAt))
            { FeatureSourceSha256 = d.FeatureSourceSha256, TrainPartitionSha256 = Hash(JsonSerializer.SerializeToUtf8Bytes(train, DdiSecurityManager.JsonOptions)), EvaluationPartitionSha256 = Hash(JsonSerializer.SerializeToUtf8Bytes(eval, DdiSecurityManager.JsonOptions)), TrainGroups = train.Select(r => r.DeviceGroupSha256).Distinct().Count(), EvaluationGroups = eval.Select(r => r.DeviceGroupSha256).Distinct().Count(), TrainingCutoff = train.Max(r => r.ObservedAt) };
            var baselines = train.Where(r => r.Label == "Benign").GroupBy(r => r.DeviceGroupSha256).Where(g => g.Count() >= 20 && g.Select(r => r.ObservedAt).Distinct().Count() >= 20 && g.Max(r => r.ObservedAt) - g.Min(r => r.ObservedAt) >= TimeSpan.FromHours(1)).Select(g => new LearnedBaseline(g.Key, g.Count(), g.Max(r => r.ObservedAt), Mean(g))).OrderBy(b => b.DeviceGroupSha256, StringComparer.Ordinal).ToArray();
            if (baselines.Length > 1024) throw new ArgumentException("Dataset exceeds 1024 device baselines.");
            string scope = d.Synthetic ? "Synthetic mechanics only; no empirical accuracy or generalization claim" : "Held-out supplied sample only; permissions and labels are operator assertions; representativeness and generalization unverified";
            var model = new AdvisoryModel(sha, Schema, "nearest-centroid-v1", now, now.AddDays(30), actor, receipt, Mean(train.Where(r => r.Label == "Benign")), Mean(train.Where(r => r.Label == "Suspicious")), new(0, 0, 0, 0, scope), baselines);
            if (!Valid(model)) throw new ArgumentException("Training classes lack sufficient feature separation.");
            int tp = 0, fp = 0, tn = 0, fn = 0, abstainedBenign = 0, abstainedSuspicious = 0;
            Dictionary<string, int> reasons = new(StringComparer.Ordinal);
            foreach (var r in eval)
            {
                var decision = Decide(model, r.Features, r.ObservedAt, r.SampleLimited, now, d.FeatureSourceSha256);
                if (decision.Label is null)
                {
                    if (r.Label == "Suspicious") abstainedSuspicious++; else abstainedBenign++;
                    reasons[decision.Reason] = reasons.GetValueOrDefault(decision.Reason) + 1;
                    continue;
                }
                bool positive = decision.Label == "Suspicious";
                if (r.Label == "Suspicious") { if (positive) tp++; else fn++; } else { if (positive) fp++; else tn++; }
            }
            model = model with { Evaluation = new(tp, fp, tn, fn, scope) { Protocol = "served-advice-v2", AsOf = now, TotalRows = eval.Length, EligibleRows = eval.Length, UnknownLabels = 0, AbstainedBenign = abstainedBenign, AbstainedSuspicious = abstainedSuspicious, AbstentionReasons = reasons.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new AbstentionReason(p.Key, p.Value)).ToArray() } };
            model = model with { ArtifactSha256 = ModelHash(model) };
            lock (_gate)
            {
                if (_state.Revision != expectedRevision) throw new InvalidOperationException("Registry changed; reload before training.");
                if (_state.RetiredDatasets.Contains(model.Id)) throw new ArgumentException("This exact dataset was retired and cannot be reused.");
                if (_state.Models.Any(m => m.Id == model.Id)) throw new ArgumentException("This exact dataset is already registered.");
                if (_state.Models.Length >= 16) throw new ArgumentException("Registry has 16 versions; no version was evicted.");
                authorizeCommit?.Invoke();
                Save(_state with { Revision = _state.Revision + 1, Models = _state.Models.Append(model).ToArray(), Status = "Unqualified local mechanics; empirical evaluation gate open; explicit advisory selection required" }, authorizeCommit);
                return Snapshot();
            }
            }
            finally { Volatile.Write(ref _training, 0); }
        }
        public ModelRegistry Select(string id, long expectedRevision, string actor, DateTime now, Action authorizeCommit = null)
        {
            if (!Text(actor) || now.Kind != DateTimeKind.Utc) throw new ArgumentException("Invalid operation metadata.");
            lock (_gate)
            {
                if (_state.Revision != expectedRevision) throw new InvalidOperationException("Registry changed; reload before selection.");
                var model = _state.Models.SingleOrDefault(m => m.Id == id);
                if (id != "" && (model is null || !Valid(model) || !Quality(model) || model.ArtifactSha256 != ModelHash(model) || model.FeatureDefinitionSha256 != FeatureDefinitionSha256 || model.CreatedAt > now || model.ExpiresAt <= now || now - model.Dataset.LastObservation > TimeSpan.FromDays(30))) throw new ArgumentException("Select a compatible unexpired version, or disable learned advice. Empirical qualification remains unavailable.");
                authorizeCommit?.Invoke();
                Save(_state with { Revision = _state.Revision + 1, Previous = _state.Selected, Selected = id, Status = "Unqualified advisory selection by " + actor + " at " + now.ToString("O") + "; empirical gate open" }, authorizeCommit);
                return Snapshot();
            }
        }
        public PredictiveAdvice Evaluate(double[] features, string group, DateTime observationTime, bool sampleLimited, DateTime now, string featureSourceSha256 = null)
        {
            lock (_gate)
            {
                PredictiveAdvice Fallback(string status, string baseline = "Unavailable") => new("Monitor", status, _state.Selected, "Deterministic heuristic retained", baseline, null, "Uncalibrated");
                var m = _state.Models.SingleOrDefault(m => m.Id == _state.Selected);
                if (m is null || !Valid(m) || !Quality(m) || m.ArtifactSha256 != ModelHash(m)) return Fallback("Missing, low-quality or incompatible model artifact");
                var decision = Decide(m, features, observationTime, sampleLimited, now, featureSourceSha256);
                var b = m.Baselines.SingleOrDefault(b => b.DeviceGroupSha256 == group);
                string baseline = b is null ? "Absent" : b.LastObservation > observationTime ? "Future baseline excluded" : observationTime - b.LastObservation > TimeSpan.FromDays(7) ? "Stale" : "Learned from supplied benign training observations";
                double? drift = b is not null && Vector(features) && baseline.StartsWith("Learned", StringComparison.Ordinal) ? Distance(features, b.Mean) : null;
                if (decision.Label is null) return Fallback(decision.Reason, baseline);
                return new("Monitor", decision.Reason, m.Id, decision.Label, baseline, drift, m.Evaluation.Scope);
            }
        }
        public ModelRegistry Retire(string id, long expectedRevision, string actor, DateTime now, Action authorizeCommit = null)
        {
            if (!Text(actor) || now.Kind != DateTimeKind.Utc) throw new ArgumentException("Invalid operation metadata.");
            lock (_gate)
            {
                if (_state.Revision != expectedRevision) throw new InvalidOperationException("Registry changed; reload before retirement.");
                if (!_state.Models.Any(m => m.Id == id)) throw new ArgumentException("Select an available model to retire.");
                if (_state.RetiredDatasets.Length >= 128) throw new ArgumentException("Retirement history is full; no provenance was evicted.");
                authorizeCommit?.Invoke();
                Save(_state with { Revision = _state.Revision + 1, Models = _state.Models.Where(m => m.Id != id).ToArray(), Selected = _state.Selected == id ? "" : _state.Selected, Previous = _state.Previous == id ? "" : _state.Previous, RetiredDatasets = _state.RetiredDatasets.Append(id).ToArray(), Status = "Retired by " + actor + " at " + now.ToString("O") + "; stored learned parameters removed; historical exports/backups are not recalled" }, authorizeCommit);
                return Snapshot();
            }
        }
    }

    public sealed record IndicatorContext(string Id, string Source, string ProvenanceStatus, int AssertedConfidence, DateTime? ExpiresAt, string Freshness, ProvenanceView Context);
    public sealed record PredictiveEvidence(string EventId, DateTime ObservedAt, DateTime EarliestRetainedEvent, string TimeBasis, string RegistrationAgeStatus, SecurityDevice Infrastructure, string InfrastructureBasis, string DeviceGroupSha256, string FeatureSchema, double[] Features, IndicatorContext[] Indicators, PredictiveAdvice Advice);
    public sealed partial class DdiSecurityManager
    {
        PredictiveModelRegistry _predictive;
        public PredictiveModelRegistry PredictiveModels { get { lock (_sync) return _predictive ??= new PredictiveModelRegistry(_folder); } }
        public PredictiveEvidence PredictiveContext(string eventId, DateTime now)
        {
            var events = RecentEvents();
            var item = events.SingleOrDefault(e => e.Id == eventId) ?? throw new ArgumentException("Select an available recent event.");
            string identity = item.Device is null || (string.IsNullOrEmpty(item.Device.ClientIdentifier) && string.IsNullOrEmpty(item.Device.HardwareAddress)) ? "" : JsonSerializer.Serialize(new[] { item.Device.Scope, item.Device.ClientIdentifier, item.Device.HardwareAddress, item.Device.ViewId, item.Device.Site, item.Device.Vlan?.ToString(System.Globalization.CultureInfo.InvariantCulture) }, JsonOptions);
            string group = identity == "" ? "" : Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity))).ToLowerInvariant();
            var behavior = item.Behavior;
            var advice = PredictiveModels.Evaluate(behavior?.FeatureSchema == PredictiveModelRegistry.Schema && behavior.Samples >= 30 ? behavior.FeatureVector : null, group, item.Timestamp, behavior?.SampleLimited ?? true, now, behavior?.FeatureSourceSha256);
            var indicators = (item.Matches ?? []).Select(i => new IndicatorContext(i.Id, i.Source, "Source and confidence are supplied assertions; expiry is not a fresh provider check", i.Confidence, i.Expires, i.Expires is null ? "Expiry unknown" : i.Expires <= now ? "Expired" : "Within supplied expiry", PredictiveProvenance.View(i.Provenance, item.Timestamp, now))).ToArray();
            return new(item.Id, item.Timestamp, events.Where(e => e.Query == item.Query).Min(e => e.Timestamp), "Earliest retained local event only; bounded history, not global first seen", "Unknown; DNS observations do not establish registration age", item.Device, item.Device is null ? "No unambiguous device context" : "Resolver snapshot at event capture; scope/identity from current lease context; site/view/VLAN are configured assertions, not historical lease proof", group, behavior?.FeatureSchema, behavior?.FeatureVector?.ToArray(), indicators, advice);
        }
    }
}
