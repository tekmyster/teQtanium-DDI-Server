using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace DnsServerCore.Security
{
    public sealed class PublicSuffixes
    {
        public string VersionSha256 { get; }
        readonly HashSet<string> _rules = new HashSet<string>(StringComparer.Ordinal);
        readonly HashSet<string> _wildcards = new HashSet<string>(StringComparer.Ordinal);
        readonly HashSet<string> _exceptions = new HashSet<string>(StringComparer.Ordinal);
        public PublicSuffixes(IEnumerable<string> lines)
        {
            foreach (string raw in lines)
            {
                string rule = raw.Trim();
                if (rule.Length == 0 || rule.StartsWith("//", StringComparison.Ordinal)) continue;
                if (rule.StartsWith('!')) _exceptions.Add(Normalize(rule[1..]));
                else if (rule.StartsWith("*.", StringComparison.Ordinal)) _wildcards.Add(Normalize(rule[2..]));
                else _rules.Add(Normalize(rule));
            }
            // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
            string canonical = string.Join('\n', _rules.Concat(_wildcards.Select(r => "*." + r)).Concat(_exceptions.Select(r => "!" + r)).OrderBy(r => r, StringComparer.Ordinal)) + "\n";
            VersionSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        }
        public static string Normalize(string name)
        {
            name = name.TrimEnd('.').ToLowerInvariant();
            if (name.Length == 0 || name.Length > 253 || name.Split('.').Any(l => l.Length == 0 || l.Length > 63)) throw new ArgumentException("Invalid DNS name.");
            return new IdnMapping().GetAscii(name).ToLowerInvariant();
        }
        public string RegistrableDomain(string name)
        {
            string[] labels = Normalize(name).Split('.');
            int suffixLength = 1;
            for (int i = 0; i < labels.Length; i++)
            {
                string suffix = string.Join('.', labels, i, labels.Length - i);
                if (_exceptions.Contains(suffix)) { suffixLength = labels.Length - i - 1; break; }
                if (_rules.Contains(suffix)) suffixLength = Math.Max(suffixLength, labels.Length - i);
                if (i > 0 && _wildcards.Contains(suffix)) suffixLength = Math.Max(suffixLength, labels.Length - i + 1);
            }
            return string.Join('.', labels.Skip(Math.Max(0, labels.Length - suffixLength - 1)));
        }
    }

    public sealed class BehavioralAnalyzer
    {
        const int MaxStreams = 4096, MaxSamples = 512;
        readonly record struct Sample(DateTime Time, ulong Name, bool HasPrefix, bool Long, bool Entropy, bool Txt, bool Nx, bool DgaLexical, int LabelLength, double LabelEntropy);
        sealed class Stream
        {
            public DateTime Last, LastDropped;
            public readonly Queue<Sample> Samples = new();
            public void Add(Sample sample)
            {
                if (sample.Time < Last) { Samples.Clear(); LastDropped = default; }
                while (Samples.TryPeek(out var oldest) && sample.Time - oldest.Time >= TimeSpan.FromHours(1)) Samples.Dequeue();
                if (Samples.Count == MaxSamples) LastDropped = Samples.Dequeue().Time;
                Samples.Enqueue(sample); Last = sample.Time;
            }
        }
        readonly object _sync = new();
        readonly Dictionary<(string Client, string Domain), Stream> _domains = new();
        readonly Dictionary<string, Stream> _clients = new(StringComparer.Ordinal);
        readonly PublicSuffixes _suffixes;
        DnsTunnelingSettings _tunneling = new();
        long _tunnelingRevision = -1;
        public BehavioralAnalyzer(PublicSuffixes suffixes) { _suffixes = suffixes; }
        public static double Entropy(string text)
        {
            if (text.Length == 0) return 0;
            return text.GroupBy(c => c).Sum(g => { double p = (double)g.Count() / text.Length; return -p * Math.Log2(p); });
        }
        static ulong Fingerprint(string text)
        {
            // Store fixed-size fingerprints rather than retaining possible DNS payloads.
            Span<byte> hash = stackalloc byte[32];
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text), hash);
            return System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(hash);
        }
        static Stream GetStream<TKey>(Dictionary<TKey, Stream> streams, TKey key, DateTime now)
        {
            if (streams.TryGetValue(key, out var stream)) return stream;
            if (streams.Count >= MaxStreams)
            {
                foreach (var stale in streams.Where(p => now - p.Value.Last >= TimeSpan.FromHours(1)).Select(p => p.Key).ToArray()) streams.Remove(stale);
                if (streams.Count >= MaxStreams) streams.Remove(streams.MinBy(p => p.Value.Last).Key);
            }
            streams[key] = stream = new Stream(); return stream;
        }
        static BehavioralFinding Tunneling(Stream stream, int minutes, int volume, DateTime now, DnsTunnelingSettings policy)
        {
            DateTime cutoff = now.AddMinutes(-minutes);
            var samples = stream.Samples.Where(s => s.Time > cutoff).ToArray();
            int count = samples.Length;
            List<ScoreContribution> points = [];
            int unique = samples.Where(s => s.HasPrefix).Select(s => s.Name).Distinct().Count();
            bool IsLong(Sample sample) => sample.LabelLength >= policy.LongLabelLength;
            bool IsEntropy(Sample sample) => sample.LabelLength >= policy.EntropyMinimumLength && sample.LabelEntropy >= policy.EntropyThreshold;
            bool longLabels = count > 0 && samples.Count(IsLong) >= count * policy.LexicalRatio;
            bool entropy = count > 0 && samples.Count(IsEntropy) >= count * policy.LexicalRatio;
            bool lexical = longLabels || entropy;
            bool novelty = unique >= policy.MinimumUniqueSubdomains && unique >= count * policy.NoveltyRatio;
            if (count >= policy.MinimumSamples)
            {
                if (longLabels) points.Add(new("LongLabels", 20, $"At least {policy.LexicalRatio:P0} of sampled names have labels of {policy.LongLabelLength} or more characters."));
                if (entropy) points.Add(new("HighEntropy", 20, $"At least {policy.LexicalRatio:P0} of sampled names have labels of at least {policy.EntropyMinimumLength} characters and entropy of {policy.EntropyThreshold} bits per character."));
                if (novelty) points.Add(new("UniqueSubdomains", 25, $"At least {policy.MinimumUniqueSubdomains} distinct subdomains account for {policy.NoveltyRatio:P0} or more of sampled queries."));
                if (count >= volume) points.Add(new("QueryVolume", 15, $"At least {volume} sampled queries in the {minutes}-minute observation window."));
                if (samples.Count(s => s.Txt) >= count * policy.TxtRatio) points.Add(new("TxtRatio", 10, $"At least {policy.TxtRatio:P0} of sampled queries use TXT; this is supporting evidence only."));
                if (samples.Count(s => s.Nx) >= count * policy.NxDomainRatio) points.Add(new("NxDomainRatio", 10, $"At least {policy.NxDomainRatio:P0} of sampled responses are NXDOMAIN."));
            }
            // Lexical and changing-payload evidence must corroborate each other before escalation.
            int score = Math.Min(100, points.Sum(p => p.Points));
            if ((!lexical || !novelty) && score > 49)
            {
                points.Add(new("CorroborationLimit", 49 - score, "Priority is limited because label structure and changing subdomains do not corroborate."));
                score = 49;
            }
            return new("DnsTunneling", "ClientDomain", score, count, count == 0 ? now : samples[0].Time, minutes, stream.LastDropped > cutoff, points.ToArray());
        }
        static BehavioralFinding Dga(Stream stream, DateTime now)
        {
            var samples = stream.Samples.ToArray();
            int count = samples.Length;
            List<ScoreContribution> points = [];
            if (count >= 30)
            {
                if (samples.Count(s => s.DgaLexical) >= count * .5) points.Add(new("DomainLexical", 20, "At least half of registered domains have long, diverse, high-entropy labels."));
                if (samples.Select(s => s.Name).Distinct().Count() >= Math.Max(25, count * .8)) points.Add(new("DomainDiversity", 25, "At least 25 distinct registered domains account for 80% or more of sampled queries."));
                if (samples.Count(s => s.Nx) >= count * .8) points.Add(new("FailedDestinations", 35, "At least 80% of sampled destination lookups return NXDOMAIN."));
            }
            // None of these indicators alone classifies a domain generation pattern.
            int score = points.Count == 3 ? 80 : 0;
            return new("DgaPattern", "Client", score, count, count == 0 ? now : samples[0].Time, 60, stream.LastDropped > now.AddHours(-1), points.ToArray());
        }
        static BehavioralFinding Periodicity(Stream stream, DateTime now)
        {
            var samples = stream.Samples.ToArray();
            List<ScoreContribution> points = [];
            if (samples.Length >= 20 && samples[^1].Time - samples[0].Time >= TimeSpan.FromMinutes(10) && samples.Count(s => !s.Nx) >= samples.Length * .8)
            {
                var intervals = samples.Zip(samples.Skip(1), (a, b) => (b.Time - a.Time).TotalSeconds).ToArray();
                double mean = intervals.Average();
                double deviation = Math.Sqrt(intervals.Average(v => (v - mean) * (v - mean)));
                if (mean >= 10 && deviation / mean <= .1)
                    points.Add(new("RegularTiming", 35, "Successful lookups repeat at nearly regular intervals; scheduled legitimate software can behave the same way."));
            }
            return new("PeriodicDns", "ClientDomain", points.Sum(p => p.Points), samples.Length, samples[0].Time, 60, stream.LastDropped > now.AddHours(-1), points.ToArray());
        }
        public BehavioralScore Observe(string clientKey, string name, string type, bool nxDomain, DateTime now, DnsTunnelingSettings tunneling = null, long policyRevision = 0)
        {
            name = PublicSuffixes.Normalize(name);
            string domain = _suffixes.RegistrableDomain(name);
            string prefix = name.Length > domain.Length ? name[..(name.Length - domain.Length - 1)] : "";
            string longest = prefix.Split('.').OrderByDescending(s => s.Length).First();
            string registeredLabel = domain.Split('.')[0];
            bool dga = registeredLabel.Length >= 16 && registeredLabel.Distinct().Count() >= 10 && Entropy(registeredLabel) >= 3.5;
            double labelEntropy = Entropy(longest);
            Sample sample = new(now, Fingerprint(prefix), prefix.Length > 0, longest.Length >= 32, longest.Length >= 20 && labelEntropy >= 4.0, type == "TXT", nxDomain, dga, longest.Length, labelEntropy);
            lock (_sync)
            {
                tunneling ??= new DnsTunnelingSettings();
                bool retiredSettings = _tunneling != tunneling && policyRevision < _tunnelingRevision;
                if (_tunneling != tunneling && !retiredSettings)
                {
                    // Rebuild evidence under the new gates; never mix configurations in a window.
                    _domains.Clear(); _clients.Clear(); _tunneling = tunneling;
                }
                _tunnelingRevision = Math.Max(_tunnelingRevision, policyRevision);
                // An in-flight older policy may evaluate one sample, but cannot erase or mix newer windows.
                var domainStream = retiredSettings ? new Stream() : GetStream(_domains, (clientKey, domain), now);
                var clientStream = retiredSettings ? new Stream() : GetStream(_clients, clientKey, now);
                domainStream.Add(sample); clientStream.Add(sample with { Name = Fingerprint(domain) });
                BehavioralFinding[] findings = [Tunneling(domainStream, tunneling.ShortWindowMinutes, tunneling.ShortWindowVolume, now, tunneling), Tunneling(domainStream, tunneling.LongWindowMinutes, tunneling.LongWindowVolume, now, tunneling), Dga(clientStream, now), Periodicity(domainStream, now)];
                // Stable ordering favors the short window when scores tie.
                var selected = findings.OrderByDescending(f => f.Score).First();
                // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
                // A fixed domain/hour feature contract, independent of the selected heuristic finding.
                var featureSamples = domainStream.Samples.ToArray();
                double Ratio(Func<Sample, bool> predicate) => (double)featureSamples.Count(predicate) / featureSamples.Length;
                return new(selected.Score, domain, selected.Samples, selected.WindowStart, selected.Contributions, "heuristic-v2", "Uncalibrated", findings.Where(f => f.Score > 0).ToArray(), selected.WindowMinutes, selected.SampleLimited || domainStream.LastDropped > now.AddHours(-1))
                {
                    FeatureSchema = PredictiveModelRegistry.Schema,
                    FeatureSourceSha256 = _suffixes.VersionSha256,
                    FeatureVector = [Ratio(s => s.Long), Ratio(s => s.Entropy), Ratio(s => s.Txt), Ratio(s => s.Nx), (double)featureSamples.Select(s => s.Name).Distinct().Count() / featureSamples.Length, Ratio(s => s.DgaLexical), (double)featureSamples.Length / MaxSamples]
                };
            }
        }
    }
}
