using System;

namespace DnsServerCore.Security
{
    public sealed record ThreatIndicator(string Id, string Kind, string Value, string Action, string Source, int Confidence = 80, DateTime? Expires = null, string ClientNetwork = null, string Evidence = null)
    {
        // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
        public IndicatorProvenance Provenance { get; init; }
    }
    public sealed record MispSettings(bool Enabled = false, string Url = "", string ApiKeyEnvironment = "DDI_MISP_API_KEY", int RefreshSeconds = 300, int CacheLifetimeHours = 24);
    public sealed record LlmSettings(bool Enabled = false, string Endpoint = "", string Model = "", string ApiKeyEnvironment = "", bool ShareDomains = false, bool AllowRemote = false);
    public sealed record LlmAnalysis(string EventId, string Model, DateTime Timestamp, string Summary, bool DomainsShared, string Status = "Advisory");
    // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
    [System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
    public sealed record DnsTunnelingSettings(int ShortWindowMinutes = 5, int LongWindowMinutes = 60, int MinimumSamples = 30,
        int LongLabelLength = 32, int EntropyMinimumLength = 20, double EntropyThreshold = 4.0,
        int MinimumUniqueSubdomains = 25, double NoveltyRatio = .8, double LexicalRatio = .5,
        int ShortWindowVolume = 60, int LongWindowVolume = 120, double TxtRatio = .5, double NxDomainRatio = .5)
    {
        public DnsTunnelingSettings Validate()
        {
            static void Range(double value, double min, double max, string label)
            { if (!double.IsFinite(value) || value < min || value > max) throw new ArgumentException($"{label} must be between {min} and {max}."); }
            Range(ShortWindowMinutes, 1, 15, "Short window (minutes)"); Range(LongWindowMinutes, 15, 60, "Long window (minutes)");
            if (ShortWindowMinutes >= LongWindowMinutes) throw new ArgumentException("Long window must exceed the short window.");
            Range(MinimumSamples, 10, 512, "Minimum sampled queries"); Range(LongLabelLength, 8, 63, "Long label length");
            Range(EntropyMinimumLength, 8, 63, "Minimum entropy label length"); Range(EntropyThreshold, 1, 6, "Label entropy (bits per character)");
            Range(MinimumUniqueSubdomains, 2, 512, "Minimum unique subdomains"); Range(NoveltyRatio, .1, 1, "Unique subdomain ratio");
            Range(LexicalRatio, .1, 1, "Long or high-entropy label ratio"); Range(TxtRatio, .1, 1, "TXT query ratio"); Range(NxDomainRatio, .1, 1, "NXDOMAIN response ratio");
            Range(ShortWindowVolume, MinimumSamples, 512, "Short window query volume"); Range(LongWindowVolume, MinimumSamples, 512, "Long window query volume");
            return this;
        }
    }
    public sealed record SecurityPolicy(int Version, long Revision, bool Enabled, string Mode, bool InspectAuthoritative, int AlertThreshold, string DeviceDnsResponse, string DhcpResponse, int DeviceThreshold, ThreatIndicator[] Indicators, MispSettings Misp, LlmSettings Llm = null)
    {
        public EdlFeed[] EdlFeeds { get; init; } = [];
        public EdlPublication[] EdlPublications { get; init; } = [];
        public DnsTunnelingSettings DnsTunneling { get; init; } = new();
        public static SecurityPolicy Default => new SecurityPolicy(1, 0, false, "Monitor", false, 70, "Monitor", "Observe", 90, [], new MispSettings());
    }
    public sealed record SecurityDevice(string Scope, string ClientIdentifier, string HardwareAddress, string HostName, string ViewId, string Site, int? Vlan);
    public sealed record ScoreContribution(string Feature, int Points, string Evidence);
    public sealed record BehavioralFinding(string Kind, string Scope, int Score, int Samples, DateTime WindowStart, int WindowMinutes, bool SampleLimited, ScoreContribution[] Contributions);
    public sealed record BehavioralScore(int Score, string Domain, int Samples, DateTime WindowStart, ScoreContribution[] Contributions, string ModelVersion = "heuristic-v1", string Confidence = "Uncalibrated", BehavioralFinding[] Findings = null, int WindowMinutes = 5, bool SampleLimited = false, string BaselineStatus = "NotLearned")
    {
        // Modified by Tekmyster Industries, LLC — remains GPL-3.0.
        public string FeatureSchema { get; init; }
        public string FeatureSourceSha256 { get; init; }
        public double[] FeatureVector { get; init; }
    }
    public sealed record SecurityDecision(string Action, ThreatIndicator[] Matches, BehavioralScore Behavior, string Reason, int AdditionalMatches = 0);
    public sealed record SecurityEvent(string Id, DateTime Timestamp, string Node, string Service, string ClientAddress, string Query, string QueryType, string ResponseCode, string Action, long PolicyRevision, SecurityDevice Device, ThreatIndicator[] Matches, BehavioralScore Behavior, string Reason, int AdditionalMatches = 0);
    public sealed record SecuritySignal(string Id, DateTime Timestamp, DateTime Expires, string Node, string Service, string Scope, string ClientIdentifier, string HardwareAddress, int Score, string Reason, string[] EvidenceKeys = null);
    public sealed record MispHealth(DateTime? LastSuccess, DateTime? LastAttempt, string Status, int Indicators)
    {
        public string CacheState { get; init; } = "Empty";
        public string CacheSourceUrl { get; init; } = "";
        public string CacheOrigin { get; init; } = "None";
        public DateTime? CacheReceivedAt { get; init; }
        public DateTime? CacheFetchedAt { get; init; }
        public DateTime? CacheExpiresAt { get; init; }
        public DateTime? CacheLastExpiresAt { get; init; }
        public int ActiveUnsupportedAttributes { get; init; }
        public string LocalRefreshState { get; init; } = "NeverCompleted";
        public bool LocalSuccessSourceMatches { get; init; }
        public bool LocalRefreshStale { get; init; }
        public DateTime? LastFailure { get; init; }
        public bool CompleteSnapshot { get; init; }
        public int SnapshotEntries { get; init; }
        public int UnsupportedAttributes { get; init; }
        public int DnsMatchingIndicators { get; init; }
        public int UrlEvidenceOnly { get; init; }
    }
    public sealed record MispCache(string SourceUrl, ThreatIndicator[] Indicators);
    public sealed record SignalHealth(DateTime? LastSuccess, string Status, long DeliveryErrors);
}
