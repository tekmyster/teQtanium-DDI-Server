// Copyright (c) 2026 Tekmyster Industries, LLC. GPL-3.0; see ../../LICENSE.
using DnsServerCore.Security;
using System.Text;
using System.Text.Json;

static class ReplayChecks
{
    static readonly byte[] Psl = Encoding.UTF8.GetBytes("// Synthetic mechanical suffix fixture\nexample\n");
    static string H(string s) => Replay.Hash(Encoding.UTF8.GetBytes(s));
    static readonly DateTime Start = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    public static void WriteFixture(string directory)
    {
        if (Directory.Exists(directory) || File.Exists(directory)) throw new IOException("Synthetic fixture destination must be new.");
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "synthetic-psl.dat"), Psl);
        File.WriteAllBytes(Path.Combine(directory, "synthetic-manifest.json"), JsonSerializer.SerializeToUtf8Bytes(Fixture(), Replay.Json));
        Console.WriteLine("Invented mechanical fixture written; no packets or quality proof.");
    }
    public static ReplayManifest Fixture()
    {
        List<ReplayRow> rows = [];
        for (int n = 0; n < 40; n++)
            foreach (string cohort in new[] { "benign", "false-positive", "suspicious", "unknown" })
                rows.Add(new(H($"{cohort}-{n}"), H(cohort), H(cohort + "-family"), "Test", Start.AddSeconds(n),
                    cohort == "benign" ? "verification.service.example" : $"abcdefghijklmnopqrstuvwxyz0123456789{n:D4}.service.example",
                    "TXT", true, cohort is "benign" or "false-positive" ? "Benign" : cohort == "unknown" ? "Unknown" : "Suspicious", "Synthetic label arithmetic fixture", Start.AddDays(1)));
        rows.Add(new(H("miss"), H("miss"), H("miss-family"), "Test", Start.AddSeconds(40), "ordinary.missed.example", "A", false, "Suspicious", "Synthetic missed incident", Start.AddDays(1)));
        var exposures = rows.GroupBy(r => r.Device).Select(g => new Exposure(g.Key, Start, Start.AddHours(1), g.First().Label, true, "Synthetic measured one-hour coverage assertion")).ToArray();
        return new(1, true, "Synthetic mechanical fixture; never quality proof", "GPL-3.0 fixture",
            "Synthetic permission reference", "Synthetic privacy reference", "Synthetic consent reference",
            "Synthetic revocation reference", "Deliberately constructed arithmetic cohorts", "Synthetic labels only",
            "Actual BehavioralAnalyzer.Observe, synthetic DNS-shaped strings, no packets", "Cold Test only, disjoint synthetic device/family groups",
            "Invented fixture author", "Constructed inert strings in local memory", "Mechanical testing only; never empirical evidence", "Caller-owned private fixture; no automatic retention/erase", DateTime.UtcNow.AddMinutes(-2),
            DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddDays(1), false, DateTime.UtcNow, Start.AddDays(1),
            Replay.Hash(File.ReadAllBytes(typeof(BehavioralAnalyzer).Assembly.Location)), Replay.Hash(Psl), 70,
            rows.ToArray(), exposures,
            [new("detected", H("suspicious"), "service.example", Start, Start.AddHours(1), "Synthetic matched incident", 0),
             new("missed", H("miss"), "missed.example", Start, Start.AddHours(1), "Synthetic undetected incident", 0),
             new("unobserved", H("miss"), "absent.example", Start, Start.AddHours(1), "Synthetic unobserved domain", null)]);
    }
    public static void Run()
    {
        int checks = 0;
        void Check(bool ok, string why) { if (!ok) throw new InvalidOperationException(why); checks++; }
        JsonElement Result(ReplayManifest m) => JsonSerializer.SerializeToElement(Replay.Evaluate(m, JsonSerializer.SerializeToUtf8Bytes(m, Replay.Json), Psl), Replay.Json);
        void Reject(ReplayManifest m, string why)
        {
            try { Result(m); } catch (ArgumentException) { checks++; return; }
            throw new InvalidOperationException(why);
        }
        var m = Fixture(); var result = Result(m); var counts = result.GetProperty("metrics");
        Check(result.GetProperty("scope").GetString()!.Contains("Synthetic"), "Synthetic scope absent");
        Check(!result.GetProperty("empiricallyQualified").GetBoolean(), "Fixture must not qualify quality");
        Check(counts.GetProperty("truePositive").GetInt32() == 11 && counts.GetProperty("falsePositive").GetInt32() == 11, "Actual analyzer alert count changed");
        Check(counts.GetProperty("unknownLabels").GetInt32() == 40 && counts.GetProperty("unknownPredictedPositive").GetInt32() == 11, "Unknowns entered confusion counts");
        Check(counts.GetProperty("falseNegative").GetInt32() == 30 && counts.GetProperty("trueNegative").GetInt32() == 69, "Cold observation confusion counts wrong");
        Check(counts.GetProperty("abstainedBenign").GetInt32() == 0 && counts.GetProperty("coverageKnown").GetDouble() == 1, "Heuristic decisions falsely abstain");
        Check(Math.Abs(result.GetProperty("observedDeviceDays").GetDouble() - 5.0 / 24) < 1e-12, "Exposure denominator inferred from traffic");
        Check(Math.Abs(result.GetProperty("falsePositiveAlertsPerBenignObservedDeviceDay").GetDouble() - 132) < 1e-9, "FP benign exposure rate wrong");
        Check(Result(m with { Exposures = m.Exposures.Select(e => e with { Start = Start.AddHours(-11) }).ToArray() }).GetProperty("benignObservedDeviceDays").GetDouble() == 1, "Two devices observed twelve hours across midnight must equal one benign device-day");
        var splitExposure = m.Exposures.SelectMany(e => new[] { e with { End = Start.AddMinutes(30) }, e with { Start = Start.AddMinutes(45) } }).ToArray();
        var gaps = Result(m with { Exposures = splitExposure });
        Check(Math.Abs(gaps.GetProperty("observedDeviceDays").GetDouble() - 5.0 / 32) < 1e-12, "Coverage gaps counted as observed time");
        Check(gaps.GetProperty("delay")[0].GetProperty("delaySeconds").ValueKind == JsonValueKind.Null, "Coverage gaps implied complete first detection");
        var delay = result.GetProperty("delay");
        Check(delay[0].GetProperty("delaySeconds").GetDouble() == 29, "Detection delay mismatched");
        Check(delay[1].GetProperty("delaySeconds").ValueKind == JsonValueKind.Null && delay[1].GetProperty("status").GetString() == "Not detected in observed interval", "Miss turned into zero delay");
        Check(delay[2].GetProperty("status").GetString() == "No matched observations", "Unobserved incident silently dropped");
        Check(Result(m with { Exposures = [] }).GetProperty("falsePositiveAlertsPerObservedDeviceDay").ValueKind == JsonValueKind.Null, "Missing exposure invented a denominator");
        Check(Result(m with { Exposures = [] }).GetProperty("delay")[0].GetProperty("delaySeconds").ValueKind == JsonValueKind.Null, "Missing observation coverage implied first detection delay");
        Check(Result(m with { Incidents = [m.Incidents[0] with { Start = null }] }).GetProperty("delay")[0].GetProperty("status").GetString() == "Onset unavailable", "Missing onset imputed");
        Reject(m with { Revoked = true }, "Revoked rights accepted");
        Reject(m with { RightsExpireAt = m.AsOf }, "Expired rights accepted");
        Reject(m with { RightsCheckedAt = m.AsOf.AddSeconds(1) }, "Future rights check accepted");
        Reject(m with { AsOf = DateTime.UtcNow.AddHours(1) }, "Future evaluation time accepted");
        Reject(m with { ConsentReference = "" }, "Missing consent accepted");
        Reject(m with { DetectorSha256 = new string('0', 64) }, "Different assembly accepted");
        Reject(m with { PslSha256 = new string('0', 64) }, "Different PSL accepted");
        Reject(m with { Rows = m.Rows.Reverse().ToArray() }, "Unordered time accepted");
        Reject(m with { Rows = m.Rows.Append(m.Rows[^1]).ToArray() }, "Duplicate observation accepted");
        Reject(m with { Rows = m.Rows.Append(m.Rows[^1] with { Id = H("repeat-new-id") }).ToArray() }, "Repeated capture with new ID accepted");
        var bad = m.Rows.ToArray(); bad[0] = bad[0] with { Label = "" };
        Reject(m with { Rows = bad }, "Missing label imputed benign");
        bad = m.Rows.ToArray(); bad[0] = bad[0] with { LabelAvailableAt = m.AsOf.AddDays(1) };
        Reject(m with { Rows = bad }, "Future label available in earlier evaluation");
        bad = m.Rows.ToArray(); bad[0] = bad[0] with { At = Start.ToLocalTime() };
        Reject(m with { Rows = bad }, "Local timestamp accepted");
        bad = m.Rows.ToArray(); bad[0] = bad[0] with { Partition = "Train" };
        Reject(m with { Rows = bad }, "Device split leakage accepted");
        var train = m.Rows[0] with { Id = H("train"), Device = H("train-device"), Partition = "Train", At = Start.AddHours(-1) };
        Reject(m with { Rows = new[] { train }.Concat(m.Rows).ToArray() }, "Independent family leakage accepted");
        train = train with { IndependentGroup = H("train-family") };
        Check(Result(m with { Rows = new[] { train }.Concat(m.Rows).ToArray() }).GetProperty("predictions").GetArrayLength() == m.Rows.Length, "Training rows contaminated test replay");
        Check(Result(m with { Exposures = m.Exposures.Append(m.Exposures[0]).ToArray() }).GetProperty("observedDeviceDays").GetDouble() == result.GetProperty("observedDeviceDays").GetDouble(), "Overlapping exposure double-counted");
        Reject(m with { Exposures = m.Exposures.Append(m.Exposures[0] with { Label = "Unknown" }).ToArray() }, "Conflicting overlapping coverage accepted");
        Reject(m with { Exposures = m.Exposures.Skip(1).ToArray() }, "Partial denominator accepted");
        Reject(m with { Exposures = m.Exposures.Select(e => e with { CompleteObservation = false }).ToArray() }, "Incomplete capture accepted as exposure");
        Reject(m with { Incidents = [m.Incidents[0] with { Device = H("benign") }] }, "Contradictory incident accepted");
        var p = new ReplayPrediction("id", "device", Start, "example", "Suspicious", "Abstain", 0, 0, false, "Allow", "");
        var metrics = Replay.Metrics([p, p with { Label = "Benign" }, p with { Label = "Unknown" }]);
        Check(metrics.Precision is null && metrics.RecallAmongClassified is null && metrics.CoverageKnown == 0 && metrics.KnownSuspiciousDetectionFraction == 0 && metrics.UnknownAbstained == 1, "All abstaining arithmetic wrong");
        Check(Replay.Metrics([]).KnownSuspiciousDetectionFraction is null, "Empty denominator produced zero");
        Check(result.GetProperty("predictions").EnumerateArray().All(p => p.GetProperty("consumerOutcome").GetString() is "Monitor" or "BelowAlertThreshold"), "Offline heuristic became blocking");
        var again = Result(m);
        Check(result.GetProperty("predictions").GetRawText() == again.GetProperty("predictions").GetRawText(), "Sequential replay nondeterministic");
        var sampled = m.Rows.First(r => r.Label == "Suspicious");
        var burst = Enumerable.Range(0, 600).Select(n => sampled with { Id = H("burst" + n), At = Start.AddSeconds(n), Query = $"abcdefghijklmnopqrstuvwxyz0123456789{n:D4}.service.example" }).ToArray();
        Check(Result(m with { Rows = burst, Exposures = m.Exposures.Where(e => e.Device == sampled.Device).ToArray(), Incidents = [] }).GetProperty("predictions")[599].GetProperty("sampleLimited").GetBoolean(), "Actual sample truncation hidden by replay");
        using (var cancel = new CancellationTokenSource())
        {
            cancel.Cancel();
            try { Replay.Evaluate(m, [], Psl, cancel.Token); throw new InvalidOperationException("Cancelled work completed"); }
            catch (OperationCanceledException) { checks++; }
        }
        Parallel.For(0, 4, _ => { if (Result(m).GetProperty("predictions").GetRawText() != result.GetProperty("predictions").GetRawText()) throw new InvalidOperationException("Concurrent isolated replay differs"); });
        checks++;
        Console.WriteLine($"PASS: {checks} offline replay mechanical checks; synthetic only, no quality proof.");
    }
}
