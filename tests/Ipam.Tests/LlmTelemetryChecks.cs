// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore.Security;
using System.Net;
using System.Text.Json;

static class LlmTelemetryChecks
{
    sealed class Clock : TimeProvider
    {
        public long Milliseconds;
        public DateTimeOffset Wall = new(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Milliseconds;
        public override DateTimeOffset GetUtcNow() => Wall;
        public void Advance(int ms) { Milliseconds += ms; Wall = Wall.AddMilliseconds(ms); }
    }
    sealed class Provider(Clock clock) : HttpMessageHandler
    {
        public string Usage = ",\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":3,\"total_tokens\":15}";
        public int Delay = 100;
        public bool Wait, Timeout;
        public HttpStatusCode Status = HttpStatusCode.OK;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            clock.Advance(Delay);
            if (Wait) await Task.Delay(System.Threading.Timeout.Infinite, token);
            if (Timeout) throw new OperationCanceledException();
            return new(Status) { Content = new StringContent("{\"choices\":[{\"message\":{\"content\":\"Benign fixture reply.\"}}]" + Usage + "}") };
        }
    }
    public static async Task Run()
    {
        int checks = 0;
        void Check(bool value, string reason) { if (!value) throw new Exception(reason); checks++; }
        var clock = new Clock(); var telemetry = new LlmTelemetry(clock);
        var settings = new LlmSettings(false, "http://127.0.0.1:11434/v1/chat/completions", "fixture");
        var provider = new Provider(clock);
        using var http = new HttpClient(provider); using var connector = new SecurityLlm(http, telemetry);
        async Task Call(bool fails = false) { try { await connector.TestConnectionAsync(settings); Check(!fails, "Expected failed fixture call"); } catch (InvalidOperationException) { Check(fails, "Unexpected fixture failure"); } }
        LlmMetrics Read() => telemetry.Snapshot(settings, 15);
        Check(Read().Window.TotalTokens is null && Read().SinceRestart.Requests == 0 && Read().LastSuccess is null, "New process invents usage or observations");
        Check(!Read().WindowComplete && !Read().WindowTruncated && Read().Trend.All(b => b.Requests is null), "Startup coverage falsely reports a full window or zero-filled history");
        await Call();
        var m = Read();
        Check(m.Window.InputTokens == 12 && m.Window.OutputTokens == 3 && m.Window.TotalTokens == 15 && m.Window.UsageReported == 1, "Actual provider usage was not preserved");
        Check(m.LastSuccess.Kind == "ConnectionTest" && m.ConfiguredObservation.Outcome == "Success" && m.LastSuccess.Source == "Loopback", "Observed connection attribution missing");
        Check(m.SuccessfulLatency.P50Milliseconds == 100 && m.SuccessfulLatency.P95Milliseconds == 100, "Single response percentile incorrect");
        provider.Usage = ""; await Call();
        Check(Read().Window.TotalTokens == 15 && Read().Window.UsageMissing == 1 && Read().Window.UsageReported == 1, "Missing provider usage became zero or fabricated tokens");
        foreach (var invalid in new[] { "null", "{\"prompt_tokens\":-1,\"completion_tokens\":3,\"total_tokens\":2}", "{\"prompt_tokens\":9223372036854775808,\"completion_tokens\":1,\"total_tokens\":1}", "{\"prompt_tokens\":1,\"completion_tokens\":3,\"total_tokens\":7}", "{\"prompt_tokens\":\"1\",\"completion_tokens\":3,\"total_tokens\":4}", "{}", "[]" })
        {
            provider.Usage = ",\"usage\":" + invalid; await Call();
        }
        Check(Read().Window.UsageInvalid == 6 && Read().Window.UsageMissing == 2 && Read().Window.TotalTokens == 15, "Invalid/negative/overflow/inconsistent usage was counted");
        provider.Usage = ",\"usage\":{\"prompt_tokens\":0,\"completion_tokens\":0,\"total_tokens\":0}"; await Call();
        Check(Read().Window.UsageReported == 2 && Read().Window.TotalTokens == 15, "Explicit zero provider usage is unavailable");
        provider.Status = HttpStatusCode.ServiceUnavailable; await Call(true);
        provider.Status = HttpStatusCode.TooManyRequests; await Call(true);
        provider.Status = HttpStatusCode.OK; provider.Timeout = true; await Call(true); provider.Timeout = false;
        Check(Read().Window.Failed == 1 && Read().Window.Busy == 1 && Read().Window.TimedOut == 1, "Provider failure/busy/timeout outcome attribution incorrect");
        provider.Wait = true;
        using var cancel = new CancellationTokenSource();
        var a = connector.TestConnectionAsync(settings, cancel.Token); var b = connector.TestConnectionAsync(settings, cancel.Token);
        await Call(true);
        Check(Read().InFlight == 2 && Read().Capacity == 2 && Read().Window.Busy == 2, "Concurrent capacity or local busy counting incorrect");
        cancel.Cancel();
        foreach (var task in new[] { a, b }) { try { await task; throw new Exception("Cancellation swallowed"); } catch (OperationCanceledException) { checks++; } }
        provider.Wait = false;
        m = Read(); Check(m.InFlight == 0 && m.Window.Cancelled == 2 && m.Window.Requests == m.StartedRequests, "Requests were double counted or cancellation retained capacity");
        Check(m.Window.Requests == m.Window.Success + m.Window.Failed + m.Window.Busy + m.Window.Cancelled + m.Window.TimedOut, "Outcome partition is incomplete");
        clock.Advance(15 * 60 * 1000);
        Check(Read().Window.Requests == 0 && Read().Window.TotalTokens is null && Read().SinceRestart.TotalTokens == 15, "Window expiry lost lifetime counters or fabricated usage");
        Check(telemetry.Snapshot(settings with { Model = "different" }, 15).ConfiguredObservation is null, "An unsaved different model made the saved connection appear reachable");
        var restarted = new LlmTelemetry(clock); Check(restarted.Snapshot(settings).SinceRestart.Requests == 0 && restarted.Snapshot(settings).LastSuccess is null, "Restart retained observations without persistence");
        var bounded = new LlmTelemetry(clock, 2);
        for (int i = 0; i < 3; i++) { var attempt = bounded.Begin(settings, "ConnectionTest"); clock.Advance(100); bounded.Finish(attempt, "Success", new("Reported", new(1, 1, 2))); }
        var limited = bounded.Snapshot(settings, 15);
        Check(!limited.WindowComplete && limited.Window.Requests == 2 && limited.SinceRestart.Requests == 3 && limited.Trend.Last().Requests is null, "Bounded retention silently reports complete or zero-filled windows");
        clock.Advance(60 * 60 * 1000); Check(bounded.Snapshot(settings).WindowComplete && bounded.Snapshot(settings).Window.Requests == 0, "Expired truncation contaminates future window");
        var percentiles = new LlmTelemetry(clock);
        foreach (int ms in new[] { 100, 200, 300, 400, 500 }) { var a1 = percentiles.Begin(settings, "ConnectionTest"); clock.Advance(ms); percentiles.Finish(a1, "Success"); }
        clock.Wall = clock.Wall.AddDays(-2);
        Check(percentiles.Snapshot(settings).SuccessfulLatency is { P50Milliseconds: 300, P95Milliseconds: 500, Samples: 5 }, "Monotonic nearest-rank percentiles changed with wall clock");
        var huge = new LlmTelemetry(clock);
        for (int i = 0; i < 2; i++) { var request = huge.Begin(settings, "ConnectionTest"); huge.Finish(request, "Success", new("Reported", new(LlmTelemetry.MaxExact, 0, LlmTelemetry.MaxExact))); }
        Check(huge.Snapshot(settings).SinceRestart is { Saturated: true, TotalTokens: LlmTelemetry.MaxExact }, "Aggregate overflow silently wrapped or lost exact integer bounds");
        string json = JsonSerializer.Serialize(Read());
        Check(!json.Contains(settings.Endpoint) && !json.Contains("Benign fixture reply") && !json.Contains("ApiKeyEnvironment"), "Statistics contain endpoint, response or credential reference");
        Console.WriteLine($"PASS: {checks} benign LLM usage, outcomes, concurrency, monotonic timing, coverage and retention checks.");
    }
}
