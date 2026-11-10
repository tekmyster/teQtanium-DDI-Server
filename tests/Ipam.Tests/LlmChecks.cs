// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
using DnsServerCore.Security;
using System.Net;

// Benign connector-only checks. No detector traffic, policy writes or external model calls.
static class LlmChecks
{
    sealed class ModelStub : HttpMessageHandler
    {
        public string Body;
        public string Response = "{\"choices\":[{\"message\":{\"content\":\"Synthetic model reply.\"}}]}";
        public HttpStatusCode Status = HttpStatusCode.OK;
        public bool Wait;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Body = await request.Content.ReadAsStringAsync(token);
            if (Wait) await Task.Delay(Timeout.Infinite, token);
            return new(Status) { Content = new StringContent(Response) };
        }
    }
    public static async Task Run()
    {
        int checks = 0;
        void Check(bool value, string name) { if (!value) throw new Exception(name); checks++; }
        async Task Fail(Func<Task> run, string expected)
        {
            try { await run(); }
            catch (InvalidOperationException ex) { Check(ex.Message.Contains(expected), "Expected actionable model failure: " + expected); return; }
            throw new Exception("Expected model failure: " + expected);
        }
        var settings = new LlmSettings(false, "http://127.0.0.1:11434/v1/chat/completions", "fixture-model", ShareDomains: true);
        var stub = new ModelStub();
        using var client = new HttpClient(stub);
        using var connector = new SecurityLlm(client);
        var result = await connector.TestConnectionAsync(settings);
        Check(result.EventId == "connection-test" && result.Model == settings.Model && !result.DomainsShared && result.Status == "Advisory", "Connection check provenance or privacy changed");
        Check(stub.Body.Contains("benign model connection check") && !stub.Body.Contains("clientAddress"), "Connection check lacks fixed benign prompt");
        foreach (var body in new[] { "{}", "{\"choices\":[]}", "{\"choices\":[{\"message\":{\"content\":\"\"}}]}", "{\"choices\":[{\"message\":{\"tool_calls\":[]}}]}", "invalid JSON" })
        {
            stub.Response = body;
            await Fail(() => connector.TestConnectionAsync(settings), "unsupported response");
        }
        stub.Response = new string('x', 65537);
        await Fail(() => connector.TestConnectionAsync(settings), "64 KiB");
        foreach (var status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.NotFound, HttpStatusCode.TooManyRequests, HttpStatusCode.ServiceUnavailable })
        {
            stub.Status = status;
            await Fail(() => connector.TestConnectionAsync(settings), status switch { HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => "denied access", HttpStatusCode.NotFound => "not found", HttpStatusCode.TooManyRequests => "busy", _ => "rejected" });
        }
        stub.Status = HttpStatusCode.OK;
        stub.Response = "{\"choices\":[{\"message\":{\"content\":\"Synthetic model reply.\"}}]}";
        stub.Wait = true;
        using var cancel = new CancellationTokenSource();
        var first = connector.TestConnectionAsync(settings, cancel.Token);
        var second = connector.TestConnectionAsync(settings, cancel.Token);
        await Fail(() => connector.TestConnectionAsync(settings), "Two analyses");
        cancel.Cancel();
        foreach (var task in new[] { first, second })
        {
            try { await task; throw new Exception("Caller cancellation swallowed"); }
            catch (OperationCanceledException) { checks++; }
        }
        stub.Wait = false;
        Check((await connector.TestConnectionAsync(settings)).Summary == "Synthetic model reply.", "Capacity did not recover after cancellation");
        string priorCa = Environment.GetEnvironmentVariable("DDI_LLM_CA_FILE");
        try
        {
            Environment.SetEnvironmentVariable("DDI_LLM_CA_FILE", Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "missing.pem"));
            using var badCa = new SecurityLlm(); // Invalid optional integration configuration must not fail service construction.
            await Fail(() => badCa.TestConnectionAsync(settings), "CA file could not be loaded");
        }
        finally { Environment.SetEnvironmentVariable("DDI_LLM_CA_FILE", priorCa); }
        Console.WriteLine($"PASS: {checks} benign LLM connector checks; no external model called.");
    }
}
