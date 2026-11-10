// Modified by Tekmyster Industries, LLC — remains GPL-3.0
using DnsServerCore.Security;
using System.Diagnostics;
using System.Net;
using System.Text;

static class FeedDeadlineChecks
{
    sealed class StalledBody : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) { await Task.Delay(Timeout.InfiniteTimeSpan, token); return 0; }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
    sealed class Provider(bool edl) : HttpMessageHandler
    {
        public bool Stall;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            HttpContent body = Stall ? new StreamContent(new StalledBody()) : new StringContent(edl ? "fixture.example\n" : "{\"response\":{\"Attribute\":[{\"uuid\":\"00000000-0000-4000-8000-000000000001\",\"type\":\"domain\",\"value\":\"fixture.example\"}]}}", Encoding.UTF8, edl ? "text/plain" : "application/json");
            if (Stall) body.Headers.ContentType = new(edl ? "text/plain" : "application/json");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = body });
        }
    }
    public static async Task Run()
    {
        string folder = Path.Combine(Path.GetTempPath(), "ddi-feed-deadlines-" + Guid.NewGuid().ToString("N"));
        Environment.SetEnvironmentVariable("DDI_MISP_DEADLINE_API_KEY", "fixture");
        var suffixes = new PublicSuffixes(["example"]); var misp = new Provider(false); var edl = new Provider(true);
        try
        {
            await using var m = new DdiSecurityManager(Path.Combine(folder, "misp"), suffixes, new HttpClient(misp) { Timeout = TimeSpan.FromMilliseconds(500) });
            await using var e = new DdiSecurityManager(Path.Combine(folder, "edl"), suffixes, new HttpClient(edl) { Timeout = TimeSpan.FromMilliseconds(500) });
            m.SetPolicy(SecurityPolicy.Default with { Enabled = true, Misp = new(true, "https://fixture.test", "DDI_MISP_DEADLINE_API_KEY") }, 0);
            e.SetPolicy(SecurityPolicy.Default with { Enabled = true, EdlFeeds = [new("fixture", "Domain", "https://fixture.test/list", true)] }, 0);
            await Task.WhenAll(m.RefreshMispAsync(), e.RefreshEdlAsync());
            if (m.MispStatus.Indicators != 1 || e.EdlStatus()[0].Entries != 1) throw new Exception("Deadline fixture seed was not accepted");
            byte[] mBefore = m.ExportEnrichment(), eBefore = e.ExportEdl();
            e.SetPolicy(e.Policy, e.Policy.Revision); misp.Stall = true; edl.Stall = true;
            var elapsed = Stopwatch.StartNew();
            await Task.WhenAll(m.RefreshMispAsync(), e.RefreshEdlAsync()).WaitAsync(TimeSpan.FromSeconds(75));
            if (elapsed.Elapsed < TimeSpan.FromSeconds(55) || elapsed.Elapsed > TimeSpan.FromSeconds(75)) throw new Exception("Whole-body deadline not observed");
            if (!mBefore.SequenceEqual(m.ExportEnrichment()) || !eBefore.SequenceEqual(e.ExportEdl()) || !m.MispStatus.Status.Contains("failed") || !e.EdlStatus()[0].Status.Contains("failed")) throw new Exception("Deadline did not retain complete cache and report failure");
            Console.WriteLine($"PASS: both real asynchronous stalled-body reads cancelled by whole-refresh deadline after {elapsed.Elapsed.TotalSeconds:F1}s; complete MISP/EDL caches retained (fixture transport).");
        }
        finally { Environment.SetEnvironmentVariable("DDI_MISP_DEADLINE_API_KEY", null); if (Directory.Exists(folder)) Directory.Delete(folder, true); }
    }
}
