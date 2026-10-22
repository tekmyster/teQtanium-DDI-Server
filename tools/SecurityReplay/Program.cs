// Copyright (c) 2026 Tekmyster Industries, LLC. GPL-3.0; see ../../LICENSE.
using System.Text.Json;
using System.Text.Json.Serialization;

try
{
    if (args.Length == 1 && args[0] == "--self-test") { ReplayChecks.Run(); return 0; }
    if (args.Length == 2 && args[0] == "--write-synthetic-fixture") { ReplayChecks.WriteFixture(args[1]); return 0; }
    if (args.Length == 3 && args[0] == "--verify-report")
    {
        Replay.VerifyReport(args[1], args[2]);
        Console.WriteLine("Report integrity and current input rights assertions verified; no quality qualification.");
        return 0;
    }
    if (args.Length != 3) throw new ArgumentException("Usage: SecurityReplay <manifest.json> <reviewed-psl.dat> <new-report.json> | --self-test");
    using var cancellation = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancellation.Cancel(); };
    var report = JsonSerializer.SerializeToElement(Replay.Run(args[0], args[1], cancellation.Token), Replay.Json);
    string expected = report.GetProperty("inputSha256").GetString()!;
    string pending = args[2] + ".pending";
    Replay.CheckPublication(args[0], expected);
    // One bounded pending file per explicit output; never overwrite prior evidence.
    using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None))
    {
        JsonSerializer.Serialize(output, new { Version = 1, Sha256 = Replay.Hash(JsonSerializer.SerializeToUtf8Bytes(report)), Payload = report }, Replay.Json);
        if (output.Length > 32 * 1024 * 1024) throw new IOException("Result exceeds the 32 MiB cap.");
        output.Flush(true);
    }
    cancellation.Token.ThrowIfCancellationRequested();
    Replay.CheckPublication(args[0], expected);
    File.Move(pending, args[2], false);
    Console.WriteLine("Offline replay report written. Qualification remains subject to independent review.");
    return 0;
}
catch (Exception e) when (e is ArgumentException or IOException or JsonException or InvalidOperationException or OperationCanceledException or KeyNotFoundException or UnauthorizedAccessException)
{
    Console.Error.WriteLine(e.Message);
    return 2;
}
