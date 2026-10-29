namespace RouterVPN.ControllerUI.BridgeFixture
{
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using RouterVPN.ControllerUI;

// A native Framework process fixture for the public shipping channel. No
// authenticated-Stream seam, bearer, TLS pin or private parent field is used.
// The native Go launcher supplies its real inherited read-only process handle.
public static class BridgeProcess
{
    private static readonly Uri Origin = new Uri("https://127.0.0.1:8788");

    public static int Main(string[] args)
    {
        if (args.Length != 4) return 120;
        try
        {
            Run(args).GetAwaiter().GetResult();
            return 0;
        }
        catch (Exception error)
        {
            File.WriteAllText(args[3], "FAIL " + error.ToString(), new UTF8Encoding(false));
            return 1;
        }
    }

    private static void Report(string path, string text)
    { File.WriteAllText(path, text, new UTF8Encoding(false)); }

    private static async Task<string> Get(HttpClient client, string path)
    {
        using (HttpResponseMessage response = await client.GetAsync(new Uri(Origin, path)).ConfigureAwait(false))
        {
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }
    }

    private static async Task Run(string[] args)
    {
        string mode = args[0], pipe = args[1], report = args[3];
        long parent;
        if (!Int64.TryParse(args[2], out parent) || parent <= 0) throw new Exception("invalid captured parent");
        ControllerChannel channel = null;
        try
        {
            try
            {
                channel = await ControllerChannel.ConnectAsync(pipe, parent, 10000, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                if (mode == "reject-peer") { Report(report, "REJECTED PEER"); return; }
                throw;
            }
            if (mode == "reject-peer") throw new Exception("unproved peer acquired the C# channel");
            using (HttpClient first = channel.CreateClient(10000, 256 * 1024))
            using (HttpClient second = channel.CreateClient(10000, 256 * 1024))
            {
                if (mode == "reject-request")
                {
                    try { await Get(first, "/api/status").ConfigureAwait(false); }
                    catch { Report(report, "REJECTED REQUEST"); return; }
                    throw new Exception("unproved TLS controller received an accepted UI request");
                }
                if (await Get(first, "/api/status").ConfigureAwait(false) != "captured")
                    throw new Exception("captured status changed");
                if (mode == "hold" || mode == "second-stage")
                {
                    Report(report, "READY");
                    if (mode == "hold") { await Task.Delay(30000).ConfigureAwait(false); return; }
                    DateTime end = DateTime.UtcNow.AddSeconds(12);
                    while (!File.Exists(report + ".continue"))
                    {
                        if (DateTime.UtcNow >= end) throw new Exception("owned continuation was not received");
                        await Task.Delay(10).ConfigureAwait(false);
                    }
                    if (await Get(second, "/api/status").ConfigureAwait(false) != "captured")
                        throw new Exception("another GUI cleanup changed the surviving request");
                    Report(report, "PASS SECOND STAGE");
                    return;
                }
                if (mode == "pending")
                {
                    Report(report, "READY");
                    await Get(first, "/api/hold").ConfigureAwait(false);
                    throw new Exception("retired GUI received a held private response");
                }
                if (mode == "cancel")
                {
                    using (CancellationTokenSource cancel = new CancellationTokenSource())
                    {
                        Task<HttpResponseMessage> pending = first.GetAsync(new Uri(Origin, "/api/hold"), cancel.Token);
                        if (await Get(second, "/api/entered").ConfigureAwait(false) != "entered")
                            throw new Exception("held HTTP request did not enter");
                        cancel.Cancel();
                        bool cancelled = false;
                        try { using (HttpResponseMessage unexpected = await pending.ConfigureAwait(false)) { } }
                        catch (OperationCanceledException) { cancelled = true; }
                        if (!cancelled) throw new Exception("actual C# cancellation delivered a response");
                        if (await Get(second, "/api/drained").ConfigureAwait(false) != "drained")
                            throw new Exception("cancelled Go request did not join its HTTP owner");
                    }
                    Report(report, "PASS CANCEL");
                    return;
                }
                if (mode != "roundtrip") throw new Exception("unrecognized fixture mode");
                first.Dispose();
                if (await Get(second, "/api/status").ConfigureAwait(false) != "captured")
                    throw new Exception("widget disposal closed another captured client");
                byte[] body = new byte[32769];
                for (int index = 0; index < body.Length; index++) body[index] = (byte)((index * 29 + 7) & 255);
                using (ByteArrayContent content = new ByteArrayContent(body))
                using (HttpResponseMessage response = await second.PostAsync(new Uri(Origin, "/api/profile/import"), content).ConfigureAwait(false))
                {
                    if ((int)response.StatusCode != 207) throw new Exception("captured HTTP status was lost");
                    byte[] echo = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                    if (echo.Length != body.Length) throw new Exception("actual pipe chunking changed body length");
                    for (int index = 0; index < body.Length; index++)
                        if (echo[index] != body[index]) throw new Exception("actual pipe chunking changed private bytes");
                }
                Report(report, "PASS ROUNDTRIP");
            }
        }
        finally
        {
            if (channel != null) channel.CloseAsync().GetAwaiter().GetResult();
        }
    }
}
}
