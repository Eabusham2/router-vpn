namespace RouterVPN.ControllerUI.Tests
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    public static partial class TransportTests
    {
        // Compiled only beside the existing assembly-private authenticated
        // stream fixture. The production PowerShell module has no public
        // channel-injection parameter and shipping C# has no test constructor.
        public sealed class AdapterHarness : IDisposable
        {
            private readonly Duplex[] pair = Duplex.Pair();
            private readonly Task server;
            private int revoked, calls, cancelled;
            public readonly ManualResetEventSlim Entered = new ManualResetEventSlim();
            public readonly ControllerChannel Channel;
            public int Calls { get { return Volatile.Read(ref calls); } }
            public int Cancelled { get { return Volatile.Read(ref cancelled); } }
            public AdapterHarness()
            {
                Channel = new ControllerChannel(pair[0], delegate {
                    if (Volatile.Read(ref revoked) != 0) throw new InvalidOperationException("captured adapter peer retired");
                }, null, 5000);
                server = Task.Run((Func<Task>)Serve);
            }
            public static byte[] Pattern(int length)
            {
                byte[] value = new byte[length];
                for (int index = 0; index < value.Length; index++) value[index] = (byte)(index * 29 + 7);
                return value;
            }
            public static string Hash(byte[] body)
            {
                using (SHA256 hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(body)).Replace("-", "").ToLowerInvariant();
            }
            private async Task Serve()
            {
                try
                {
                    while (true)
                    {
                        Frame request = await ReadFrame(pair[1]).ConfigureAwait(false);
                        if (request.Kind == 2)
                        {
                            Interlocked.Increment(ref cancelled);
                            byte[] terminal = ReplyHeader(5, request.ID, 0, 0);
                            await pair[1].WriteAsync(terminal, 0, terminal.Length).ConfigureAwait(false);
                            continue;
                        }
                        if (request.Kind != 1) throw new InvalidOperationException("adapter sent another frame kind");
                        Interlocked.Increment(ref calls);
                        if (request.Path == "/api/hold") { Entered.Set(); continue; }
                        int status = request.Path == "/api/fail" ? 409 : 200;
                        string body = "{\"path\":\"" + Convert.ToBase64String(UTF8.GetBytes(request.Path)) +
                            "\",\"method\":" + request.Method + ",\"bytes\":" + request.Body.Length +
                            ",\"sha256\":\"" + Hash(request.Body) + "\",\"timeout\":" + request.Timeout +
                            ",\"limit\":" + request.Limit + "}";
                        await Reply(pair[1], request, status, UTF8.GetBytes(body)).ConfigureAwait(false);
                    }
                }
                catch (EndOfStreamException) { }
                catch (ObjectDisposedException) { }
                catch (InvalidOperationException) { if (!pair[0].Disposed.Task.IsCompleted) throw; }
            }
            public void Revoke() { Interlocked.Exchange(ref revoked, 1); }
            public void Dispose()
            {
                Channel.CloseAsync().GetAwaiter().GetResult();
                pair[1].Dispose();
                if (!server.Wait(5000)) throw new InvalidOperationException("adapter fixture server did not join");
                Entered.Dispose();
            }
        }
    }
}
