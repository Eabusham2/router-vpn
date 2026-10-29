namespace RouterVPN.ControllerUI.Tests
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Collections;
    using System.Diagnostics;
    using System.IO;
    using System.IO.Pipes;
    using System.Net;
    using System.Net.Http;
    using System.Security.Cryptography;
    using System.Reflection;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    public static class TransportTests
    {
        private static readonly Encoding UTF8 = new UTF8Encoding(false, true);
        private static void Check(bool value, string message)
        { if (!value) throw new InvalidOperationException("CONTROL " + message); }
        private static async Task<T> Within<T>(Task<T> task, string message)
        {
            Task done = await Task.WhenAny(task, Task.Delay(8000)).ConfigureAwait(false);
            Check(done == task, message + " timed out");
            return await task.ConfigureAwait(false);
        }
        private static async Task Within(Task task, string message)
        {
            Task done = await Task.WhenAny(task, Task.Delay(8000)).ConfigureAwait(false);
            Check(done == task, message + " timed out");
            await task.ConfigureAwait(false);
        }
        private static async Task Rejected(Task task, string message)
        {
            try { await Within(task, message).ConfigureAwait(false); }
            catch (Exception error)
            {
                if (error.Message.StartsWith("CONTROL ", StringComparison.Ordinal)) throw;
                return;
            }
            throw new InvalidOperationException("CONTROL " + message);
        }

        private sealed class Mailbox
        {
            internal readonly BlockingCollection<byte[]> Bytes = new BlockingCollection<byte[]>();
        }
        private sealed class Duplex : Stream
        {
            private readonly Mailbox input, output;
            private byte[] current;
            private int offset;
            private readonly object readGate = new object();
            private int disposed;
            internal int MaxRead = 4096;
            internal int BlockAfter = -1;
            internal long Written;
            internal readonly TaskCompletionSource<bool> Entered = ControllerChannel.NewCompletion<bool>();
            internal readonly TaskCompletionSource<bool> Continue = ControllerChannel.NewCompletion<bool>();
            internal readonly TaskCompletionSource<bool> Disposed = ControllerChannel.NewCompletion<bool>();
            internal Duplex(Mailbox source, Mailbox destination) { input = source; output = destination; }
            internal static Duplex[] Pair()
            {
                Mailbox a = new Mailbox(), b = new Mailbox();
                return new Duplex[] { new Duplex(a, b), new Duplex(b, a) };
            }
            public override bool CanRead { get { return true; } }
            public override bool CanWrite { get { return true; } }
            public override bool CanSeek { get { return false; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
            public override void Flush() { }
            public override long Seek(long value, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
            public override int Read(byte[] buffer, int at, int count) { return ReadAsync(buffer, at, count, CancellationToken.None).GetAwaiter().GetResult(); }
            public override void Write(byte[] buffer, int at, int count) { WriteAsync(buffer, at, count, CancellationToken.None).GetAwaiter().GetResult(); }
            public override Task<int> ReadAsync(byte[] buffer, int at, int count, CancellationToken token)
            {
                return Task.Run(delegate
                {
                    lock (readGate)
                    {
                        while (current == null || offset == current.Length)
                        {
                            try { current = input.Bytes.Take(token); offset = 0; }
                            catch (InvalidOperationException) { return 0; }
                        }
                        int copy = Math.Min(Math.Min(count, MaxRead), current.Length - offset);
                        Buffer.BlockCopy(current, offset, buffer, at, copy);
                        offset += copy;
                        return copy;
                    }
                });
            }
            private void Emit(byte[] buffer, int at, int count)
            {
                if (count == 0) return;
                byte[] copy = new byte[count]; Buffer.BlockCopy(buffer, at, copy, 0, count);
                output.Bytes.Add(copy); Interlocked.Add(ref Written, count);
            }
            public override async Task WriteAsync(byte[] buffer, int at, int count, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                int split = Interlocked.Exchange(ref BlockAfter, -1);
                if (split >= 0)
                {
                    split = Math.Min(split, count);
                    Emit(buffer, at, split);
                    Entered.TrySetResult(true);
                    // This exact entered operation deliberately cannot be
                    // retired until the test supplies its join witness.
                    await Continue.Task.ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                    Emit(buffer, at + split, count - split);
                }
                else Emit(buffer, at, count);
            }
            protected override void Dispose(bool disposing)
            {
                if (disposing && Interlocked.Exchange(ref disposed, 1) == 0)
                {
                    input.Bytes.CompleteAdding(); output.Bytes.CompleteAdding();
                    Disposed.TrySetResult(true);
                }
                base.Dispose(disposing);
            }
        }

        private sealed class Frame
        {
            internal byte[] Header, Body;
            internal string Path;
            internal ulong ID;
            internal byte Kind, Method;
            internal int Limit, Timeout;
        }
        private static async Task ReadBytes(Stream stream, byte[] bytes)
        {
            int offset = 0;
            while (offset < bytes.Length)
            {
                int read = await stream.ReadAsync(bytes, offset, bytes.Length - offset).ConfigureAwait(false);
                if (read == 0) throw new EndOfStreamException();
                offset += read;
            }
        }
        private static ulong Number(byte[] source, int start, int length)
        {
            ulong value = 0;
            for (int i = start; i < start + length; i++) value = value * 256 + source[i];
            return value;
        }
        private static void Number(byte[] target, int start, int length, ulong value)
        {
            for (int i = start + length - 1; i >= start; i--) { target[i] = (byte)(value % 256); value /= 256; }
        }
        private static byte[] ReplyHeader(byte kind, ulong id, int status, int length)
        {
            byte[] raw = new byte[32];
            Buffer.BlockCopy(Encoding.ASCII.GetBytes("RVB1"), 0, raw, 0, 4);
            raw[4] = kind; Number(raw, 6, 2, (ulong)status); Number(raw, 8, 8, id); Number(raw, 24, 4, (ulong)length);
            return raw;
        }
        private static async Task<Frame> ReadFrame(Stream stream)
        {
            byte[] header = new byte[32]; await ReadBytes(stream, header).ConfigureAwait(false);
            Check(Encoding.ASCII.GetString(header, 0, 4) == "RVB1", "request header lost its wire version");
            int pathLength = (int)Number(header, 20, 2), bodyLength = (int)Number(header, 24, 4);
            Check(pathLength <= 2048 && bodyLength >= 0 && bodyLength <= (32 << 20), "request length is not bounded");
            byte[] path = new byte[pathLength], body = new byte[bodyLength];
            await ReadBytes(stream, path).ConfigureAwait(false); await ReadBytes(stream, body).ConfigureAwait(false);
            return new Frame { Header = header, Kind = header[4], Method = header[5], ID = Number(header, 8, 8),
                Path = UTF8.GetString(path), Body = body, Limit = (int)Number(header, 28, 4), Timeout = (int)Number(header, 16, 4) };
        }
        private static async Task Reply(Stream stream, Frame request, int status, byte[] body)
        {
            byte[] header = ReplyHeader(3, request.ID, status, body.Length);
            await stream.WriteAsync(header, 0, header.Length).ConfigureAwait(false);
            await stream.WriteAsync(body, 0, body.Length).ConfigureAwait(false);
        }
        private static ControllerChannel Channel(Stream stream)
        { return new ControllerChannel(stream, delegate { }, null, 5000); }
        private static HttpRequestMessage Request(string target, byte[] bytes)
        {
            HttpRequestMessage request = new HttpRequestMessage(bytes == null ? HttpMethod.Get : HttpMethod.Post, ControllerChannel.Origin + target);
            if (bytes != null) request.Content = new ByteArrayContent(bytes);
            return request;
        }

        private static async Task GoldenHeaderAndResponse()
        {
            Duplex[] pair = Duplex.Pair(); pair[0].MaxRead = 3; pair[1].MaxRead = 2;
            using (ControllerChannel channel = Channel(pair[0]))
            using (HttpClient client = channel.CreateClient(5000, 256))
            {
                Task<HttpResponseMessage> operation = client.SendAsync(Request("/api/status", null));
                Frame request = await Within(ReadFrame(pair[1]), "golden request").ConfigureAwait(false);
                Check(request.Timeout > 0 && request.Timeout <= 5000, "serialized timeout extended admission");
                byte[] normalized = (byte[])request.Header.Clone(); Number(normalized, 16, 4, 5000);
                string hex = BitConverter.ToString(normalized).Replace("-", "").ToLowerInvariant();
                Check(hex == "5256423101010000000000000000000100001388000b00000000000000000100", "cross-language header bytes changed");
                Check(request.Path == "/api/status" && request.Body.Length == 0, "request target/body changed");
                await Reply(pair[1], request, 409, UTF8.GetBytes("selected owner changed")).ConfigureAwait(false);
                using (HttpResponseMessage result = await Within(operation, "golden response").ConfigureAwait(false))
                {
                    Check((int)result.StatusCode == 409 && !result.IsSuccessStatusCode, "non-success HTTP status was replaced");
                    Check(await result.Content.ReadAsStringAsync().ConfigureAwait(false) == "selected owner changed", "HTTP failure body was replaced");
                }
            }
            pair[1].Dispose();
        }

        private static async Task ConcurrentIDsAndReplies()
        {
            Duplex[] pair = Duplex.Pair(); pair[0].MaxRead = 7;
            using (ControllerChannel channel = Channel(pair[0]))
            using (HttpClient client = channel.CreateClient(5000, 1024))
            {
                List<Task<HttpResponseMessage>> operations = new List<Task<HttpResponseMessage>>();
                for (int i = 0; i < 16; i++)
                {
                    int captured = i;
                    operations.Add(Task.Run(delegate { return client.SendAsync(Request("/api/status?item=" + captured, null)); }));
                }
                List<Frame> frames = new List<Frame>();
                for (int i = 0; i < 16; i++)
                {
                    Frame request = await Within(ReadFrame(pair[1]), "concurrent request").ConfigureAwait(false);
                    Check(request.ID == (ulong)i + 1, "serialized request IDs were reused or reordered"); frames.Add(request);
                }
                for (int i = frames.Count - 1; i >= 0; i--)
                    await Reply(pair[1], frames[i], 200, UTF8.GetBytes(frames[i].Path)).ConfigureAwait(false);
                for (int i = 0; i < operations.Count; i++)
                    using (HttpResponseMessage response = await Within(operations[i], "correlated response").ConfigureAwait(false))
                        Check(await response.Content.ReadAsStringAsync().ConfigureAwait(false) == "/api/status?item=" + i, "response adopted another request");
            }
            pair[1].Dispose();
        }

        private static async Task CancelBeforeAndDuringFrame()
        {
            Duplex[] pair = Duplex.Pair();
            using (ControllerChannel channel = Channel(pair[0]))
            using (HttpClient client = channel.CreateClient(5000, 1024))
            using (CancellationTokenSource cancelled = new CancellationTokenSource())
            {
                cancelled.Cancel();
                await Rejected(client.SendAsync(Request("/api/status", null), cancelled.Token), "pre-cancel request was sent").ConfigureAwait(false);
                Check(pair[0].Written == 0, "pre-cancel request consumed an ID or wrote bytes");
                pair[0].BlockAfter = 9;
                using (CancellationTokenSource active = new CancellationTokenSource())
                {
                    Task<HttpResponseMessage> result = client.SendAsync(Request("/api/disconnect", UTF8.GetBytes("{}")), active.Token);
                    await Within(pair[0].Entered.Task, "partial write entered").ConfigureAwait(false);
                    active.Cancel();
                    await Rejected(result, "cancelled request completed successfully").ConfigureAwait(false);
                    Check(!pair[0].Disposed.Task.IsCompleted, "request cancellation corrupted a committed frame");
                    pair[0].Continue.TrySetResult(true);
                    Frame request;
                    try { request = await Within(ReadFrame(pair[1]), "complete cancelled frame").ConfigureAwait(false); }
                    catch (Exception error) { throw new InvalidOperationException("CONTROL request cancellation corrupted a committed frame", error); }
                    Check(request.ID == 1 && request.Method == 2 && request.Path == "/api/disconnect" && UTF8.GetString(request.Body) == "{}", "request cancellation corrupted a committed frame");
                    Frame cancel = await Within(ReadFrame(pair[1]), "cancel after request").ConfigureAwait(false);
                    Check(cancel.Kind == 2 && cancel.ID == request.ID && cancel.Body.Length == 0, "cancellation overtook or changed its request");
                    // Response and cancellation can cross. The retained ID must
                    // consume this late success without killing another request.
                    await Reply(pair[1], request, 200, UTF8.GetBytes("late success")).ConfigureAwait(false);
                    Task<HttpResponseMessage> next = client.SendAsync(Request("/api/status", null));
                    Frame second = await Within(ReadFrame(pair[1]), "replacement request").ConfigureAwait(false);
                    Check(second.ID == 2, "cancelled ID was reused");
                    await Reply(pair[1], second, 200, UTF8.GetBytes("current")).ConfigureAwait(false);
                    using (HttpResponseMessage response = await Within(next, "response after cancelled tombstone").ConfigureAwait(false))
                        Check(await response.Content.ReadAsStringAsync().ConfigureAwait(false) == "current", "late response replaced a current operation");
                }
            }
            pair[1].Dispose();
        }

        private static async Task WidgetDisposalPreservesChannel()
        {
            Duplex[] pair = Duplex.Pair();
            using (ControllerChannel channel = Channel(pair[0]))
            using (HttpClient second = channel.CreateClient(5000, 1024))
            {
                HttpClient first = channel.CreateClient(5000, 1024);
                Task<HttpResponseMessage> pending = first.SendAsync(Request("/api/status", null));
                Frame request = await Within(ReadFrame(pair[1]), "widget request").ConfigureAwait(false);
                first.Dispose();
                Check(!pair[0].Disposed.Task.IsCompleted, "widget disposal closed the common channel");
                await Rejected(pending, "disposed widget retained its request").ConfigureAwait(false);
                Frame cancellation = await Within(ReadFrame(pair[1]), "widget cancellation").ConfigureAwait(false);
                Check(cancellation.Kind == 2 && cancellation.ID == request.ID, "widget disposal did not cancel only its request");
                byte[] terminal = ReplyHeader(5, request.ID, 0, 0); await pair[1].WriteAsync(terminal, 0, terminal.Length).ConfigureAwait(false);
                Task<HttpResponseMessage> alive = second.SendAsync(Request("/api/profiles", null));
                Frame next = await Within(ReadFrame(pair[1]), "remaining widget request").ConfigureAwait(false);
                await Reply(pair[1], next, 200, UTF8.GetBytes("[]")).ConfigureAwait(false);
                using (HttpResponseMessage response = await Within(alive, "remaining widget response").ConfigureAwait(false))
                    Check(response.IsSuccessStatusCode && !pair[0].Disposed.Task.IsCompleted, "widget disposal closed the common channel");
            }
            pair[1].Dispose();
        }

        private static async Task CloseJoinsEnteredWrite()
        {
            Duplex[] pair = Duplex.Pair(); pair[0].BlockAfter = 5;
            ControllerChannel channel = Channel(pair[0]);
            using (HttpClient client = channel.CreateClient(5000, 1024))
            {
                Task<HttpResponseMessage> request = client.SendAsync(Request("/api/status", null));
                await Within(pair[0].Entered.Task, "close fixture entered write").ConfigureAwait(false);
                Task close = channel.CloseAsync();
                await Within(pair[0].Disposed.Task, "close revocation").ConfigureAwait(false);
                await Rejected(request, "channel close retained a callable request").ConfigureAwait(false);
                Check(!close.IsCompleted, "channel close released an entered write before join");
                pair[0].Continue.TrySetResult(true);
                await Within(close, "joined channel close").ConfigureAwait(false);
                await Rejected(client.SendAsync(Request("/api/status", null)), "closed channel admitted a replacement").ConfigureAwait(false);
            }
            channel.Dispose(); pair[1].Dispose();
        }

        private static async Task BoundsAndTargets()
        {
            string[] invalid = { "/api/controller/identity", "/api/controller", "/api/../status", "/api//status", "/api/%73tatus",
                "/api/status#secret", "/api/status?bad=%", "/api/status?x=1;y=2", "/api\\status", "/api/status/" };
            Duplex[] pair = Duplex.Pair();
            using (ControllerChannel channel = Channel(pair[0]))
            using (HttpClient client = channel.CreateClient(1000, 1024))
            {
                foreach (string path in invalid)
                    await Rejected(client.SendAsync(Request(path, null)), "invalid local target was accepted " + path).ConfigureAwait(false);
                await Rejected(client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://127.0.0.1:8788/api/status")), "another URI scheme was accepted").ConfigureAwait(false);
                await Rejected(client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://localhost:8788/api/status")), "another authority was accepted").ConfigureAwait(false);
                await Rejected(client.SendAsync(new HttpRequestMessage(new HttpMethod("PATCH"), ControllerChannel.Origin + "/api/status")), "unsupported method was accepted").ConfigureAwait(false);
                HttpRequestMessage headers = Request("/api/status", null); headers.Headers.Add("Authorization", "not-a-credential");
                await Rejected(client.SendAsync(headers), "caller headers were accepted").ConfigureAwait(false);
                await Rejected(client.SendAsync(Request("/api/profile/import?x=1", new byte[(8 << 20) + 1])), "query gained the large-import exception").ConfigureAwait(false);
                await Rejected(client.SendAsync(Request("/api/external-profile/import", new byte[(8 << 20) + 1])), "another route gained the large-import exception").ConfigureAwait(false);
                await Rejected(client.SendAsync(Request("/api/profile/import", new byte[(32 << 20) + 1])), "oversize import was accepted").ConfigureAwait(false);
                Check(pair[0].Written == 0, "invalid target/body escaped before rejection");
            }
            pair[1].Dispose();
        }

        private static async Task ExactLargeImport()
        {
            Duplex[] pair = Duplex.Pair(); byte[] body = new byte[32 << 20];
            for (int i = 0; i < body.Length; i++) body[i] = (byte)(i * 17 + 3);
            byte[] expected; using (SHA256 hash = SHA256.Create()) expected = hash.ComputeHash(body);
            using (ControllerChannel channel = Channel(pair[0]))
            using (HttpClient client = channel.CreateClient(15000, 1024))
            {
                Task<HttpResponseMessage> result = client.SendAsync(Request("/api/profile/import", body));
                Task<Frame> received = ReadFrame(pair[1]);
                Task first = await Task.WhenAny(result, received).ConfigureAwait(false);
                Check(first == received, "32MiB import was rejected before transmission");
                Frame frame = await Within(received, "32MiB import").ConfigureAwait(false);
                byte[] actual; using (SHA256 hash = SHA256.Create()) actual = hash.ComputeHash(frame.Body);
                Check(frame.Body.Length == body.Length && Convert.ToBase64String(actual) == Convert.ToBase64String(expected), "32MiB import bytes changed or were truncated");
                await Reply(pair[1], frame, 200, UTF8.GetBytes("{}" )).ConfigureAwait(false);
                using (HttpResponseMessage response = await Within(result, "large import response").ConfigureAwait(false)) Check(response.IsSuccessStatusCode, "large import failed");
            }
            pair[1].Dispose();
        }

        private static async Task PendingAndAggregateBudgets()
        {
            Duplex[] pair = Duplex.Pair();
            using (ControllerChannel channel = Channel(pair[0]))
            using (HttpClient client = channel.CreateClient(5000, 1024))
            {
                List<Task<HttpResponseMessage>> tasks = new List<Task<HttpResponseMessage>>();
                for (int i = 0; i < 32; i++) tasks.Add(client.SendAsync(Request("/api/status", null)));
                for (int i = 0; i < 32; i++) await Within(ReadFrame(pair[1]), "bounded pending request").ConfigureAwait(false);
                await Rejected(client.SendAsync(Request("/api/status", null)), "pending limit was exceeded").ConfigureAwait(false);
                Check(pair[0].Written == 32L * (32 + 11), "pending limit was exceeded");
                await channel.CloseAsync().ConfigureAwait(false);
                foreach (Task<HttpResponseMessage> task in tasks) await Rejected(task, "closed pending request succeeded").ConfigureAwait(false);
            }
            pair[1].Dispose(); pair = Duplex.Pair();
            using (ControllerChannel channel = Channel(pair[0]))
            using (HttpClient client = channel.CreateClient(5000, 8 << 20))
            {
                byte[] body = new byte[32 << 20];
                Task<HttpResponseMessage> first = client.SendAsync(Request("/api/profile/import", body));
                await Rejected(client.SendAsync(Request("/api/profile/import", body)), "aggregate byte budget was exceeded").ConfigureAwait(false);
                Check(pair[0].Written <= 32L + "/api/profile/import".Length + body.Length, "aggregate byte budget was exceeded");
                await channel.CloseAsync().ConfigureAwait(false);
                await Rejected(first, "budget owner close failed").ConfigureAwait(false);
            }
            pair[1].Dispose();
        }

        private static async Task ResponseValidation()
        {
            string[] cases = { "limit", "magic", "reserved", "foreign-id", "kind", "status", "truncated", "utf8" };
            foreach (string name in cases)
            {
                Duplex[] pair = Duplex.Pair();
                using (ControllerChannel channel = Channel(pair[0]))
                using (HttpClient client = channel.CreateClient(5000, 8))
                {
                    Task<HttpResponseMessage> result = client.SendAsync(Request("/api/status", null), HttpCompletionOption.ResponseHeadersRead);
                    Frame request = await Within(ReadFrame(pair[1]), "response validation request").ConfigureAwait(false);
                    byte[] raw = ReplyHeader(3, request.ID, 200, 0);
                    if (name == "limit") raw = ReplyHeader(3, request.ID, 200, 9);
                    if (name == "magic") raw[0] = 0;
                    if (name == "reserved") raw[22] = 1;
                    if (name == "foreign-id") raw = ReplyHeader(3, request.ID + 1, 200, 0);
                    if (name == "kind") raw[4] = 1;
                    if (name == "status") raw = ReplyHeader(3, request.ID, 99, 0);
                    if (name == "truncated") raw = ReplyHeader(3, request.ID, 200, 4);
                    if (name == "utf8") raw = ReplyHeader(4, request.ID, 0, 2);
                    await pair[1].WriteAsync(raw, 0, raw.Length).ConfigureAwait(false);
                    if (name == "truncated") pair[1].Dispose();
                    if (name == "utf8") await pair[1].WriteAsync(new byte[] { 0xc3, 0x28 }, 0, 2).ConfigureAwait(false);
                    await Rejected(result, "malformed response accepted " + name).ConfigureAwait(false);
                    await Within(pair[0].Disposed.Task, "malformed response did not revoke channel " + name).ConfigureAwait(false);
                }
                pair[1].Dispose();
            }
        }

        private static async Task FailureAndCancelled()
        {
            Duplex[] pair = Duplex.Pair();
            using (ControllerChannel channel = Channel(pair[0]))
            using (HttpClient client = channel.CreateClient(5000, 1024))
            {
                for (byte kind = 4; kind <= 5; kind++)
                {
                    Task<HttpResponseMessage> request = client.SendAsync(Request("/api/status", null));
                    Frame frame = await Within(ReadFrame(pair[1]), "terminal request").ConfigureAwait(false);
                    byte[] body = kind == 4 ? UTF8.GetBytes("The captured local controller request failed.") : new byte[0];
                    byte[] header = ReplyHeader(kind, frame.ID, 0, body.Length);
                    await pair[1].WriteAsync(header, 0, header.Length).ConfigureAwait(false); await pair[1].WriteAsync(body, 0, body.Length).ConfigureAwait(false);
                    await Rejected(request, "non-success terminal frame was reported successful").ConfigureAwait(false);
                    if (kind == 5) Check(request.IsCanceled, "server cancellation was not a cancelled task");
                }
                Task<HttpResponseMessage> last = client.SendAsync(Request("/api/status", null));
                Frame final = await Within(ReadFrame(pair[1]), "request after terminal frames").ConfigureAwait(false);
                await Reply(pair[1], final, 200, UTF8.GetBytes("ok")).ConfigureAwait(false);
                using (HttpResponseMessage response = await Within(last, "final response").ConfigureAwait(false)) Check(response.IsSuccessStatusCode, "terminal frame retired another request");
            }
            pair[1].Dispose();
        }

        private static async Task RevokedPublication()
        {
            Duplex[] pair = Duplex.Pair();
            using (ControllerChannel channel = Channel(pair[0]))
            using (HttpClient client = channel.CreateClient(5000, 1024))
            {
                Task<HttpResponseMessage> task = client.SendAsync(Request("/api/status", null));
                Frame frame = await Within(ReadFrame(pair[1]), "publication request").ConfigureAwait(false);
                Type type = typeof(ControllerChannel);
                object gate = type.GetField("gate", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(channel);
                IDictionary pending = (IDictionary)type.GetField("pending", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(channel);
                object state;
                lock (gate) state = pending[frame.ID];
                MethodInfo publish = type.GetMethod("PublishResponse", BindingFlags.Instance | BindingFlags.NonPublic);
                FieldInfo closing = type.GetField("closing", BindingFlags.Instance | BindingFlags.NonPublic);
                using (HttpResponseMessage late = new HttpResponseMessage(HttpStatusCode.OK))
                {
                    late.Content = new StringContent("held old response");
                    lock (gate)
                    {
                        // Hold precisely the real Retire linearization point:
                        // admission revoked, terminal TCS delivery not yet run.
                        // Invoke the same publication method as ReadLoop, with
                        // its genuine pending request and an unsettled result.
                        closing.SetValue(channel, true);
                        try
                        {
                            bool accepted = (bool)publish.Invoke(channel, new object[] { state, late });
                            Check(!accepted && !task.IsCompleted, "revoked channel published a held response");
                        }
                        finally { closing.SetValue(channel, false); }
                    }
                }
                await channel.CloseAsync().ConfigureAwait(false);
                await Rejected(task, "revoked publication remained live").ConfigureAwait(false);
            }
            pair[1].Dispose();
        }

        private static async Task CapturedDeadlineBehindWriter()
        {
            Duplex[] pair = Duplex.Pair(); pair[0].BlockAfter = 7;
            long clock = 0;
            using (ControllerChannel channel = new ControllerChannel(pair[0], delegate { }, null, 5000, delegate { return Interlocked.Read(ref clock); }))
            using (HttpClient client = channel.CreateClient(900000, 1024))
            {
                Task<HttpResponseMessage> first = client.SendAsync(Request("/api/status?first", null));
                await Within(pair[0].Entered.Task, "deadline writer entered").ConfigureAwait(false);
                HttpRequestMessage queued = Request("/api/status?remaining", null);
                HttpRequestMessage expired = Request("/api/status?expired", null);
#pragma warning disable 0618
                queued.Properties["RouterVPNControllerTimeoutMilliseconds"] = 500000;
                expired.Properties["RouterVPNControllerTimeoutMilliseconds"] = 1000;
#pragma warning restore 0618
                Task<HttpResponseMessage> second = client.SendAsync(queued), third = client.SendAsync(expired);
                // Advance only this internal seam's monotonic clock. No sleeps,
                // scheduling assumption or production timeout is changed.
                Interlocked.Exchange(ref clock, Stopwatch.Frequency * 250000L / 1000L);
                pair[0].Continue.TrySetResult(true);
                Frame a = await Within(ReadFrame(pair[1]), "first deadline frame").ConfigureAwait(false);
                Frame b = await Within(ReadFrame(pair[1]), "remaining deadline frame").ConfigureAwait(false);
                Check(a.ID == 1 && b.ID == 2 && b.Path == "/api/status?remaining" && b.Timeout == 250000,
                    "writer serialization extended the captured request deadline");
                await Rejected(third, "expired queued request reached the wire").ConfigureAwait(false);
                await Reply(pair[1], a, 200, UTF8.GetBytes("first")).ConfigureAwait(false);
                await Reply(pair[1], b, 200, UTF8.GetBytes("second")).ConfigureAwait(false);
                using (HttpResponseMessage result = await Within(first, "first deadline response").ConfigureAwait(false)) { }
                using (HttpResponseMessage result = await Within(second, "second deadline response").ConfigureAwait(false)) { }
                Task<HttpResponseMessage> after = client.SendAsync(Request("/api/status?after", null));
                Frame c = await Within(ReadFrame(pair[1]), "request after expiry").ConfigureAwait(false);
                Check(c.ID == 3 && c.Path == "/api/status?after", "expired queued request consumed or reused an ID");
                await Reply(pair[1], c, 200, UTF8.GetBytes("current")).ConfigureAwait(false);
                using (HttpResponseMessage result = await Within(after, "response after expiry").ConfigureAwait(false)) { }
                foreach (object invalid in new object[] { 0, 900001, "5000", 5000L })
                {
                    HttpRequestMessage request = Request("/api/status", null);
#pragma warning disable 0618
                    request.Properties["RouterVPNControllerTimeoutMilliseconds"] = invalid;
#pragma warning restore 0618
                    await Rejected(client.SendAsync(request), "invalid deadline override was accepted").ConfigureAwait(false);
                }
            }
            pair[1].Dispose();
        }

        private static async Task AdmissionCloseJoin()
        {
            Duplex[] pair = Duplex.Pair();
            ControllerChannel channel = Channel(pair[0]);
            using (ManualResetEventSlim entered = new ManualResetEventSlim())
            using (ManualResetEventSlim release = new ManualResetEventSlim())
            using (HttpRequestMessage message = Request("/api/status", null))
            {
                MethodInfo send = typeof(ControllerChannel).GetMethod("SendAsync", BindingFlags.Instance | BindingFlags.NonPublic);
                Task<HttpResponseMessage> operation = Task.Run(delegate
                {
                    return (Task<HttpResponseMessage>)send.Invoke(channel, new object[] { message, 5000, 1024, CancellationToken.None,
                        new Action(delegate { entered.Set(); release.Wait(); }) });
                });
                Check(entered.Wait(5000), "admission hold did not reach its captured boundary");
                Task close = channel.CloseAsync();
                try
                {
                    // Retire records this authority synchronously. Inspect it
                    // while the actual admitted caller is held, rather than
                    // guessing whether its async finalizer has been scheduled.
                    FieldInfo joinedField = typeof(ControllerChannel).GetField("writesJoined", BindingFlags.Instance | BindingFlags.NonPublic);
                    TaskCompletionSource<bool> joined = (TaskCompletionSource<bool>)joinedField.GetValue(channel);
                    Check(!joined.Task.IsCompleted, "close released an admitted request before writer dispatch joined");
                    await Within(pair[0].Disposed.Task, "admission close revocation").ConfigureAwait(false);
                    Check(!close.IsCompleted, "close released an admitted request before writer dispatch joined");
                }
                finally { release.Set(); }
                await Rejected(operation, "revoked admission was dispatched successfully").ConfigureAwait(false);
                await Within(close, "joined admitted request close").ConfigureAwait(false);
                Check(pair[0].Written == 0, "revoked admission wrote a private frame");
            }
            channel.Dispose(); pair[1].Dispose();
        }

        private sealed class NoPostContext : SynchronizationContext
        {
            internal int Posts;
            public override void Post(SendOrPostCallback callback, object state)
            { Interlocked.Increment(ref Posts); throw new InvalidOperationException("UI context must not execute transport continuations"); }
        }
        private static Task SynchronousUIContext()
        {
            return Task.Run(delegate
            {
                Duplex[] pair = Duplex.Pair();
                using (ControllerChannel channel = Channel(pair[0]))
                using (HttpClient client = channel.CreateClient(5000, 1024))
                {
                    Task server = Task.Run(async delegate
                    {
                        Frame request = await ReadFrame(pair[1]).ConfigureAwait(false);
                        await Reply(pair[1], request, 200, UTF8.GetBytes("sync")).ConfigureAwait(false);
                    });
                    SynchronizationContext previous = SynchronizationContext.Current; NoPostContext context = new NoPostContext();
                    try
                    {
                        SynchronizationContext.SetSynchronizationContext(context);
                        using (HttpResponseMessage response = client.SendAsync(Request("/api/status", null)).GetAwaiter().GetResult())
                            Check(response.Content.ReadAsStringAsync().GetAwaiter().GetResult() == "sync", "synchronous UI result changed");
                        Check(context.Posts == 0, "transport captured the UI synchronization context");
                    }
                    finally { SynchronizationContext.SetSynchronizationContext(previous); }
                    server.GetAwaiter().GetResult();
                }
                pair[1].Dispose();
            });
        }

        private static async Task PeerRevocationAndPrivateSeam()
        {
            Check(typeof(ControllerChannel).GetConstructors().Length == 0, "production exposes unauthenticated stream construction");
            Check(!ControllerChannel.ValidPipeName(@"\\other\pipe\RouterVPN-Controller-v1-" + new string('a', 32)), "remote pipe name was accepted");
            Check(ControllerChannel.ValidPipeName(ControllerChannel.PipePrefix + new string('a', 32)), "exact local pipe name was rejected");
            Duplex[] pair = Duplex.Pair(); bool live = true;
            using (ControllerChannel channel = new ControllerChannel(pair[0], delegate { if (!live) throw new IOException("captured parent exited"); }, null, 5000))
            using (HttpClient client = channel.CreateClient(5000, 1024))
            {
                live = false;
                await Rejected(client.SendAsync(Request("/api/status", null)), "dead retained parent admitted private bytes").ConfigureAwait(false);
                Check(pair[0].Written == 0, "dead parent received private bytes");
                await Within(pair[0].Disposed.Task, "idle parent-death revocation").ConfigureAwait(false);
            }
            pair[1].Dispose();
        }

        private static async Task RealDuplexPipeBytes()
        {
            string name = "RouterVPN-UI-test-" + Guid.NewGuid().ToString("N");
            using (NamedPipeServerStream server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
            using (NamedPipeClientStream clientPipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                Task accepting = server.WaitForConnectionAsync();
                await clientPipe.ConnectAsync(5000).ConfigureAwait(false); await accepting.ConfigureAwait(false);
                using (ControllerChannel channel = Channel(clientPipe))
                using (HttpClient client = channel.CreateClient(5000, 1024))
                {
                    Task<HttpResponseMessage> response = client.SendAsync(Request("/api/profile/settings", UTF8.GetBytes("{\"name\":\"\u0625\u064a\u0627\u062f\"}")));
                    Frame frame = await Within(ReadFrame(server), "actual pipe request").ConfigureAwait(false);
                    Check(UTF8.GetString(frame.Body) == "{\"name\":\"\u0625\u064a\u0627\u062f\"}", "actual pipe changed UTF8 JSON");
                    await Reply(server, frame, 200, frame.Body).ConfigureAwait(false);
                    using (HttpResponseMessage result = await Within(response, "actual pipe response").ConfigureAwait(false))
                        Check(await result.Content.ReadAsStringAsync().ConfigureAwait(false) == UTF8.GetString(frame.Body), "actual pipe reply changed UTF8 JSON");
                }
            }
        }

        private static async Task RejectedNativeDispatchJoins()
        {
            // No native request may enter when the managed scheduler rejects
            // dispatch. The actual owner still has to remain closeable.
            using (NamedPipeClientStream pipe = new NamedPipeClientStream(".", "RouterVPN-unused-" + Guid.NewGuid().ToString("N"),
                PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                Type native = typeof(ControllerChannel).GetNestedType("OwnedPipeStream", BindingFlags.NonPublic);
                Stream stream = (Stream)Activator.CreateInstance(native, BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { pipe }, null);
                MethodInfo start = native.GetMethod("StartOperation", BindingFlags.Instance | BindingFlags.NonPublic);
                MethodInfo finish = native.GetMethod("FinishOperation", BindingFlags.Instance | BindingFlags.NonPublic);
                FieldInfo count = native.GetField("operations", BindingFlags.Instance | BindingFlags.NonPublic);
                Exception rejected = new InvalidOperationException("owned scheduler rejected the operation");
                bool observed = false;
                Func<Func<int>, Task<int>> dispatch = delegate { throw rejected; };
                try
                {
                    try { start.Invoke(stream, new object[] { new byte[1], 0, 1, false, CancellationToken.None, dispatch }); }
                    catch (TargetInvocationException error) { observed = Object.ReferenceEquals(error.InnerException, rejected); }
                    Check(observed, "native scheduler rejection was not preserved");
                    Check((int)count.GetValue(stream) == 0, "native scheduler rejection retained an unowned operation");
                    await Within(Task.Run(delegate { stream.Dispose(); }), "rejected native scheduling close").ConfigureAwait(false);
                }
                finally
                {
                    // The negative variant has submitted no IRP either. Join
                    // only that fixture's known rejected bookkeeping before
                    // releasing its otherwise unconnected test pipe owner.
                    if ((int)count.GetValue(stream) == 1) finish.Invoke(stream, new object[0]);
                    stream.Dispose();
                }
            }
        }

        private static async Task WindowsNativeOverlapped()
        {
            string name = "RouterVPN-UI-native-test-" + Guid.NewGuid().ToString("N");
            using (NamedPipeServerStream server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
            using (NamedPipeClientStream pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                Task accepting = server.WaitForConnectionAsync();
                await pipe.ConnectAsync(5000).ConfigureAwait(false); await accepting.ConfigureAwait(false);
                Type native = typeof(ControllerChannel).GetNestedType("OwnedPipeStream", BindingFlags.NonPublic);
                Stream stream = (Stream)Activator.CreateInstance(native, BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { pipe }, null);
                using (ControllerChannel channel = Channel(stream))
                using (HttpClient client = channel.CreateClient(5000, 8192))
                {
                    for (int i = 0; i < 16; i++)
                    {
                        byte[] bytes = new byte[4097 + i]; for (int n = 0; n < bytes.Length; n++) bytes[n] = (byte)(n + i);
                        Task<HttpResponseMessage> response = client.SendAsync(Request("/api/profile/settings", bytes));
                        Frame frame = await Within(ReadFrame(server), "actual native OVERLAPPED request").ConfigureAwait(false);
                        Check(frame.Body.Length == bytes.Length, "native OVERLAPPED changed request length");
                        await Reply(server, frame, 200, bytes).ConfigureAwait(false);
                        using (HttpResponseMessage result = await Within(response, "actual native OVERLAPPED reply").ConfigureAwait(false))
                            Check(Convert.ToBase64String(await result.Content.ReadAsByteArrayAsync().ConfigureAwait(false)) == Convert.ToBase64String(bytes),
                                "native OVERLAPPED reply bytes changed");
                    }
                    // The next native read is idle/pending. Close must cancel
                    // and join it before releasing the CLR-bound pipe handle.
                    await Within(channel.CloseAsync(), "native pending read cancellation join").ConfigureAwait(false);
                }
            }
        }

        public static void Run(string selected)
        {
            List<KeyValuePair<string, Func<Task>>> cases = new List<KeyValuePair<string, Func<Task>>> {
                Case("golden", GoldenHeaderAndResponse), Case("concurrent", ConcurrentIDsAndReplies),
                Case("cancel-frame", CancelBeforeAndDuringFrame), Case("widget-dispose", WidgetDisposalPreservesChannel),
                Case("close-join", CloseJoinsEnteredWrite), Case("targets", BoundsAndTargets), Case("large-import", ExactLargeImport),
                Case("budgets", PendingAndAggregateBudgets), Case("responses", ResponseValidation), Case("terminals", FailureAndCancelled),
                Case("sync-context", SynchronousUIContext), Case("peer-revocation", PeerRevocationAndPrivateSeam), Case("real-pipe", RealDuplexPipeBytes),
                Case("publication-revocation", RevokedPublication), Case("captured-deadline", CapturedDeadlineBehindWriter),
                Case("admission-close", AdmissionCloseJoin), Case("native-dispatch-failure", RejectedNativeDispatchJoins)
            };
            if (Environment.OSVersion.Platform == PlatformID.Win32NT) cases.Add(Case("native-overlapped", WindowsNativeOverlapped));
            int count = 0;
            foreach (KeyValuePair<string, Func<Task>> test in cases)
            {
                if (selected != null && selected.Length != 0 && selected != test.Key) continue;
                Within(test.Value(), test.Key).GetAwaiter().GetResult();
                Console.WriteLine("PASS controller GUI transport " + test.Key); count++;
            }
            Check(count > 0, "test selector matched no executable cases");
            Console.WriteLine("PASS controller GUI transport total=" + count);
        }
        private static KeyValuePair<string, Func<Task>> Case(string name, Func<Task> test)
        { return new KeyValuePair<string, Func<Task>>(name, test); }
    }
}
