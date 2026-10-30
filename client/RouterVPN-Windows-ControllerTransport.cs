// The native UI owns no HTTP socket, TLS callback or controller credential.
// Its separately authenticated launcher forwards this bounded pipe protocol.
// Keep this source compatible with Windows PowerShell 5.1 / .NET Framework.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace RouterVPN.ControllerUI
{
    public sealed class ControllerChannel : IDisposable
    {
        internal const int HeaderSize = 32;
        internal const int MaxBody = 8 << 20;
        internal const int MaxImport = 32 << 20;
        internal const int MaxPending = 32;
        internal const long MaxReserved = 64L << 20;
        internal const int MaxTimeout = 900000;
        internal const int MaxSpeedLabTimeout = 960000;
        internal const string Origin = "https://127.0.0.1:8788";
        internal const string PipePrefix = @"\\.\pipe\RouterVPN-Controller-v1-";
        internal static readonly UTF8Encoding UTF8 = new UTF8Encoding(false, true);

        private readonly Stream stream;
        private readonly Action verifyPeer;
        private readonly IDisposable retainedPeer;
        private readonly int frameTimeout;
        private readonly Func<long> timestamp;
        private readonly object gate = new object();
        private readonly SemaphoreSlim writer = new SemaphoreSlim(1, 1);
        private readonly CancellationTokenSource lifetime = new CancellationTokenSource();
        private readonly HashSet<RequestState> requests = new HashSet<RequestState>();
        private readonly Dictionary<ulong, RequestState> pending = new Dictionary<ulong, RequestState>();
        private readonly TaskCompletionSource<bool> started = NewCompletion<bool>();
        private readonly TaskCompletionSource<bool> writesJoined = NewCompletion<bool>();
        private readonly TaskCompletionSource<bool> closed = NewCompletion<bool>();
        private Task readerTask;
        private Task peerTask;
        private ulong lastID;
        private long reserved;
        private int writes;
        private bool closing;
        private Exception closeReason;

        private sealed class RequestState
        {
            internal readonly TaskCompletionSource<HttpResponseMessage> Result = NewCompletion<HttpResponseMessage>();
            internal CancellationTokenSource Cancellation;
            internal CancellationTokenRegistration Registration;
            internal ulong ID;
            internal long Reserved;
            internal int ResponseLimit;
            internal long AdmittedAt;
            internal int Timeout;
            internal bool Cancelled, CancelQueued, Released;
        }

        internal static TaskCompletionSource<T> NewCompletion<T>()
        {
            return new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        // The only stream-injection seam is assembly-private for executable
        // framing tests. Normal callers must use ConnectAsync and real peers.
        internal ControllerChannel(Stream authenticatedStream, Action peerCheck, IDisposable peer, int frameMilliseconds, Func<long> monotonic = null)
        {
            if (authenticatedStream == null || !authenticatedStream.CanRead || !authenticatedStream.CanWrite ||
                peerCheck == null || frameMilliseconds < 1 || frameMilliseconds > 15000)
                throw new ArgumentException("The native UI requires its captured duplex channel.");
            stream = authenticatedStream;
            verifyPeer = peerCheck;
            retainedPeer = peer;
            frameTimeout = frameMilliseconds;
            timestamp = monotonic ?? Stopwatch.GetTimestamp;
            verifyPeer();
            readerTask = Task.Run((Func<Task>)ReadLoopAsync);
            peerTask = Task.Run((Func<Task>)WatchPeerAsync);
            started.TrySetResult(true);
        }

        public static async Task<ControllerChannel> ConnectAsync(string fullPipeName, long inheritedParentHandle,
            int timeoutMilliseconds, CancellationToken cancellationToken)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                throw new PlatformNotSupportedException("The native UI requires a Windows process-owned pipe.");
            if (!ValidPipeName(fullPipeName) || inheritedParentHandle <= 0 || timeoutMilliseconds < 1 || timeoutMilliseconds > 15000)
                throw new ArgumentException("The native UI handoff is invalid.");
            ParentOwner parent = null;
            OwnedPipeStream owned = null;
            NamedPipeClientStream pipe = null;
            try
            {
                parent = new ParentOwner(new IntPtr(inheritedParentHandle));
                pipe = new NamedPipeClientStream(".", fullPipeName.Substring(9), PipeDirection.InOut,
                    PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
                // Connect(int) is available on Framework as well as modern
                // .NET. Join the bounded native call even after cancellation.
                NamedPipeClientStream connecting = pipe;
                await Task.Run(delegate { connecting.Connect(timeoutMilliseconds); }).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                parent.VerifyPipe(pipe.SafePipeHandle);
                owned = new OwnedPipeStream(pipe);
                pipe = null;
                using (CancellationTokenSource handoff = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    handoff.CancelAfter(5000);
                    byte[] hello = UTF8.GetBytes("RouterVPN-UI-Bridge-v1\n");
                    await WriteExactAsync(owned, hello, handoff.Token).ConfigureAwait(false);
                    byte[] expected = UTF8.GetBytes("RouterVPN-UI-Bridge-Ready-v1\n");
                    byte[] received = new byte[expected.Length];
                    await ReadExactAsync(owned, received, 0, received.Length, handoff.Token).ConfigureAwait(false);
                    for (int i = 0; i < expected.Length; i++)
                        if (received[i] != expected[i]) throw ProtocolError();
                    parent.VerifyPipe(owned.PipeHandle);
                }
                ParentOwner capturedParent = parent;
                OwnedPipeStream capturedPipe = owned;
                ControllerChannel result = new ControllerChannel(owned,
                    delegate { capturedParent.VerifyPipe(capturedPipe.PipeHandle); }, parent, 15000);
                owned = null;
                parent = null;
                return result;
            }
            finally
            {
                if (owned != null) owned.Dispose();
                if (pipe != null) pipe.Dispose();
                if (parent != null) parent.Dispose();
            }
        }

        internal static bool ValidPipeName(string name)
        {
            if (name == null || !name.StartsWith(PipePrefix, StringComparison.Ordinal) || name.Length != PipePrefix.Length + 32)
                return false;
            for (int i = PipePrefix.Length; i < name.Length; i++)
                if (!(name[i] >= '0' && name[i] <= '9') && !(name[i] >= 'a' && name[i] <= 'f')) return false;
            return true;
        }

        // A feature owns its client and handler, never the common channel.
        // Existing per-request CTS values remain effective; the header also
        // carries an independent bounded server deadline.
        public HttpClient CreateClient(int timeoutMilliseconds, int responseLimit)
        {
            if (timeoutMilliseconds < 1 || timeoutMilliseconds > MaxSpeedLabTimeout || responseLimit < 1 || responseLimit > MaxBody)
                throw new ArgumentOutOfRangeException("The native UI request bounds are invalid.");
            lock (gate) { ThrowIfClosed(); }
            HttpClient client = new HttpClient(new ControllerHandler(this, timeoutMilliseconds, responseLimit), true);
            client.Timeout = Timeout.InfiniteTimeSpan;
            client.MaxResponseContentBufferSize = responseLimit;
            return client;
        }

        private sealed class ControllerHandler : HttpMessageHandler
        {
            private readonly ControllerChannel channel;
            private readonly int timeout, limit;
            private readonly CancellationTokenSource disposed = new CancellationTokenSource();
            private int retired;
            internal ControllerHandler(ControllerChannel owner, int requestTimeout, int responseLimit)
            { channel = owner; timeout = requestTimeout; limit = responseLimit; }
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
            {
                if (Interlocked.CompareExchange(ref retired, 0, 0) != 0) throw new ObjectDisposedException("ControllerHandler");
                using (CancellationTokenSource owned = CancellationTokenSource.CreateLinkedTokenSource(token, disposed.Token))
                    return await channel.SendAsync(request, timeout, limit, owned.Token).ConfigureAwait(false);
            }
            protected override void Dispose(bool disposing)
            {
                if (disposing && Interlocked.Exchange(ref retired, 1) == 0) disposed.Cancel();
                // The token source stays alive while a registered request can
                // still observe it. Channel retirement joins those requests.
                base.Dispose(disposing);
            }
        }

        private static string Target(HttpRequestMessage request)
        {
            if (request == null || request.RequestUri == null || !request.RequestUri.IsAbsoluteUri)
                throw ProtocolError();
            string original = request.RequestUri.OriginalString;
            if (!original.StartsWith(Origin + "/api/", StringComparison.Ordinal)) throw ProtocolError();
            string target = original.Substring(Origin.Length);
            ValidateTarget(target);
            // Do not let System.Uri silently normalize a different authority,
            // port, path, fragment or userinfo into the captured endpoint.
            if (request.RequestUri.Scheme != "https" || request.RequestUri.Host != "127.0.0.1" || request.RequestUri.Port != 8788 ||
                request.RequestUri.UserInfo != "" || request.RequestUri.Fragment != "") throw ProtocolError();
            foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
                throw new InvalidOperationException("The native UI cannot forward request headers.");
            return target;
        }

        internal static void ValidateTarget(string target)
        {
            if (target == null || !target.StartsWith("/api/", StringComparison.Ordinal) || UTF8.GetByteCount(target) > 2048)
                throw ProtocolError();
            for (int i = 0; i < target.Length; i++)
                if (target[i] < 32 || target[i] == 127 || target[i] == '\\' || target[i] == '#') throw ProtocolError();
            int query = target.IndexOf('?');
            string path = query < 0 ? target : target.Substring(0, query);
            if (path.IndexOf('%') >= 0 || path.IndexOf("//", StringComparison.Ordinal) >= 0 || path.EndsWith("/", StringComparison.Ordinal) ||
                path == "/api/controller" || path.StartsWith("/api/controller/", StringComparison.Ordinal)) throw ProtocolError();
            string[] parts = path.Split('/');
            foreach (string part in parts) if (part == "." || part == "..") throw ProtocolError();
            if (query >= 0)
                for (int i = query + 1; i < target.Length; i++)
                {
                    if (target[i] == ';') throw ProtocolError();
                    if (target[i] == '%')
                    {
                        if (i + 2 >= target.Length || !Hex(target[i + 1]) || !Hex(target[i + 2])) throw ProtocolError();
                        i += 2;
                    }
                }
        }

        private static bool Hex(char value)
        { return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'; }

        private static byte Method(HttpMethod method)
        {
            if (method == HttpMethod.Get) return 1;
            if (method == HttpMethod.Post) return 2;
            if (method == HttpMethod.Put) return 3;
            if (method == HttpMethod.Delete) return 4;
            throw ProtocolError();
        }

        private Task<HttpResponseMessage> SendAsync(HttpRequestMessage message, int timeout, int limit, CancellationToken token, Action afterAdmission = null)
        {
            token.ThrowIfCancellationRequested();
            verifyPeer();
            string target = Target(message);
            byte method = Method(message.Method);
            object capturedTimeout;
            // Properties is the Framework-compatible per-request API. The
            // optional value only narrows this handler's configured ceiling.
#pragma warning disable 0618
            if (message.Properties.TryGetValue("RouterVPNControllerTimeoutMilliseconds", out capturedTimeout))
#pragma warning restore 0618
            {
                if (!(capturedTimeout is int) || (int)capturedTimeout < 1 || (int)capturedTimeout > timeout) throw ProtocolError();
                timeout = (int)capturedTimeout;
            }
            // The established Tor Compare Speed Lab operation captures a
            // 960-second budget. No other method/target borrows that allowance.
            int timeoutLimit = method == 2 && target == "/api/speed-lab/run" ? MaxSpeedLabTimeout : MaxTimeout;
            if (timeout > timeoutLimit) throw ProtocolError();
            byte[] path = UTF8.GetBytes(target);
            long contentLength = 0;
            if (message.Content != null)
            {
                // The shipping UI sends captured JSON StringContent and exact
                // ByteArrayContent imports. Reject unbounded/lazy serializers.
                if (!(message.Content is ByteArrayContent) || !message.Content.Headers.ContentLength.HasValue)
                    throw new InvalidOperationException("The native UI requires a bounded captured request body.");
                contentLength = message.Content.Headers.ContentLength.Value;
            }
            int bodyLimit = method == 2 && target == "/api/profile/import" ? MaxImport : MaxBody;
            if (contentLength < 0 || contentLength > bodyLimit) throw ProtocolError();
            RequestState state = new RequestState();
            state.ResponseLimit = limit;
            state.AdmittedAt = timestamp();
            state.Timeout = timeout;
            state.Reserved = contentLength + path.Length + limit;
            state.Cancellation = CancellationTokenSource.CreateLinkedTokenSource(token, lifetime.Token);
            state.Cancellation.CancelAfter(timeout);
            try
            {
                lock (gate)
                {
                    ThrowIfClosed();
                    if (requests.Count >= MaxPending || state.Reserved > MaxReserved || reserved > MaxReserved - state.Reserved)
                        throw new InvalidOperationException("The native UI channel has reached its bounded request budget.");
                    requests.Add(state);
                    reserved += state.Reserved;
                    // Close observes a fully registered request AND its queued
                    // writer owner together. It cannot dispose a half-admitted
                    // CTS before registration/dispatch has finished.
                    state.Registration = state.Cancellation.Token.Register(delegate { CancelRequest(state); });
                    writes++;
                }
            }
            catch { Release(state); throw; }
            try
            {
                // Only the internal executable test holds this boundary. The
                // shipping handler never supplies a callback or alternate owner.
                if (afterAdmission != null) afterAdmission();
                StartOwnedWrite(delegate { return WriteRequestAsync(state, message, method, path, (int)contentLength); });
            }
            catch (Exception error)
            {
                state.Result.TrySetException(error);
                Release(state);
                FinishWrite();
                throw;
            }
            return state.Result.Task;
        }

        private void QueueWrite(Func<Task> operation)
        {
            lock (gate)
            {
                if (closing) return;
                writes++;
            }
            try { StartOwnedWrite(operation); }
            catch (Exception error) { FinishWrite(); Retire(error); }
        }

        private void StartOwnedWrite(Func<Task> operation)
        {
            Task.Run(async delegate
            {
                try { await operation().ConfigureAwait(false); }
                catch (Exception error) { Retire(error); }
                finally
                {
                    FinishWrite();
                }
            });
        }

        private void FinishWrite()
        {
            lock (gate) { writes--; if (closing && writes == 0) writesJoined.TrySetResult(true); }
        }

        private async Task WriteRequestAsync(RequestState state, HttpRequestMessage message, byte method, byte[] path, int bodyLength)
        {
            bool acquired = false;
            try
            {
                await writer.WaitAsync(state.Cancellation.Token).ConfigureAwait(false);
                acquired = true;
                state.Cancellation.Token.ThrowIfCancellationRequested();
                verifyPeer();
                byte[] body = message.Content == null ? new byte[0] : await message.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                if (body.Length != bodyLength) throw ProtocolError();
                byte[] header = new byte[HeaderSize];
                lock (gate)
                {
                    ThrowIfClosed();
                    state.Cancellation.Token.ThrowIfCancellationRequested();
                    long elapsed = timestamp() - state.AdmittedAt;
                    if (elapsed < 0) throw ProtocolError();
                    double remaining = state.Timeout - elapsed * (1000.0 / Stopwatch.Frequency);
                    if (remaining < 1) throw new OperationCanceledException("The captured native UI deadline elapsed before transmission.");
                    if (lastID == UInt64.MaxValue) throw ProtocolError();
                    state.ID = ++lastID;
                    pending.Add(state.ID, state);
                    Header(header, 1, method, 0, state.ID, (uint)Math.Floor(remaining), (ushort)path.Length, (uint)body.Length, (uint)state.ResponseLimit);
                }
                using (CancellationTokenSource frame = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token))
                {
                    frame.CancelAfter(frameTimeout);
                    // After ID commitment the frame uses ONLY channel lifetime,
                    // never the individual request's cancellation token.
                    await WriteExactAsync(stream, header, frame.Token).ConfigureAwait(false);
                    await WriteExactAsync(stream, path, frame.Token).ConfigureAwait(false);
                    await WriteExactAsync(stream, body, frame.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                if (state.ID != 0) throw;
                state.Result.TrySetCanceled();
            }
            catch (Exception error)
            {
                if (state.ID != 0) throw;
                state.Result.TrySetException(error);
            }
            finally
            {
                if (acquired) writer.Release();
                if (state.ID == 0) Release(state);
            }
        }

        private void CancelRequest(RequestState state)
        {
            bool send = false;
            lock (gate)
            {
                if (state.Released) return;
                state.Cancelled = true;
                state.Result.TrySetCanceled();
                if (!closing && state.ID != 0 && !state.CancelQueued) { state.CancelQueued = true; send = true; }
            }
            if (send) QueueWrite(delegate { return WriteCancelAsync(state); });
        }

        private async Task WriteCancelAsync(RequestState state)
        {
            await writer.WaitAsync(lifetime.Token).ConfigureAwait(false);
            try
            {
                lock (gate) { if (state.Released || closing) return; }
                verifyPeer();
                byte[] header = new byte[HeaderSize];
                Header(header, 2, 0, 0, state.ID, 0, 0, 0, 0);
                using (CancellationTokenSource frame = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token))
                {
                    frame.CancelAfter(frameTimeout);
                    await WriteExactAsync(stream, header, frame.Token).ConfigureAwait(false);
                }
            }
            finally { writer.Release(); }
        }

        private async Task ReadLoopAsync()
        {
            try
            {
                while (true)
                {
                    byte[] header = new byte[HeaderSize];
                    await ReadExactAsync(stream, header, 0, 1, lifetime.Token).ConfigureAwait(false);
                    using (CancellationTokenSource frame = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token))
                    {
                        frame.CancelAfter(frameTimeout);
                        await ReadExactAsync(stream, header, 1, HeaderSize - 1, frame.Token).ConfigureAwait(false);
                        if (header[0] != 'R' || header[1] != 'V' || header[2] != 'B' || header[3] != '1' ||
                            header[5] != 0 || U32(header, 16) != 0 || U16(header, 20) != 0 || U16(header, 22) != 0 || U32(header, 28) != 0)
                            throw ProtocolError();
                        byte kind = header[4];
                        ushort status = U16(header, 6);
                        ulong id = U64(header, 8);
                        uint length = U32(header, 24);
                        RequestState state;
                        lock (gate)
                        {
                            if (id == 0 || !pending.TryGetValue(id, out state) || state.Released) throw ProtocolError();
                            if (kind == 3)
                            {
                                if (status < 100 || status > 599 || length > state.ResponseLimit) throw ProtocolError();
                            }
                            else if (kind == 4)
                            {
                                if (status != 0 || length == 0 || length > 4096) throw ProtocolError();
                            }
                            else if (kind != 5 || status != 0 || length != 0) throw ProtocolError();
                        }
                        byte[] body = new byte[(int)length];
                        await ReadExactAsync(stream, body, 0, body.Length, frame.Token).ConfigureAwait(false);
                        verifyPeer();
                        if (kind == 3)
                        {
                            HttpResponseMessage response = new HttpResponseMessage((HttpStatusCode)status);
                            response.Content = new ByteArrayContent(body);
                            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                            response.Content.Headers.ContentType.CharSet = "utf-8";
                            if (!PublishResponse(state, response)) response.Dispose();
                        }
                        else if (kind == 4) state.Result.TrySetException(new HttpRequestException(UTF8.GetString(body)));
                        else state.Result.TrySetCanceled();
                        Release(state);
                    }
                }
            }
            catch (Exception error) { Retire(error); }
        }

        private bool PublishResponse(RequestState state, HttpResponseMessage response)
        {
            // Revocation and response publication share one linearization
            // point. A fully read old response cannot win after Close has
            // revoked admission but before its terminal errors are delivered.
            lock (gate)
            {
                return !closing && !state.Released && !state.Cancelled && !state.Cancellation.IsCancellationRequested &&
                    state.Result.TrySetResult(response);
            }
        }

        private void Release(RequestState state)
        {
            lock (gate)
            {
                if (state.Released) return;
                state.Released = true;
                if (state.ID != 0) pending.Remove(state.ID);
                if (requests.Remove(state)) reserved -= state.Reserved;
            }
            // Registration.Dispose may join a callback. Never join it while
            // holding the map lock that the callback itself acquires.
            state.Registration.Dispose();
            state.Cancellation.Dispose();
        }

        private async Task WatchPeerAsync()
        {
            try
            {
                while (true)
                {
                    await Task.Delay(100, lifetime.Token).ConfigureAwait(false);
                    verifyPeer();
                }
            }
            catch (Exception error) { Retire(error); }
        }

        private void Retire(Exception reason)
        {
            RequestState[] captured;
            lock (gate)
            {
                if (closing) return;
                closing = true;
                closeReason = reason ?? new ObjectDisposedException("ControllerChannel");
                captured = new RequestState[requests.Count];
                requests.CopyTo(captured);
                if (writes == 0) writesJoined.TrySetResult(true);
            }
            foreach (RequestState state in captured) state.Result.TrySetException(new IOException("The captured native UI channel closed.", closeReason));
            lifetime.Cancel();
            Task.Run((Func<Task>)FinishCloseAsync);
        }

        private async Task FinishCloseAsync()
        {
            Exception failure = null;
            try
            {
                await started.Task.ConfigureAwait(false);
                // The real pipe's Dispose cancels and joins entered native I/O
                // BEFORE releasing its handle. Reader/writer tasks then settle.
                try { stream.Dispose(); } catch (Exception error) { failure = error; }
                await readerTask.ConfigureAwait(false);
                await peerTask.ConfigureAwait(false);
                await writesJoined.Task.ConfigureAwait(false);
                RequestState[] captured;
                lock (gate) { captured = new RequestState[requests.Count]; requests.CopyTo(captured); }
                foreach (RequestState state in captured) Release(state);
                if (retainedPeer != null) retainedPeer.Dispose();
                writer.Dispose();
                lifetime.Dispose();
            }
            catch (Exception error) { failure = error; }
            if (failure == null) closed.TrySetResult(true); else closed.TrySetException(failure);
        }

        public Task CloseAsync()
        {
            Retire(new ObjectDisposedException("ControllerChannel"));
            return closed.Task;
        }
        public void Dispose() { CloseAsync().GetAwaiter().GetResult(); }
        private void ThrowIfClosed() { if (closing) throw new ObjectDisposedException("ControllerChannel"); }
        internal static Exception ProtocolError() { return new IOException("The captured native UI channel received an invalid frame."); }

        internal static void Header(byte[] buffer, byte kind, byte method, ushort status, ulong id, uint timeout, ushort path, uint body, uint limit)
        {
            buffer[0] = (byte)'R'; buffer[1] = (byte)'V'; buffer[2] = (byte)'B'; buffer[3] = (byte)'1';
            buffer[4] = kind; buffer[5] = method;
            Put(buffer, 6, status, 2); Put(buffer, 8, id, 8); Put(buffer, 16, timeout, 4); Put(buffer, 20, path, 2);
            buffer[22] = 0; buffer[23] = 0; Put(buffer, 24, body, 4); Put(buffer, 28, limit, 4);
        }
        private static void Put(byte[] target, int offset, ulong value, int count)
        { for (int i = count - 1; i >= 0; i--) { target[offset + i] = (byte)value; value >>= 8; } }
        internal static ushort U16(byte[] source, int offset) { return (ushort)((source[offset] << 8) | source[offset + 1]); }
        internal static uint U32(byte[] source, int offset) { return ((uint)source[offset] << 24) | ((uint)source[offset + 1] << 16) | ((uint)source[offset + 2] << 8) | source[offset + 3]; }
        internal static ulong U64(byte[] source, int offset) { return ((ulong)U32(source, offset) << 32) | U32(source, offset + 4); }
        internal static async Task ReadExactAsync(Stream source, byte[] buffer, int offset, int count, CancellationToken token)
        {
            while (count > 0)
            {
                token.ThrowIfCancellationRequested();
                int requested = Math.Min(count, 4096);
                int read = await source.ReadAsync(buffer, offset, requested, token).ConfigureAwait(false);
                if (read <= 0 || read > requested) throw new EndOfStreamException("The captured native UI frame is incomplete.");
                offset += read; count -= read;
            }
            token.ThrowIfCancellationRequested();
        }
        internal static async Task WriteExactAsync(Stream target, byte[] buffer, CancellationToken token)
        {
            for (int offset = 0; offset < buffer.Length;)
            {
                token.ThrowIfCancellationRequested();
                int count = Math.Min(buffer.Length - offset, 4096);
                await target.WriteAsync(buffer, offset, count, token).ConfigureAwait(false);
                offset += count;
            }
            token.ThrowIfCancellationRequested();
        }

        private sealed class ParentOwner : IDisposable
        {
            private readonly SafeWaitHandle handle;
            private readonly uint pid;
            private readonly Identity identity;
            internal ParentOwner(IntPtr inherited)
            {
                handle = new SafeWaitHandle(inherited, true);
                try
                {
                    // PUBLIC_OBJECT_BASIC_INFORMATION is the documented
                    // user-mode readback; do not test excess rights by using
                    // terminate, VM or duplicate-handle operations.
                    // https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntqueryobject
                    IntPtr basic = Marshal.AllocHGlobal(56);
                    try
                    {
                        uint returned;
                        int status = Native.NtQueryObject(handle, 0, basic, 56, out returned);
                        if (status != 0 || returned != 56 || unchecked((uint)Marshal.ReadInt32(basic, 4)) != 0x00101000)
                            throw new IOException("The native UI parent handle has unexpected access rights.");
                    }
                    finally { Marshal.FreeHGlobal(basic); }
                    if (!Native.SetHandleInformation(handle, 1, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    pid = Native.GetProcessId(handle);
                    if (pid == 0 || pid == Native.GetCurrentProcessId()) throw ProtocolError();
                    identity = ReadIdentity(Native.GetCurrentProcess());
                    VerifyProcess();
                }
                catch { handle.Dispose(); throw; }
            }
            private void VerifyProcess()
            {
                if (handle.IsClosed || handle.IsInvalid || Native.WaitForSingleObject(handle, 0) != 258 || Native.GetProcessId(handle) != pid)
                    throw new IOException("The captured native UI parent is no longer alive.");
                bool retained = false;
                try
                {
                    handle.DangerousAddRef(ref retained);
                    Identity current = ReadIdentity(handle.DangerousGetHandle());
                    if (current.SID != identity.SID || current.Logon != identity.Logon || current.Session != identity.Session || current.Elevated != identity.Elevated)
                        throw new IOException("The captured native UI parent identity changed.");
                }
                finally { if (retained) handle.DangerousRelease(); }
            }
            internal void VerifyPipe(SafePipeHandle pipe)
            {
                VerifyProcess();
                uint server;
                if (!Native.GetNamedPipeServerProcessId(pipe, out server) || server != pid)
                    throw new IOException("The native UI pipe belongs to another process.");
                VerifyProcess();
            }
            public void Dispose() { handle.Dispose(); }
        }

        private sealed class Identity
        {
            internal string SID;
            internal ulong Logon;
            internal uint Session;
            internal bool Elevated;
        }
        private static Identity ReadIdentity(IntPtr process)
        {
            IntPtr token;
            if (!Native.OpenProcessToken(process, 8, out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                byte[] statistics = TokenInformation(token, 10, 56);
                if (BitConverter.ToUInt32(statistics, 24) != 1) throw ProtocolError();
                byte[] session = TokenInformation(token, 12, 4), elevated = TokenInformation(token, 20, 4);
                uint elevation = BitConverter.ToUInt32(elevated, 0);
                if (elevation > 1) throw ProtocolError();
                uint required;
                Native.GetTokenInformation(token, 1, IntPtr.Zero, 0, out required);
                if (Marshal.GetLastWin32Error() != 122 || required < IntPtr.Size || required > 65536) throw ProtocolError();
                IntPtr user = Marshal.AllocHGlobal((int)required);
                try
                {
                    uint returned;
                    if (!Native.GetTokenInformation(token, 1, user, required, out returned) || returned != required) throw ProtocolError();
                    return new Identity { SID = new SecurityIdentifier(Marshal.ReadIntPtr(user)).Value,
                        Logon = BitConverter.ToUInt64(statistics, 8), Session = BitConverter.ToUInt32(session, 0), Elevated = elevation == 1 };
                }
                finally { Marshal.FreeHGlobal(user); }
            }
            finally { Native.CloseHandle(token); }
        }
        private static byte[] TokenInformation(IntPtr token, int field, int size)
        {
            IntPtr data = Marshal.AllocHGlobal(size);
            try
            {
                uint returned;
                if (!Native.GetTokenInformation(token, field, data, (uint)size, out returned) || returned != size) throw ProtocolError();
                byte[] result = new byte[size]; Marshal.Copy(data, result, 0, size); return result;
            }
            finally { Marshal.FreeHGlobal(data); }
        }

        // Framework PipeStream cancellation varies across runtimes. Perform
        // actual OVERLAPPED I/O so cancellation always joins the exact kernel
        // request before its pinned buffer, event or pipe handle is released.
        private sealed class OwnedPipeStream : Stream
        {
            private readonly NamedPipeClientStream pipe;
            private readonly object operationGate = new object();
            private readonly object closeGate = new object();
            private readonly CancellationTokenSource retired = new CancellationTokenSource();
            private readonly ManualResetEventSlim drained = new ManualResetEventSlim(true);
            private int operations;
            private bool closing, disposed;
            internal SafePipeHandle PipeHandle { get { return pipe.SafePipeHandle; } }
            internal OwnedPipeStream(NamedPipeClientStream value) { pipe = value; }
            public override bool CanRead { get { return true; } }
            public override bool CanWrite { get { return true; } }
            public override bool CanSeek { get { return false; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
            public override int Read(byte[] buffer, int offset, int count) { return ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult(); }
            public override void Write(byte[] buffer, int offset, int count) { WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult(); }
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token)
            { return StartOperation(buffer, offset, count, false, token); }
            public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token)
            {
                int written = await StartOperation(buffer, offset, count, true, token).ConfigureAwait(false);
                if (written != count) throw new IOException("The captured native UI write was incomplete.");
            }
            private Task<int> StartOperation(byte[] buffer, int offset, int count, bool write, CancellationToken token,
                Func<Func<int>, Task<int>> dispatch = null)
            {
                if (buffer == null || offset < 0 || count < 0 || offset > buffer.Length - count) throw new ArgumentException();
                if (count == 0) return Task.FromResult(0);
                lock (operationGate)
                {
                    if (closing) throw new ObjectDisposedException("OwnedPipeStream");
                    operations++; drained.Reset();
                }
                try
                {
                    Func<int> operation = delegate
                    {
                        try
                        {
                            using (CancellationTokenSource owned = CancellationTokenSource.CreateLinkedTokenSource(token, retired.Token))
                                return Operation(buffer, offset, count, write, owned.Token);
                        }
                        finally { FinishOperation(); }
                    };
                    // The private executable test can reject dispatch before
                    // any native operation enters. Normal Stream callers
                    // always use the actual default Task scheduler.
                    return dispatch == null ? Task.Run(operation) : dispatch(operation);
                }
                catch
                {
                    // Synchronous scheduling failure installed no delegate
                    // finally and submitted no IRP. Retire its admitted count.
                    FinishOperation();
                    throw;
                }
            }
            private void FinishOperation()
            { lock (operationGate) { operations--; if (operations == 0) drained.Set(); } }
            private int Operation(byte[] buffer, int offset, int count, bool write, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                bool retained = false;
                GCHandle pinned = default(GCHandle);
                IntPtr native = IntPtr.Zero;
                SafeWaitHandle completion = null;
                try
                {
                    pipe.SafePipeHandle.DangerousAddRef(ref retained);
                    pinned = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                    completion = Native.CreateEvent(IntPtr.Zero, true, false, null);
                    if (completion.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                    // PipeStream has already bound this handle to the CLR's
                    // IOCP. Suppress completion-port packets for our own
                    // unmanaged OVERLAPPED, retaining the untagged event owner.
                    // https://learn.microsoft.com/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus
                    Native.Overlapped operation = new Native.Overlapped {
                        Event = new IntPtr(completion.DangerousGetHandle().ToInt64() | 1L) };
                    native = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Native.Overlapped)));
                    Marshal.StructureToPtr(operation, native, false);
                    IntPtr bytes = new IntPtr(pinned.AddrOfPinnedObject().ToInt64() + offset);
                    IntPtr captured = native;
                    // Allocate/register all managed cancellation state before
                    // submitting an IRP. If registration itself fails, there is
                    // no pending native operation whose buffer could escape.
                    using (CancellationTokenRegistration cancel = token.Register(delegate { Native.CancelIoEx(pipe.SafePipeHandle, captured); }))
                    {
                        token.ThrowIfCancellationRequested();
                        uint transferred;
                        bool submitted = false, completed = false;
                        try
                        {
                            bool immediate = write ? Native.WriteFile(pipe.SafePipeHandle, bytes, (uint)count, out transferred, native) :
                                Native.ReadFile(pipe.SafePipeHandle, bytes, (uint)count, out transferred, native);
                            int startError = immediate ? 0 : Marshal.GetLastWin32Error();
                            submitted = immediate || startError == 997;
                            if (!submitted)
                            {
                                if (!write && (startError == 109 || startError == 232)) return 0;
                                throw new Win32Exception(startError);
                            }
                            // Cancellation may have run just before submission
                            // and found no IRP. Revoke that newly entered exact
                            // operation as well, then join its completion.
                            if (token.IsCancellationRequested) Native.CancelIoEx(pipe.SafePipeHandle, native);
                            bool joined = Native.GetOverlappedResult(pipe.SafePipeHandle, native, out transferred, true);
                            int resultError = joined ? 0 : Marshal.GetLastWin32Error();
                            completed = true;
                            token.ThrowIfCancellationRequested();
                            if (!joined)
                            {
                                if (!write && (resultError == 109 || resultError == 232)) return 0;
                                throw new Win32Exception(resultError);
                            }
                            if (transferred > count) throw ProtocolError();
                            return (int)transferred;
                        }
                        finally
                        {
                            if (submitted && !completed)
                            {
                                Native.CancelIoEx(pipe.SafePipeHandle, native);
                                Native.GetOverlappedResult(pipe.SafePipeHandle, native, out transferred, true);
                            }
                        }
                    }
                }
                finally
                {
                    if (native != IntPtr.Zero) Marshal.FreeHGlobal(native);
                    if (completion != null) completion.Dispose();
                    if (pinned.IsAllocated) pinned.Free();
                    if (retained) pipe.SafePipeHandle.DangerousRelease();
                }
            }
            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    lock (closeGate)
                    {
                        lock (operationGate) { if (disposed) return; closing = true; }
                        retired.Cancel();
                        drained.Wait();
                        lock (operationGate) { pipe.Dispose(); disposed = true; }
                        retired.Dispose();
                        drained.Dispose();
                    }
                }
                base.Dispose(disposing);
            }
        }

        private static class Native
        {
            [StructLayout(LayoutKind.Sequential)] internal struct Overlapped
            { internal IntPtr Internal, InternalHigh; internal uint Offset, OffsetHigh; internal IntPtr Event; }
            [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetHandleInformation(SafeWaitHandle handle, uint mask, uint flags);
            [DllImport("ntdll.dll")] internal static extern int NtQueryObject(SafeWaitHandle handle, int informationClass, IntPtr information, uint length, out uint returned);
            [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint GetProcessId(SafeWaitHandle process);
            [DllImport("kernel32.dll")] internal static extern uint GetCurrentProcessId();
            [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
            [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(SafeWaitHandle handle, uint timeout);
            [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
            [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool OpenProcessToken(IntPtr process, uint desired, out IntPtr token);
            [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetTokenInformation(IntPtr token, int field, IntPtr data, uint length, out uint returned);
            [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CloseHandle(IntPtr handle);
            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateEventW")]
            internal static extern SafeWaitHandle CreateEvent(IntPtr attributes, bool manual, bool initial, string name);
            [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool ReadFile(SafePipeHandle handle, IntPtr buffer, uint count, out uint read, IntPtr overlapped);
            [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool WriteFile(SafePipeHandle handle, IntPtr buffer, uint count, out uint written, IntPtr overlapped);
            [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CancelIoEx(SafePipeHandle handle, IntPtr overlapped);
            [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetOverlappedResult(SafePipeHandle handle, IntPtr overlapped, out uint count, bool wait);
        }
    }
}
