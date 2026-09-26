"""Exact pinned HTTP publication and FinalMask half-close corrections.

No authentication, wire data, masks, race detector or pointer checks are disabled.
"""
from pathlib import Path
PATCHES = {'transport/internet/splithttp/client.go': [('\t"sync"', '\t"sync"\n\t"sync/atomic"'), ('\tclosed          bool', '\tclosed          atomic.Bool'), ('return c.closed', 'return c.closed.Load()'), ('c.closed = true', 'c.closed.Store(true)'), ('type WaitReadCloser struct {\n\tWait chan struct{}\n\tio.ReadCloser\n}\n\nfunc (w *WaitReadCloser) Set(rc io.ReadCloser) {\n\tw.ReadCloser = rc\n\tdefer func() {\n\t\tif recover() != nil {\n\t\t\trc.Close()\n\t\t}\n\t}()\n\tclose(w.Wait)\n}\n\nfunc (w *WaitReadCloser) Read(b []byte) (int, error) {\n\tif w.ReadCloser == nil {\n\t\tif <-w.Wait; w.ReadCloser == nil {\n\t\t\treturn 0, io.ErrClosedPipe\n\t\t}\n\t}\n\treturn w.ReadCloser.Read(b)\n}\n\nfunc (w *WaitReadCloser) Close() error {\n\tif w.ReadCloser != nil {\n\t\treturn w.ReadCloser.Close()\n\t}\n\tdefer func() {\n\t\tif recover() != nil && w.ReadCloser != nil {\n\t\t\tw.ReadCloser.Close()\n\t\t}\n\t}()\n\tclose(w.Wait)\n\treturn nil\n}', 'type WaitReadCloser struct {\n\tWait chan struct{}\n\tmu sync.Mutex\n\treader io.ReadCloser\n\tpublished bool\n\tclosed bool\n\tcloseDone chan struct{}\n\tcloseErr error\n}\n\nfunc (w *WaitReadCloser) publishLocked() {\n\tif !w.published {\n\t\tw.published = true\n\t\tclose(w.Wait)\n\t}\n}\n\nfunc (w *WaitReadCloser) Set(rc io.ReadCloser) {\n\tif rc == nil { _ = w.Close(); return }\n\tw.mu.Lock()\n\tif w.closed || w.published {\n\t\tw.mu.Unlock()\n\t\t_ = rc.Close()\n\t\treturn\n\t}\n\tw.reader = rc\n\tw.publishLocked()\n\tw.mu.Unlock()\n}\n\nfunc (w *WaitReadCloser) Read(b []byte) (int, error) {\n\t<-w.Wait\n\tw.mu.Lock()\n\trc, closed := w.reader, w.closed\n\tw.mu.Unlock()\n\tif closed || rc == nil { return 0, io.ErrClosedPipe }\n\treturn rc.Read(b)\n}\n\nfunc (w *WaitReadCloser) Close() error {\n\tw.mu.Lock()\n\tif w.closed {\n\t\tdone := w.closeDone\n\t\tw.mu.Unlock()\n\t\t<-done\n\t\treturn w.closeErr\n\t}\n\tw.closed = true\n\tw.closeDone = make(chan struct{})\n\tw.publishLocked()\n\trc := w.reader\n\tw.mu.Unlock()\n\tvar err error\n\tif rc != nil { err = rc.Close() }\n\tw.mu.Lock()\n\tw.closeErr = err\n\tclose(w.closeDone)\n\tw.mu.Unlock()\n\treturn err\n}')], 'transport/internet/finalmask/fragment/conn.go': [('\t"net"', '\t"net"\n\t"io"\n\t"sync"'), ('\tcount  uint64', '\tcount  uint64\n\twriteMu sync.Mutex'), ('func (c *fragmentConn) Write(p []byte) (n int, err error) {\n\tc.count++', "// Preserve TCP half-close through FinalMask: REALITY's listener requires it.\n// Do not unwrap the stream or bypass any configured camouflage writes.\nfunc (c *fragmentConn) CloseWrite() error {\n\tc.writeMu.Lock()\n\tdefer c.writeMu.Unlock()\n\tif conn, ok := c.Conn.(interface { CloseWrite() error }); ok {\n\t\treturn conn.CloseWrite()\n\t}\n\treturn io.ErrClosedPipe\n}\n\nfunc (c *fragmentConn) Write(p []byte) (n int, err error) {\n\tc.writeMu.Lock()\n\tdefer c.writeMu.Unlock()\n\tc.count++")]}

def patch_text(path, text):
    expected={'c.closed = true':3}
    for old,new in PATCHES[path]:
        count=expected.get(old,1)
        if old in text:
            # A replacement containing its old anchor is already applied only
            # when the entire new snippet exists the expected number of times.
            if new in text and text.count(new)==count:
                continue
            if text.count(old)!=count:
                raise ValueError('Pinned native connection boundary changed: '+path)
            text=text.replace(old,new)
        elif text.count(new)!=count:
            raise ValueError('Native connection correction differs: '+path)
    return text

def prepare(root):
    candidates={root/p:patch_text(p,(root/p).read_text()) for p in PATCHES}
    for path,text in candidates.items():path.write_text(text)
