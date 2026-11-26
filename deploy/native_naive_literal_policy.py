"""Retain captured Naive address/name and stream authority in one verified copy.

The native library and explicit DNS resolver remain unchanged. Derive the
wire hostname without an RFC 6066-forbidden terminal dot, preserving the caller's
original options. Map only its exact hostname to its original IPv6 literal.
Never edit the shared Go cache or accept an unrelated local module replacement.
"""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MODULE = 'github.com/sagernet/cronet-go'
VERSION = 'v0.0.0-20260912104727-0d28acc44093'
SUM = 'h1:CsvsLVIli53L6nzgEpyRjjWnRRhTds4D3eh5sEnF5Sw='
COPY = 'routervpn-patched-cronet'
PREFIX = MODULE+'@'+VERSION+'/'
SOURCE = 'naive_client.go'
SOURCE_SHA256 = '367a29cbc783270e07f00d28d77f6b463033805bf4e100b53100f9373bf0f5a5'
STREAM_SOURCE = 'bidirectional_stream_purego.go'
STREAM_SHA256 = '99165454412c611241c118b5305cf40d846025f570c78e574e7702c68e34bfdf'
OLD = b'\tparamsError := params.SetAsyncDNS(true)\n'
NEW = (b'\trules, paramsError := routerVPNNaiveLiteralRule(c.serverAddress, c.serverName, c.quicEnabled)\n'
       b'\tif paramsError == nil && rules != "" {\n'
       b'\t\tparamsError = params.SetHostResolverRules(rules)\n\t}\n'
       b'\tif paramsError == nil {\n\t\tparamsError = params.SetAsyncDNS(true)\n\t}\n')
NAME_OLD = b'\tserverURL := &url.URL{\n'
NAME_NEW = (b'\tserverName, err = routerVPNNaiveWireName(serverName, config.QUIC)\n'
            b'\tif err != nil {\n\t\treturn nil, err\n\t}\n\n' + NAME_OLD)
DIAL_OLD = b'func (c *NaiveClient) DialEarly(ctx context.Context, destination M.Socksaddr) (NaiveConn, error) {\n'
DIAL_NEW = DIAL_OLD + (b'\tif err := errors.Join(ctx.Err(), c.ctx.Err()); err != nil {\n'
                       b'\t\treturn nil, err\n\t}\n')
ACCESS_OLD = b'\tactiveConnections        sync.WaitGroup\n'
ACCESS_NEW = (b'\tstreamAccess             sync.Mutex\n'
              b'\tstreamContext            context.Context\n'
              b'\tcloseAttempt             *routerVPNCloseAttempt\n'
              b'\tengineSweeps             sync.WaitGroup\n'
              b'\tretiredEngines           int\n'
              b'\tfailedStartEngine        Engine\n' + ACCESS_OLD)
RESERVE_OLD = b'\theaders := map[string]string{\n'
RESERVE_NEW = (b'\tc.streamAccess.Lock()\n'
               b'\tif clientState(c.state.Load()) != clientStateRunning {\n'
               b'\t\tc.streamAccess.Unlock()\n\t\treturn nil, net.ErrClosed\n\t}\n'
               b'\tc.activeConnections.Add(1)\n\tc.streamAccess.Unlock()\n'
               b'\treserved := true\n\tdefer func() {\n\t\tif reserved {\n'
               b'\t\t\tc.activeConnections.Done()\n\t\t}\n\t}()\n\n' + RESERVE_OLD)
COUNT_OLD = b'\tc.activeConnections.Add(1)\n'
COUNT_NEW = b'\treserved = false\n'
OWNER_OLD = b'\tconn.setOnTerminate(trackedConn.release)\n\treturn trackedConn, nil\n'
OWNER_NEW = (b'\ttrackedConn.stopOwner = routerVPNNaiveStreamOwner(c.streamContext, conn.Close)\n'
             b'\tconn.setOnTerminate(func() {\n\t\ttrackedConn.stopOwner()\n\t\ttrackedConn.release()\n\t})\n'
             b'\treturn c.routerVPNPublish(ctx, trackedConn)\n')
TRACKED_OLD = b'\tclient    *NaiveClient\n\tcloseOnce sync.Once\n'
TRACKED_NEW = TRACKED_OLD + b'\tstopOwner func()\n'
CLOSE_OLD = b'func (c *trackedNaiveConn) Close() error {\n\tc.release()\n'
CLOSE_NEW = (b'func (c *trackedNaiveConn) Close() error {\n\tc.stopOwner()\n'
             b'\t// Close requests cancellation. The terminal callback releases the\n'
             b'\t// client reservation after posting stream destruction.\n')
RETIRE_OLD = b'''		case clientStateRunning:
			if !c.state.CompareAndSwap(uint32(clientStateRunning), uint32(clientStateClosing)) {
				continue
			}
			return c.doClose()

		case clientStateClosing:
			return nil

'''
RETIRE_NEW = b'''		case clientStateRunning, clientStateClosing:
			return c.routerVPNClose()

'''
DRAIN_OLD = b'''func (c *NaiveClient) doClose() error {
	if c.proxyCancel != nil {
		c.proxyCancel()
	}

	for _, engine := range c.engines {
		engine.CloseAllConnections()
	}
	c.proxyWaitGroup.Wait()
	c.activeConnections.Wait()
	for _, engine := range c.engines {
		engine.Shutdown()
		engine.Destroy()
	}

	c.state.Store(uint32(clientStateClosed))
	return nil
}

'''
DRAIN_NEW = b'''// doClose is implemented in routervpn_naive_client_lifecycle.go.

'''
SWEEP_OLD = b'''func (c *NaiveClient) CloseAllConnections() {
	if clientState(c.state.Load()) != clientStateRunning {
		return
	}
	for _, engine := range c.engines {
		engine.CloseAllConnections()
	}
}

'''
SWEEP_NEW = b'''func (c *NaiveClient) CloseAllConnections() {
	c.streamAccess.Lock()
	if clientState(c.state.Load()) != clientStateRunning {
		c.streamAccess.Unlock()
		return
	}
	c.engineSweeps.Add(1)
	c.streamAccess.Unlock()
	defer c.engineSweeps.Done()
	for _, engine := range c.engines {
		engine.CloseAllConnections()
	}
}

'''
START_OLD = b'''func (c *NaiveClient) Start() error {
'''
START_NEW = b'''func (c *NaiveClient) Start() (resultErr error) {
'''
ROLLBACK_OLD = b'''		if startError != nil {
			if c.proxyCancel != nil {
				c.proxyCancel()
			}
			for _, engine := range engines {
				engine.Shutdown()
				engine.Destroy()
			}
			c.state.Store(uint32(clientStateClosed))
			close(c.started)
		}
'''
ROLLBACK_NEW = b'''		if startError != nil {
			c.engines = engines
			resultErr = errors.Join(startError, c.routerVPNClose())
			close(c.started)
		}
'''
FAILED_HANDLE_OLD = b'''		if startError != nil {
			return startError
'''
FAILED_HANDLE_NEW = b'''		if startError != nil {
			c.failedStartEngine = engine
			return startError
'''
UNSTARTED_OLD = b'''	destroyEngine := func() {
		engine.Shutdown()
		engine.Destroy()
	}
'''
UNSTARTED_NEW = b'''	destroyEngine := engine.Destroy
'''
ATTEMPTED_OLD = b'''		destroyEngine()
		return Engine{}, E.New("failed to start engine: ", int(result))
'''
ATTEMPTED_NEW = b'''		return engine, E.New("failed to start engine: ", int(result))
'''
CHECK_RESULT_OLD = b'''	params := NewEngineParams()
'''
CHECK_RESULT_NEW = b'''	params := NewEngineParams()
	params.SetEnableCheckResult(false) // Inspect startup and shutdown results at the ownership boundary.
'''
TCP_OLD = b'''	tcpDialer := Dialer(func(address string, port uint16) int {
'''
TCP_NEW = b'''	tcpDialer := Dialer(func(address string, port uint16) int {
		if !c.routerVPNBeginProxy() {
			return NetErrorConnectionFailed.Code()
		}
		defer c.proxyWaitGroup.Done()
'''
UDP_OLD = b'''	udpDialer := UDPDialer(func(address string, port uint16) (fd int, localAddress string, localPort uint16, onClose func()) {
'''
UDP_NEW = b'''	udpDialer := UDPDialer(func(address string, port uint16) (fd int, localAddress string, localPort uint16, onClose func()) {
		if !c.routerVPNBeginProxy() {
			return NetErrorConnectionFailed.Code(), "", 0, nil
		}
		defer c.proxyWaitGroup.Done()
'''
DNS_TCP_OLD = b'''			go func() {
				_ = serveDNSStreamConn'''
DNS_TCP_NEW = b'''			c.proxyWaitGroup.Add(1)
			go func() {
				defer c.proxyWaitGroup.Done()
				_ = serveDNSStreamConn'''
DNS_UDP_OLD = b'''			go func() {
				defer dnsCancel()'''
DNS_UDP_NEW = b'''			c.proxyWaitGroup.Add(1)
			go func() {
				defer c.proxyWaitGroup.Done()
				defer dnsCancel()'''
DIAL_CANCEL_OLD = b'''		case <-c.ctx.Done():
			return nil, c.ctx.Err()
'''
DIAL_CANCEL_NEW = b'''		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.ctx.Done():
			return nil, c.ctx.Err()
'''
STREAM_CONTEXT_OLD = b'\tc.proxyCancel = proxyCancel\n'
STREAM_CONTEXT_NEW = b'\tc.streamContext = proxyContext\n' + STREAM_CONTEXT_OLD
PATCHES = ((NAME_OLD, NAME_NEW), (OLD, NEW), (DIAL_OLD, DIAL_NEW),
           (ACCESS_OLD, ACCESS_NEW), (COUNT_OLD, COUNT_NEW),
           (RESERVE_OLD, RESERVE_NEW), (OWNER_OLD, OWNER_NEW),
           (TRACKED_OLD, TRACKED_NEW), (CLOSE_OLD, CLOSE_NEW),
           (RETIRE_OLD, RETIRE_NEW),
           (DRAIN_OLD, DRAIN_NEW),
           (SWEEP_OLD, SWEEP_NEW),
           (START_OLD, START_NEW),
           (ROLLBACK_OLD, ROLLBACK_NEW),
           (FAILED_HANDLE_OLD, FAILED_HANDLE_NEW),
           (UNSTARTED_OLD, UNSTARTED_NEW),
           (ATTEMPTED_OLD, ATTEMPTED_NEW),
           (CHECK_RESULT_OLD, CHECK_RESULT_NEW),
           (TCP_OLD, TCP_NEW),
           (UDP_OLD, UDP_NEW),
           (DNS_TCP_OLD, DNS_TCP_NEW),
           (DNS_UDP_OLD, DNS_UDP_NEW),
           (DIAL_CANCEL_OLD, DIAL_CANCEL_NEW),
           (STREAM_CONTEXT_OLD, STREAM_CONTEXT_NEW))
STREAM_PATCHES = (
    (b'\tvar headerArrayPtr uintptr\n\tvar cStringBacking [][]byte // Keep C string backing slices alive\n\n\theaderLen := len(headers)\n',
     b'\theaderLen := len(headers)\n'),
    (b'\t\t// Allocate header structs\n',
     b'''		// Purego passes integer addresses through reflection. Pin all backing
		// storage before taking its address; a goroutine stack can move here.
		var pins runtime.Pinner
		defer pins.Unpin()
		pinnedCString := func(s string) uintptr {
			data := make([]byte, len(s)+1)
			copy(data, s)
			pins.Pin(&data[0])
			return uintptr(unsafe.Pointer(&data[0]))
		}
'''),
    (b'\t\theaderStructs := make([]bidirectionalStreamHeader, headerLen)\n',
     b'\t\theaderStructs := make([]bidirectionalStreamHeader, headerLen)\n\t\tpins.Pin(&headerStructs[0])\n'),
    (b'''			keyPtr, keyBacking := cronet.CString(key)
			valuePtr, valueBacking := cronet.CString(value)
			cStringBacking = append(cStringBacking, keyBacking, valueBacking)
			headerStructs[index].key = keyPtr
			headerStructs[index].value = valuePtr
''',
     b'''			headerStructs[index].key = pinnedCString(key)
			headerStructs[index].value = pinnedCString(value)
'''),
    (b'''		headerArrayPtr = uintptr(unsafe.Pointer(&headerArray))

		result := cronet.BidirectionalStreamStart(c.ptr, url, int32(priority), method, headerArrayPtr, endOfStream) == 0

		// Keep all backing slices alive until after the call
		runtime.KeepAlive(cStringBacking)
		runtime.KeepAlive(headerStructs)
		runtime.KeepAlive(headerArray)

		return result
''',
     b'''		pins.Pin(&headerArray)
		return cronet.BidirectionalStreamStart(c.ptr, url, int32(priority), method, uintptr(unsafe.Pointer(&headerArray)), endOfStream) == 0
'''),
)
TEMPLATES = {'cronet_literal.go.tmpl': 'routervpn_naive_literal.go', 'cronet_stream_owner.go.tmpl': 'routervpn_naive_stream_owner.go', 'cronet_client_lifecycle.go.tmpl': 'routervpn_naive_client_lifecycle.go'}
MAX_BYTES = 32*1024*1024


def inputs():
    return [Path(__file__).resolve(), *(ROOT / 'mobile/naive' / name for name in TEMPLATES)]


def transform(relative, raw, *, reverse=False):
    if relative == SOURCE:
        digest, patches = SOURCE_SHA256, PATCHES
    elif relative == STREAM_SOURCE:
        digest, patches = STREAM_SHA256, STREAM_PATCHES
    else:
        return raw
    original = raw
    if reverse:
        for old, new in reversed(patches):
            if original.count(new) != 1:
                raise ValueError('Native Cronet literal policy is absent or partial')
            original = original.replace(new, old, 1)
    if hashlib.sha256(original).hexdigest() != digest or any(original.count(old) != 1 for old, _ in patches):
        raise ValueError('Pinned Cronet engine startup differs')
    if reverse:
        return original
    for old, new in patches:
        original = original.replace(old, new, 1)
    return original


def h1(rows):
    raw = ''.join(digest+'  '+name+'\n' for name, digest in sorted(rows)).encode()
    return 'h1:'+base64.b64encode(hashlib.sha256(raw).digest()).decode()


def helpers():
    result = {}
    for name, relative in TEMPLATES.items():
        path = ROOT/'mobile/naive'/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Native Cronet literal helper lost its source authority')
        result[relative] = path.read_bytes()
    return result


def verify_tree(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Prepared Cronet must be an owned directory')
    generated = helpers()
    rows, records, total = [], {}, 0
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or not path.is_dir() and not path.is_file():
            raise ValueError('Prepared Cronet contains a linked or special entry')
        if path.is_dir():
            continue
        info = path.stat()
        if info.st_nlink != 1:
            raise ValueError('Prepared Cronet contains a shared source owner')
        name = path.relative_to(directory).as_posix()
        if '\n' in name or '\r' in name:
            raise ValueError('Invalid prepared Cronet path')
        total += info.st_size
        if total > MAX_BYTES or len(records) >= 5000:
            raise ValueError('Prepared Cronet exceeds source bounds')
        raw = path.read_bytes()
        if name in generated:
            if raw != generated[name]:
                raise ValueError('Prepared Cronet literal helper differs from its exact source')
        else:
            original = transform(name, raw, reverse=True)
            rows.append((PREFIX+name, hashlib.sha256(original).hexdigest()))
        records[name] = hashlib.sha256(raw).hexdigest()
    if not set(generated) <= records.keys() or SOURCE not in records or h1(rows) != SUM:
        raise ValueError('Prepared Cronet differs from its pinned whole-module checksum')
    return records


def extract_verified(archive, destination):
    rows, total, seen, files = [], 0, set(), {}
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if not entries or len(entries) > 5000:
            raise ValueError('Invalid Cronet archive size')
        for entry in entries:
            name = entry.filename
            if not name.startswith(PREFIX):
                raise ValueError('Cronet archive has a foreign module prefix')
            relative = name[len(PREFIX):]
            parts = PurePosixPath(relative)
            if (not relative or str(parts) != relative or '\\' in relative or '\n' in relative or '\r' in relative
                    or '..' in parts.parts or parts.is_absolute() or entry.is_dir()
                    or stat.S_ISLNK(entry.external_attr >> 16) or relative in seen or relative in TEMPLATES.values()):
                raise ValueError('Unsafe or duplicate Cronet archive member')
            seen.add(relative)
            total += entry.file_size
            if total > MAX_BYTES or entry.file_size > MAX_BYTES:
                raise ValueError('Cronet archive exceeds source bounds')
            raw = source.read(entry)
            rows.append((name, hashlib.sha256(raw).hexdigest()))
            files[relative] = transform(relative, raw)
    if SOURCE not in files or h1(rows) != SUM:
        raise ValueError('Downloaded Cronet does not match the pinned h1 checksum')
    files.update(helpers())
    # Validate the complete archive and transform before publishing any source.
    for name, raw in files.items():
        path = destination/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    verify_tree(destination)


def module_plan(vendor, *, required=False):
    plan = json.loads(subprocess.check_output(['go', 'mod', 'edit', '-json'], cwd=vendor, text=True))
    dependencies = [row for row in plan.get('Require', []) if row['Path'] == MODULE]
    if len(dependencies) != 1 or dependencies[0]['Version'] != VERSION:
        raise ValueError('Naive IPv6 policy requires the exact pinned Cronet version')
    replacements = [row for row in plan.get('Replace', []) or [] if row['Old']['Path'] == MODULE]
    expected = [{'Old': {'Path': MODULE, 'Version': VERSION}, 'New': {'Path': './'+COPY}}]
    if replacements and replacements != expected or required and replacements != expected:
        raise ValueError('Naive IPv6 policy refuses a missing or unrelated Cronet replacement')


def checked_vendor(vendor):
    vendor = Path(vendor).absolute()
    if vendor.is_symlink() or not vendor.is_dir():
        raise ValueError('Unsafe native Cronet checkout')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('Naive IPv6 policy requires the exact pinned native core')
    for name in ('go.mod', 'go.sum'):
        path = vendor/name
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError('Native Cronet dependency record is not owned')
    if not (vendor/'go.mod').read_bytes().startswith(b'module github.com/sagernet/sing-box\n'):
        raise ValueError('Native Cronet policy requires the original core module')
    return vendor


def prepare(vendor):
    vendor = checked_vendor(vendor)
    module_plan(vendor)
    target = vendor/COPY
    if target.exists() or target.is_symlink():
        verify_tree(target)
    else:
        info = json.loads(subprocess.check_output(['go', 'mod', 'download', '-json', MODULE+'@'+VERSION], cwd=vendor, text=True))
        if info.get('Path') != MODULE or info.get('Version') != VERSION or info.get('Sum') != SUM or info.get('Error'):
            raise ValueError('Cronet download metadata differs from the pinned module')
        with tempfile.TemporaryDirectory(prefix='.routervpn-cronet-', dir=vendor) as temporary:
            staged = Path(temporary)/'module'
            staged.mkdir()
            extract_verified(Path(info['Zip']), staged)
            staged.rename(target)
    subprocess.run(['go', 'mod', 'edit', '-replace='+MODULE+'@'+VERSION+'=./'+COPY], cwd=vendor, check=True)
    verify(vendor)


def verify(vendor):
    vendor = checked_vendor(vendor)
    module_plan(vendor, required=True)
    return {COPY+'/'+name:digest for name,digest in verify_tree(vendor/COPY).items()}
