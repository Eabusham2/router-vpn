"""Bounded, non-accepting replay of the observed encrypted hostname failure."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HELPER = 'deploy/fixtures/server-dns-diagnostic.go.tmpl'
ANCHORS = {
 'dns/router.go': [
  ('func (r *Router) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {', '\n\trouterVPNServerDNSDiagnostic("router-lookup", domain, "lookup", options, r.defaultDomainStrategy)'),
  ('func (r *Router) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {', '\n\trouterVPNServerDNSDiagnosticExchange("router-exchange", message, options, r.defaultDomainStrategy)'),
  ('func (r *Router) ExchangeAsync(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions, callback func(response *mDNS.Msg, err error)) {', '\n\trouterVPNServerDNSDiagnosticExchange("router-async", message, options, r.defaultDomainStrategy)'),
 ],
 'dns/client.go': [
  ('func (c *Client) Lookup(ctx context.Context, transport adapter.DNSTransport, domain string, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) ([]netip.Addr, error) {', '\n\trouterVPNServerDNSDiagnostic("client-lookup", domain, "lookup", options, C.DomainStrategyAsIS)'),
  ('func (c *Client) Exchange(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) (*dns.Msg, error) {', '\n\trouterVPNServerDNSDiagnosticExchange("client-exchange", message, options, C.DomainStrategyAsIS)'),
  ('func (c *Client) ExchangeAsync(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool, callback func(response *dns.Msg, err error)) {', '\n\trouterVPNServerDNSDiagnosticExchange("client-async", message, options, C.DomainStrategyAsIS)'),
 ],
}
DRIVER = 'cmd/sing-box/routervpn_server_chain_encrypted_linux_test.go'
DRIVER_ANCHOR = '\tw.process.join(t)\n'
DRIVER_PRINT = '''	diagnosticRows := 0
	for _, line := range strings.Split(w.process.log.text(), "\\n") {
		if safe := serverChainDNSDiagnosticSafe(line); safe != "" { t.Log(safe); diagnosticRows++; if diagnosticRows == 24 { break } }
	}
'''
DRIVER_FILTER = r'''
func serverChainDNSDiagnosticSafe(line string) string {
 const prefix = "ROUTERVPN_SERVER_DNS_DIAGNOSTIC "
 if len(line)>768 || !strings.HasPrefix(line,prefix) { return "" }
 var fields map[string]string
 if json.Unmarshal([]byte(strings.TrimPrefix(line,prefix)),&fields)!=nil || len(fields)!=8 { return "" }
 allowed:=map[string]string{
  "phase":"|router-lookup|client-lookup|router-exchange|client-exchange|router-async|client-async|unknown|", "question":"|lookup|a|aaaa|other|invalid|", "domain":"|test-middle|other|",
  "transport":"|explicit|selected|", "caller":"|resolve-dialer|wireguard|amnezia|server-front|other|",
  "strategy":"|as-is|ipv4-only|ipv6-only|prefer-ipv4|prefer-ipv6|unknown|",
  "lookup":"|as-is|ipv4-only|ipv6-only|prefer-ipv4|prefer-ipv6|unknown|",
  "global":"|not-applicable|as-is|ipv4-only|ipv6-only|prefer-ipv4|prefer-ipv6|unknown|",
 }
 for key,choices:=range allowed { value,ok:=fields[key]; if !ok || value=="" || strings.Contains(value,"|") || !strings.Contains(choices,"|"+value+"|") { return "" } }
 raw,_:=json.Marshal(fields)
 return prefix+string(raw)
}
'''


def eligible(case, error):
    if not isinstance(error, subprocess.CalledProcessError):
        return False
    raw = error.output or b''
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8', errors='replace')
    return (case.startswith('prefix-hostname-')
            and 'ROUTERVPN_SERVER_PEER_FAILURE hostname-question-aaaa' in raw)


def overlay(core, directory):
    core, directory = Path(core).resolve(), Path(directory).resolve()
    directory.mkdir(mode=0o755)
    replacements, original = {}, {}
    for relative, anchors in ANCHORS.items():
        path = core/relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('DNS diagnostic lost its original source')
        raw = path.read_bytes(); text = raw.decode()
        if any(text.count(anchor)!=1 for anchor,_ in anchors) or 'routerVPNServerDNSDiagnostic' in text:
            raise ValueError('DNS diagnostic source anchor differs')
        original[str(path)] = hashlib.sha256(raw).hexdigest()
        target = directory/(path.parent.name+'-'+path.name)
        for anchor,addition in anchors:
            text=text.replace(anchor,anchor+addition,1)
        target.write_text(text)
        replacements[str(path)] = str(target)
    driver = core/DRIVER
    if driver.is_symlink() or driver.read_text().count(DRIVER_ANCHOR) != 1:
        raise ValueError('DNS diagnostic lost its original joined driver')
    raw = driver.read_bytes(); original[str(driver)] = hashlib.sha256(raw).hexdigest()
    target = directory/'diagnostic-driver.go'
    target.write_text(raw.decode().replace(DRIVER_ANCHOR, DRIVER_ANCHOR+DRIVER_PRINT, 1)+DRIVER_FILTER)
    replacements[str(driver)] = str(target)
    helper = ROOT/HELPER
    if helper.is_symlink() or not helper.is_file():
        raise ValueError('DNS diagnostic helper source unavailable')
    target = directory/'diagnostic-helper.go'; target.write_bytes(helper.read_bytes())
    virtual = core/'dns/routervpn_server_dns_failure_diagnostic.go'
    if virtual.exists() or virtual.is_symlink():
        raise ValueError('DNS diagnostic refuses an existing helper')
    replacements[str(virtual)] = str(target)
    result = directory/'overlay.json'
    result.write_text(json.dumps({'Replace': replacements}, sort_keys=True)+'\n')
    receipt = {'scope': 'non-accepting-hostname-diagnostic', 'original': original,
               'overlay': {path: hashlib.sha256(Path(value).read_bytes()).hexdigest()
                           for path, value in replacements.items()}}
    (directory/'source.json').write_text(json.dumps(receipt, sort_keys=True)+'\n')
    return result, receipt


def execute(*, core, workspace, compiler, captured, common, driver_flags, peer,
            case, program, native_env, sudo, run, image_identity, source_identity, expected_source):
    original_source = source_identity()
    if original_source != expected_source:
        raise ValueError('DNS diagnostic no longer matches the failed original source')
    directory = Path(workspace)/'dns-failure-diagnostic'
    mapping, source = overlay(core, directory)
    shadow = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in [str(mapping), *json.loads(mapping.read_text())['Replace'].values()]}
    worker, driver = directory/'sing-box', directory/'acceptance.test'
    images = {}
    print('NON-ACCEPTING DNS FAILURE DIAGNOSTIC: original case failure remains authoritative', flush=True)
    try:
        run([compiler, 'build', *common, '-overlay='+str(mapping), '-o', worker, './cmd/sing-box'],
            cwd=core, env=captured, timeout=600)
        run([compiler, 'test', '-c', *driver_flags, '-overlay='+str(mapping), '-o', driver, './cmd/sing-box'],
            cwd=core, env=captured, timeout=600)
        images = {role: image_identity(path) for role, path in (('driver', driver), ('peer', peer), ('worker', worker))}
        print('NON-ACCEPTING DNS DIAGNOSTIC IDENTITIES '+json.dumps({
            'case': case, 'source': source, 'original_source_sha256': hashlib.sha256(json.dumps(original_source,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'images': {role: value[-1] for role, value in images.items()}}, sort_keys=True), flush=True)
        command = ['unshare', '--user', '--map-root-user', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                   sys.executable, '-I', '-c', program, str(driver), str(peer), str(worker),
                   images['driver'][-1], images['peer'][-1], images['worker'][-1], case]
        if sudo:
            command = [sudo, '-n', '--preserve-env=ROUTERVPN_SERVER_CHAIN_OUTER_NETNS,ROUTERVPN_SERVER_CHAIN_CARRIER_MTU', '--', *command]
        output = run(command, cwd=workspace, env=native_env, timeout=125, sudo=sudo)
        print(output, end='')
    finally:
        if any(hashlib.sha256(Path(path).read_bytes()).hexdigest()!=digest for path,digest in shadow.items()):
            raise ValueError('DNS diagnostic overlay changed')
        if source_identity() != original_source:
            raise ValueError('DNS diagnostic lost its original complete source')
        if images and any(image_identity(path) != images[role] for role,path in (('driver',driver),('peer',peer),('worker',worker))):
            raise ValueError('DNS diagnostic lost a captured image')
        if any(hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest
               for path, digest in source['original'].items()):
            raise ValueError('DNS diagnostic changed original source')


def observe_failure(case, original_failure, **arguments):
    if not eligible(case, original_failure):
        return
    try:
        execute(case=case, **arguments)
    except Exception as diagnostic_error:
        # Fixed classification only; raw errors can contain config or paths.
        print('NON-ACCEPTING DNS DIAGNOSTIC terminated: '+type(diagnostic_error).__name__, flush=True)
