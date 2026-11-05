"""Drain the original pinned WG/AWG userspace link before gVisor teardown."""
from pathlib import Path
import hashlib
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PIN='1ac1a339cb1223e9c70eae14c44411c75033c02d'
SOURCE_SHA='3321ef8f0dd2a0800d13a0e7f5d7977d3179577d'
REPLACEMENTS=[
 ('\tdispatcher     stack.NetworkDispatcher','\tdispatcherAccess sync.RWMutex\n\tdispatcher     stack.NetworkDispatcher'),
 ('func (w *stackDevice) Write(bufs [][]byte, offset int) (count int, err error) {',
  '''func (w *stackDevice) Write(bufs [][]byte, offset int) (count int, err error) {
	// Retain this exact dispatcher through delivery. Close drains it before
	// entering the stack lock; a late decrypted packet cannot attach anew.
	w.dispatcherAccess.RLock()
	defer w.dispatcherAccess.RUnlock()
	select {
	case <-w.done:
		return 0, os.ErrClosed
	default:
	}
	if w.dispatcher == nil {
		return 0, os.ErrClosed
	}'''),
 ('\t\tclose(w.done)\n\t\tclose(w.events)',
  '''\t\tclose(w.done)
		// Delivery can acquire the gVisor stack lock. Drain before Stack.Wait
		// takes that lock and calls Attach(nil), never while holding it.
		(*wireEndpoint)(w).Attach(nil)
		close(w.events)'''),
 ('''func (ep *wireEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
}

func (ep *wireEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}''',
  '''func (ep *wireEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcherAccess.Lock()
	defer ep.dispatcherAccess.Unlock()
	select {
	case <-ep.done:
		dispatcher = nil
	default:
	}
	ep.dispatcher = dispatcher
}

func (ep *wireEndpoint) IsAttached() bool {
	ep.dispatcherAccess.RLock()
	defer ep.dispatcherAccess.RUnlock()
	return ep.dispatcher != nil
}''')]

def blobsha(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def inputs():return [Path(__file__).resolve(),ROOT/'deploy/test_mobile_wireguard_stack_policy.py',ROOT/'deploy/test_mobile_wireguard_stack.py',ROOT/'mobile/wireguard/stack_close_test.go.tmpl']
def patch(source):
 original=source
 for old,new in reversed(REPLACEMENTS):
  if original.count(new)==1:original=original.replace(new,old,1)
 if blobsha(original.encode())!=SOURCE_SHA or any(original.count(old)!=1 for old,new in REPLACEMENTS):raise ValueError('Pinned WireGuard stack changed; delivery drain refused')
 fixed=original
 for old,new in REPLACEMENTS:fixed=fixed.replace(old,new,1)
 if source not in (original,fixed):raise ValueError('Partial WireGuard stack delivery drain')
 return fixed

def prepare(vendor):
 vendor=Path(vendor).resolve(strict=True)
 if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=PIN:raise ValueError('WireGuard stack drain requires the exact core pin')
 source=vendor/'transport/wireguard/device_stack.go';test=source.with_name('routervpn_stack_close_test.go')
 for p in (source,test):
  if p.is_symlink() or not p.resolve().is_relative_to(vendor):raise ValueError('Unsafe WireGuard stack drain target')
 fixed=patch(source.read_text());fixture=(ROOT/'mobile/wireguard/stack_close_test.go.tmpl').read_bytes()
 source.write_text(fixed);test.write_bytes(fixture)
 print('Verified native WG/AWG link drains before gVisor stack teardown')

def verify(vendor):
 vendor=Path(vendor).resolve(strict=True);source=vendor/'transport/wireguard/device_stack.go';test=source.with_name('routervpn_stack_close_test.go')
 if source.is_symlink() or test.is_symlink() or source.read_text()!=patch(source.read_text()) or test.read_bytes()!=(ROOT/'mobile/wireguard/stack_close_test.go.tmpl').read_bytes():raise ValueError('Changed native WireGuard stack drain projection')
