"""Synchronize the exact pinned Vision TLS parser without locking transport I/O.

Reader and writer own different framing fields but share one TLS detector. Keep
the detector's six fields in one transaction, copy its result for writer padding,
and emit parser diagnostics only after releasing the state lock.
"""
import hashlib

SOURCE = 'proxy/proxy.go'
SOURCE_SHA256 = 'a52ed3b7c16a8b1d0f63be3014454235232bca237dfda08f6a95e0244e3c0f1e'
PREPARED_SHA256 = 'd4922b395b1396d65a8c4c0778c6fa5f80be64a80d9f5bb42705ab25812957ec'

STATE_HELPERS = '''// visionTLSState is a coherent result of the shared TLS detector. Framing
// fields remain owned by their existing reader or writer; no mutex is copied.
type visionTLSState struct {
	NumberOfPacketToFilter int
	EnableXtls            bool
	IsTLS12orAbove        bool
	IsTLS                 bool
	Cipher                uint16
	RemainingServerHello  int32
}

func (s *TrafficState) visionTLSFiltering() bool {
	s.visionMu.Lock()
	defer s.visionMu.Unlock()
	return s.NumberOfPacketToFilter > 0
}

// captureVisionTLS serializes only in-memory detection. Its messages contain
// copied scalar arguments, so neither the logger nor any owned callback runs
// while the detector is locked. The public parser preserves its forced-call
// behavior; transport callers recheck the packet budget under this same lock.
func (s *TrafficState) captureVisionTLS(buffer buf.MultiBuffer, force bool) (visionTLSState, [][]any) {
	s.visionMu.Lock()
	defer s.visionMu.Unlock()
	var messages [][]any
	if force || s.NumberOfPacketToFilter > 0 {
		messages = xtlsFilterTLSLocked(buffer, s)
	}
	return visionTLSState{
		NumberOfPacketToFilter: s.NumberOfPacketToFilter,
		EnableXtls:            s.EnableXtls,
		IsTLS12orAbove:        s.IsTLS12orAbove,
		IsTLS:                 s.IsTLS,
		Cipher:                s.Cipher,
		RemainingServerHello:  s.RemainingServerHello,
	}, messages
}

func visionTLSLog(ctx context.Context, messages [][]any) {
	for _, arguments := range messages {
		errors.LogDebug(ctx, arguments...)
	}
}

func (s *TrafficState) filterVisionTLS(buffer buf.MultiBuffer, ctx context.Context) visionTLSState {
	state, messages := s.captureVisionTLS(buffer, false)
	visionTLSLog(ctx, messages)
	return state
}

'''

FILTER_OLD = '''func XtlsFilterTls(buffer buf.MultiBuffer, trafficState *TrafficState, ctx context.Context) {
	for _, b := range buffer {
		if b == nil {
			continue
		}
		trafficState.NumberOfPacketToFilter--
		if b.Len() >= 6 {
			startsBytes := b.BytesTo(6)
			if bytes.Equal(TlsServerHandShakeStart, startsBytes[:3]) && startsBytes[5] == TlsHandshakeTypeServerHello {
				trafficState.RemainingServerHello = (int32(startsBytes[3])<<8 | int32(startsBytes[4])) + 5
				trafficState.IsTLS12orAbove = true
				trafficState.IsTLS = true
				if b.Len() >= 79 && trafficState.RemainingServerHello >= 79 {
					sessionIdLen := int32(b.Byte(43))
					cipherSuite := b.BytesRange(43+sessionIdLen+1, 43+sessionIdLen+3)
					trafficState.Cipher = uint16(cipherSuite[0])<<8 | uint16(cipherSuite[1])
				} else {
					errors.LogDebug(ctx, "XtlsFilterTls short server hello, tls 1.2 or older? ", b.Len(), " ", trafficState.RemainingServerHello)
				}
			} else if bytes.Equal(TlsClientHandShakeStart, startsBytes[:2]) && startsBytes[5] == TlsHandshakeTypeClientHello {
				trafficState.IsTLS = true
				errors.LogDebug(ctx, "XtlsFilterTls found tls client hello! ", buffer.Len())
			}
		}
		if trafficState.RemainingServerHello > 0 {
			end := trafficState.RemainingServerHello
			if end > b.Len() {
				end = b.Len()
			}
			trafficState.RemainingServerHello -= b.Len()
			if bytes.Contains(b.BytesTo(end), Tls13SupportedVersions) {
				v, ok := Tls13CipherSuiteDic[trafficState.Cipher]
				if !ok {
					v = "Old cipher: " + strconv.FormatUint(uint64(trafficState.Cipher), 16)
				} else if v != "TLS_AES_128_CCM_8_SHA256" {
					trafficState.EnableXtls = true
				}
				errors.LogDebug(ctx, "XtlsFilterTls found tls 1.3! ", b.Len(), " ", v)
				trafficState.NumberOfPacketToFilter = 0
				return
			} else if trafficState.RemainingServerHello <= 0 {
				errors.LogDebug(ctx, "XtlsFilterTls found tls 1.2! ", b.Len())
				trafficState.NumberOfPacketToFilter = 0
				return
			}
			errors.LogDebug(ctx, "XtlsFilterTls inconclusive server hello ", b.Len(), " ", trafficState.RemainingServerHello)
		}
		if trafficState.NumberOfPacketToFilter <= 0 {
			errors.LogDebug(ctx, "XtlsFilterTls stop filtering", buffer.Len())
		}
	}
}'''


def locked_filter():
    """Retain every detection branch; defer only its six debug emissions."""
    signature = FILTER_OLD.splitlines()[0]
    lines = FILTER_OLD.replace(signature,
        'func xtlsFilterTLSLocked(buffer buf.MultiBuffer, trafficState *TrafficState) (messages [][]any) {', 1).splitlines()
    count = 0
    for index, line in enumerate(lines):
        if 'errors.LogDebug(ctx, ' in line:
            if not line.endswith(')'):
                raise ValueError('Pinned Vision diagnostic changed')
            lines[index] = line.replace('errors.LogDebug(ctx, ', 'messages = append(messages, []any{', 1)[:-1] + '})'
            count += 1
    if count != 6:
        raise ValueError('Pinned Vision diagnostic inventory changed')
    lines.insert(len(lines) - 1, '\treturn')
    public = '''func XtlsFilterTls(buffer buf.MultiBuffer, trafficState *TrafficState, ctx context.Context) {
	_, messages := trafficState.captureVisionTLS(buffer, true)
	visionTLSLog(ctx, messages)
}

// xtlsFilterTLSLocked is called only by captureVisionTLS with visionMu held.
// It changes no wire data and calls neither a logger nor a transport owner.
'''
    return public + '\n'.join(lines)


PATCHES = {SOURCE: (
    ('\t"strconv"\n', '\t"strconv"\n\t"sync"\n', 1),
    ('type TrafficState struct {\n', 'type TrafficState struct {\n\tvisionMu sync.Mutex // shared TLS detection only; never held across I/O\n', 1),
    ('type InboundState struct {', STATE_HELPERS + 'type InboundState struct {', 1),
    ('if *withinPaddingBuffers || w.trafficState.NumberOfPacketToFilter > 0 {',
     'if *withinPaddingBuffers || w.trafficState.visionTLSFiltering() {', 1),
    ('\tif w.trafficState.NumberOfPacketToFilter > 0 {\n\t\tXtlsFilterTls(buffer, w.trafficState, w.ctx)\n\t}',
     '\tw.trafficState.filterVisionTLS(buffer, w.ctx)', 1),
    ('\tif w.trafficState.NumberOfPacketToFilter > 0 {\n\t\tXtlsFilterTls(mb, w.trafficState, w.ctx)\n\t}',
     '\ttlsState := w.trafficState.filterVisionTLS(mb, w.ctx)', 1),
    ('longPadding := w.trafficState.IsTLS', 'longPadding := tlsState.IsTLS', 1),
    ('if w.trafficState.IsTLS &&', 'if tlsState.IsTLS &&', 1),
    ('if w.trafficState.EnableXtls {', 'if tlsState.EnableXtls {', 3),
    ('!w.trafficState.IsTLS12orAbove && w.trafficState.NumberOfPacketToFilter <= 1',
     '!tlsState.IsTLS12orAbove && tlsState.NumberOfPacketToFilter <= 1', 1),
    (FILTER_OLD, locked_filter(), 1),
)}


def transformed(text):
    for before, after, count in PATCHES[SOURCE]:
        if text.count(before) != count:
            raise ValueError('Pinned Vision parser boundary changed')
        text = text.replace(before, after)
    return text


def patch_text(path, text):
    if path != SOURCE:
        raise ValueError('Unexpected Vision parser source')
    digest = hashlib.sha256(text.encode()).hexdigest()
    if digest == PREPARED_SHA256:
        return text
    if digest != SOURCE_SHA256:
        raise ValueError('Pinned Vision parser source or synchronization differs')
    prepared = transformed(text)
    if hashlib.sha256(prepared.encode()).hexdigest() != PREPARED_SHA256:
        raise ValueError('Prepared Vision parser differs from the complete correction')
    return prepared
