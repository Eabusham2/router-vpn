//go:build windows

package mobiletor

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// The native layouts and GUIDs are the Microsoft Windows SDK fwpmu.h,
// fwpmtypes.h and fwptypes.h declarations. They match the existing executable
// WFP boundary in client/Private-RouterVPN-Wfp.ps1; Windows desktop targets are
// AMD64 and ARM64. Calls reject another ABI before creating any WFP object.
// https://learn.microsoft.com/windows/win32/fwp/object-management
// https://learn.microsoft.com/windows/win32/fwp/filter-arbitration
// https://learn.microsoft.com/windows/win32/fwp/permitting-and-blocking-applications-and-users

type desktopWFPDisplay struct{ Name, Description *uint16 }
type desktopWFPBlob struct {
	Size uint32
	Data *byte
}
type desktopWFPValue struct {
	Type uint32
	Data uint64
}
type desktopWFPConditionNative struct {
	Field syscall.GUID
	Match uint32
	Value desktopWFPValue
}
type desktopWFPAction struct {
	Type uint32
	Key  syscall.GUID
}
type desktopWFPFilter struct {
	Key             syscall.GUID
	Display         desktopWFPDisplay
	Flags           uint32
	Provider        *syscall.GUID
	Metadata        desktopWFPBlob
	Layer, Sublayer syscall.GUID
	Weight          desktopWFPValue
	ConditionCount  uint32
	Conditions      *desktopWFPConditionNative
	Action          desktopWFPAction
	Context         [2]uint64
	Reserved        *syscall.GUID
	ID              uint64
	EffectiveWeight desktopWFPValue
}
type desktopWFPSubLayer struct {
	Key      syscall.GUID
	Display  desktopWFPDisplay
	Flags    uint32
	Provider *syscall.GUID
	Metadata desktopWFPBlob
	Weight   uint16
}
type desktopWFPSession struct {
	Key                       syscall.GUID
	Display                   desktopWFPDisplay
	Flags, Timeout, ProcessID uint32
	SID                       *syscall.SID
	Username                  *uint16
	KernelMode                int32
}

type desktopWFPCondition struct {
	Field       syscall.GUID
	Type, Match uint32
	Number      uint64
	Bytes       []byte
}
type desktopWFPRule struct {
	Key             syscall.GUID
	Name            string
	Layer, Sublayer syscall.GUID
	Persistent      bool
	Weight          uint64
	Permit          bool
	Metadata        []byte
	Conditions      []desktopWFPCondition
	ID              uint64
}

type desktopWFPAPI struct {
	open, close, begin, commit, abort      *syscall.Proc
	addLayer, getLayer, deleteLayer        *syscall.Proc
	getLayerSecurity, getFilterSecurity    *syscall.Proc
	addFilter, getFilter, deleteFilter     *syscall.Proc
	createEnum, enumerate, closeEnum, free *syscall.Proc
	convertSD, freeLocal                   *syscall.Proc
	getSDControl                           *syscall.Proc
	interfaceLUID                          *syscall.Proc
}

var desktopWFPAPILoad struct {
	sync.Once
	value *desktopWFPAPI
	err   error
}

func desktopWFPRequireLayout() error {
	if unsafe.Sizeof(uintptr(0)) != 8 || unsafe.Sizeof(desktopWFPValue{}) != 16 || unsafe.Sizeof(desktopWFPConditionNative{}) != 40 || unsafe.Sizeof(desktopWFPFilter{}) != 200 || unsafe.Sizeof(desktopWFPSubLayer{}) != 72 || unsafe.Sizeof(desktopWFPSession{}) != 72 || unsafe.Offsetof(desktopWFPFilter{}.Conditions) != 120 || unsafe.Offsetof(desktopWFPFilter{}.Context) != 152 || unsafe.Offsetof(desktopWFPFilter{}.EffectiveWeight) != 184 {
		return errors.New("Windows physical WFP boundary has an unsupported native ABI")
	}
	return nil
}

func desktopWFPLoad() (*desktopWFPAPI, error) {
	desktopWFPAPILoad.Do(func() {
		if err := desktopWFPRequireLayout(); err != nil {
			desktopWFPAPILoad.err = err
			return
		}
		kernel := syscall.NewLazyDLL("kernel32.dll")
		var directory [32768]uint16
		getDirectory := kernel.NewProc("GetSystemDirectoryW")
		if err := getDirectory.Find(); err != nil {
			desktopWFPAPILoad.err = err
			return
		}
		count, _, callErr := getDirectory.Call(uintptr(unsafe.Pointer(&directory[0])), uintptr(len(directory)))
		if count == 0 || count >= uintptr(len(directory)) {
			desktopWFPAPILoad.err = errors.Join(callErr, errors.New("WFP system directory was not available"))
			return
		}
		system := syscall.UTF16ToString(directory[:count])
		wfp := syscall.NewLazyDLL(filepath.Join(system, "fwpuclnt.dll"))
		advapi := syscall.NewLazyDLL(filepath.Join(system, "advapi32.dll"))
		iphelper := syscall.NewLazyDLL(filepath.Join(system, "iphlpapi.dll"))
		a := &desktopWFPAPI{}
		for _, item := range []struct {
			target **syscall.Proc
			dll    *syscall.LazyDLL
			name   string
		}{
			{&a.open, wfp, "FwpmEngineOpen0"}, {&a.close, wfp, "FwpmEngineClose0"},
			{&a.begin, wfp, "FwpmTransactionBegin0"}, {&a.commit, wfp, "FwpmTransactionCommit0"}, {&a.abort, wfp, "FwpmTransactionAbort0"},
			{&a.addLayer, wfp, "FwpmSubLayerAdd0"}, {&a.getLayer, wfp, "FwpmSubLayerGetByKey0"}, {&a.deleteLayer, wfp, "FwpmSubLayerDeleteByKey0"},
			{&a.getLayerSecurity, wfp, "FwpmSubLayerGetSecurityInfoByKey0"},
			{&a.getFilterSecurity, wfp, "FwpmFilterGetSecurityInfoByKey0"},
			{&a.addFilter, wfp, "FwpmFilterAdd0"}, {&a.getFilter, wfp, "FwpmFilterGetByKey0"}, {&a.deleteFilter, wfp, "FwpmFilterDeleteByKey0"},
			{&a.createEnum, wfp, "FwpmFilterCreateEnumHandle0"}, {&a.enumerate, wfp, "FwpmFilterEnum0"}, {&a.closeEnum, wfp, "FwpmFilterDestroyEnumHandle0"}, {&a.free, wfp, "FwpmFreeMemory0"},
			{&a.convertSD, advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW"}, {&a.freeLocal, kernel, "LocalFree"},
			{&a.getSDControl, advapi, "GetSecurityDescriptorControl"},
			{&a.interfaceLUID, iphelper, "ConvertInterfaceIndexToLuid"},
		} {
			proc := item.dll.NewProc(item.name)
			if err := proc.Find(); err != nil {
				desktopWFPAPILoad.err = err
				return
			}
			// syscall.Proc's cached address is private. FindProc on the already
			// loaded System32 module supplies the exact verified export.
			loaded := &syscall.DLL{Name: item.dll.Name, Handle: syscall.Handle(item.dll.Handle())}
			found, err := loaded.FindProc(item.name)
			if err != nil {
				desktopWFPAPILoad.err = err
				return
			}
			*item.target = found
		}
		desktopWFPAPILoad.value = a
	})
	return desktopWFPAPILoad.value, desktopWFPAPILoad.err
}

func desktopWFPError(operation string, status uintptr) error {
	if status == 0 {
		return nil
	}
	return fmt.Errorf("Windows owned WFP %s failed (0x%08x)", operation, uint32(status))
}

func desktopWFPGUID(value string) syscall.GUID {
	// These values are compiled constants or SHA-256-derived identities, never
	// text supplied by a socket caller or a decoded permission receipt.
	var result syscall.GUID
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 16 {
		panic("invalid compiled WFP GUID")
	}
	result.Data1 = binary.BigEndian.Uint32(raw[0:4])
	result.Data2 = binary.BigEndian.Uint16(raw[4:6])
	result.Data3 = binary.BigEndian.Uint16(raw[6:8])
	copy(result.Data4[:], raw[8:16])
	return result
}

var (
	desktopWFPConnect4      = desktopWFPGUID("c38d57d105a74c33904f7fbceee60e82")
	desktopWFPConnect6      = desktopWFPGUID("4a72393b319f44bc84c3ba54dcb3b6b4")
	desktopWFPAccept4       = desktopWFPGUID("e1cd9fe7f4b5427396c0592e487b8650")
	desktopWFPAccept6       = desktopWFPGUID("a3b42c979f044672b87ecee9c483257f")
	desktopWFPLocalAddress  = desktopWFPGUID("d9ee00dec1ef4617bfe3ffd8f5a08957")
	desktopWFPRemoteAddress = desktopWFPGUID("b235ae9a1d6449b8a44c5ff3d9095045")
	desktopWFPLocalPort     = desktopWFPGUID("0c1ba1af5765453faf22a8f791ac775b")
	desktopWFPRemotePort    = desktopWFPGUID("c35a604dd22b4e1a91b468f674ee674b")
	desktopWFPProtocol      = desktopWFPGUID("3971ef2b623e4f9a8cb16e79b806b9a7")
	desktopWFPFlags         = desktopWFPGUID("632ce23b5167435c86d7e903684aa80c")
	desktopWFPInterface     = desktopWFPGUID("4cd62a4959c34969b7f3bda5d32890a4")
	desktopWFPUserID        = desktopWFPGUID("af043a0ab34d4f86979cc90371af6e66")
	desktopWFPAppID         = desktopWFPGUID("d78e1e8786444ea59437d809ecefc971")
)

func desktopWFPDerivedKey(capture DesktopSocketCapture, label string) syscall.GUID {
	digest := sha256.Sum256([]byte("RouterVPN-WFP-Socket/1\x00" + capture.SessionID + "\x00" + capture.SourceSHA256 + "\x00" + capture.NetworkID + "\x00" + label))
	return desktopWFPGUID(hex.EncodeToString(digest[:16]))
}

func desktopWFPNumber(field syscall.GUID, kind uint32, value uint64) desktopWFPCondition {
	return desktopWFPCondition{Field: field, Type: kind, Number: value}
}
func desktopWFPAddress(field syscall.GUID, address netip.Addr) desktopWFPCondition {
	if address.Is4() {
		value := address.As4()
		return desktopWFPNumber(field, 3, uint64(binary.BigEndian.Uint32(value[:])))
	}
	value := address.As16()
	return desktopWFPCondition{Field: field, Type: 11, Bytes: append([]byte(nil), value[:]...)}
}
func desktopWFPPrefix(field syscall.GUID, prefix netip.Prefix) desktopWFPCondition {
	if prefix.Addr().Is4() {
		address := prefix.Addr().As4()
		data := make([]byte, 8)
		binary.LittleEndian.PutUint32(data, binary.BigEndian.Uint32(address[:]))
		binary.LittleEndian.PutUint32(data[4:], ^uint32(0)<<uint(32-prefix.Bits()))
		return desktopWFPCondition{Field: field, Type: 256, Bytes: data}
	}
	address := prefix.Addr().As16()
	data := append([]byte(nil), address[:]...)
	return desktopWFPCondition{Field: field, Type: 257, Bytes: append(data, byte(prefix.Bits()))}
}

type desktopWFPArena struct{ retained []any }

func (a *desktopWFPArena) pointer(value any, pointer unsafe.Pointer) uint64 {
	a.retained = append(a.retained, value)
	return uint64(uintptr(pointer))
}
func (a *desktopWFPArena) number(value uint64) uint64 {
	p := new(uint64)
	*p = value
	return a.pointer(p, unsafe.Pointer(p))
}
func (a *desktopWFPArena) data(value []byte) uint64 {
	b := append([]byte(nil), value...)
	return a.pointer(b, unsafe.Pointer(&b[0]))
}
func (a *desktopWFPArena) blob(value []byte) desktopWFPBlob {
	if len(value) == 0 {
		return desktopWFPBlob{}
	}
	data := append([]byte(nil), value...)
	a.retained = append(a.retained, data)
	return desktopWFPBlob{Size: uint32(len(data)), Data: &data[0]}
}

func (a *desktopWFPArena) text(value string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(value)
	a.retained = append(a.retained, p)
	return p
}
func (a *desktopWFPArena) condition(value desktopWFPCondition) desktopWFPConditionNative {
	n := desktopWFPConditionNative{Field: value.Field, Match: value.Match, Value: desktopWFPValue{Type: value.Type}}
	switch value.Type {
	case 1, 2, 3:
		n.Value.Data = value.Number
	case 4:
		n.Value.Data = a.number(value.Number)
	case 12, 14:
		blob := new(desktopWFPBlob)
		*blob = a.blob(value.Bytes)
		n.Value.Data = a.pointer(blob, unsafe.Pointer(blob))
	default:
		n.Value.Data = a.data(value.Bytes)
	}
	return n
}
func desktopWFPBlobEqual(actual desktopWFPBlob, expected []byte) bool {
	if actual.Size != uint32(len(expected)) || actual.Size > 65536 {
		return false
	}
	if actual.Size == 0 {
		return true
	}
	return actual.Data != nil && bytes.Equal(unsafe.Slice(actual.Data, int(actual.Size)), expected)
}
func desktopWFPConditionEqual(actual desktopWFPConditionNative, expected desktopWFPCondition) bool {
	if actual.Field != expected.Field || actual.Match != expected.Match || actual.Value.Type != expected.Type {
		return false
	}
	switch expected.Type {
	case 1:
		return uint8(actual.Value.Data) == uint8(expected.Number)
	case 2:
		return uint16(actual.Value.Data) == uint16(expected.Number)
	case 3:
		return uint32(actual.Value.Data) == uint32(expected.Number)
	case 4:
		return actual.Value.Data != 0 && *(*uint64)(unsafe.Pointer(uintptr(actual.Value.Data))) == expected.Number
	case 12, 14:
		return actual.Value.Data != 0 && desktopWFPBlobEqual(*(*desktopWFPBlob)(unsafe.Pointer(uintptr(actual.Value.Data))), expected.Bytes)
	default:
		return actual.Value.Data != 0 && len(expected.Bytes) > 0 && len(expected.Bytes) <= 65536 && bytes.Equal(unsafe.Slice((*byte)(unsafe.Pointer(uintptr(actual.Value.Data))), len(expected.Bytes)), expected.Bytes)
	}
}

type desktopWFPEngine struct {
	api         *desktopWFPAPI
	handle      syscall.Handle
	transaction bool
}

func desktopWFPOpen(dynamic bool) (*desktopWFPEngine, error) {
	api, err := desktopWFPLoad()
	if err != nil {
		return nil, err
	}
	e := &desktopWFPEngine{api: api}
	session := desktopWFPSession{Timeout: 2000}
	if dynamic {
		session.Flags = 1
	}
	status, _, _ := api.open.Call(0, 10, 0, uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&e.handle)))
	runtime.KeepAlive(session)
	if err := desktopWFPError("open", status); err != nil || e.handle == 0 {
		return e, errors.Join(err, errors.New("WFP did not return a session owner"))
	}
	return e, nil
}
func (e *desktopWFPEngine) Begin() error {
	s, _, _ := e.api.begin.Call(uintptr(e.handle), 0)
	if s == 0 {
		e.transaction = true
	}
	return desktopWFPError("begin transaction", s)
}
func (e *desktopWFPEngine) Commit() error {
	s, _, _ := e.api.commit.Call(uintptr(e.handle))
	if s == 0 {
		e.transaction = false
	}
	return desktopWFPError("commit transaction", s)
}
func (e *desktopWFPEngine) Abort() error {
	if !e.transaction {
		return nil
	}
	s, _, _ := e.api.abort.Call(uintptr(e.handle))
	// A lost commit reply or BFE-forced abort can leave no transaction. That
	// proves only that the transaction is gone; the caller still reads every
	// captured filter/record to resolve the possibly committed object state.
	if s == 0 || uint32(s) == 0x8032000d || uint32(s) == 0x8032000f {
		e.transaction = false
		return nil
	}
	return desktopWFPError("abort transaction", s)
}
func (e *desktopWFPEngine) Close() error {
	if e == nil || e.handle == 0 {
		return nil
	}
	if err := e.Abort(); err != nil {
		return err
	}
	status, _, _ := e.api.close.Call(uintptr(e.handle))
	if status == 0 {
		e.handle = 0
	}
	return desktopWFPError("close dynamic session", status)
}
func (e *desktopWFPEngine) free(pointer unsafe.Pointer) {
	e.api.free.Call(uintptr(unsafe.Pointer(&pointer)))
}

func (e *desktopWFPEngine) AddSublayer(key syscall.GUID, metadata []byte) error {
	return e.addSublayer(key, metadata, true, 65535)
}
func (e *desktopWFPEngine) addSublayer(key syscall.GUID, metadata []byte, persistent bool, weight uint16) error {
	arena := &desktopWFPArena{}
	value := desktopWFPSubLayer{Key: key, Weight: weight, Metadata: arena.blob(metadata), Display: desktopWFPDisplay{Name: arena.text("Router VPN captured physical protection"), Description: arena.text("Persistent fail-closed baseline with owned dynamic socket permits")}}
	if persistent {
		value.Flags = 1
	}
	sd, err := desktopWFPOwnerSD(e.api)
	if err != nil {
		return err
	}
	status, _, _ := e.api.addLayer.Call(uintptr(e.handle), uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&sd[0])))
	runtime.KeepAlive(arena)
	runtime.KeepAlive(sd)
	return desktopWFPError("add baseline sublayer", status)
}
func (e *desktopWFPEngine) AssertSublayer(key syscall.GUID, metadata []byte) error {
	actual, exists, err := e.ReadSublayer(key, true, 65535)
	if err != nil || !exists || !bytes.Equal(actual, metadata) {
		return errors.Join(err, errors.New("WFP baseline sublayer lost its exact owner"))
	}
	return nil
}
func (e *desktopWFPEngine) ReadSublayer(key syscall.GUID, persistent bool, weight uint16) ([]byte, bool, error) {
	var pointer *desktopWFPSubLayer
	status, _, _ := e.api.getLayer.Call(uintptr(e.handle), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&pointer)))
	if uint32(status) == 0x80320007 {
		return nil, false, nil
	}
	if err := desktopWFPError("read baseline sublayer", status); err != nil {
		return nil, false, err
	}
	if pointer == nil {
		return nil, false, errors.New("WFP returned no baseline sublayer")
	}
	defer e.free(unsafe.Pointer(pointer))
	flags := uint32(0)
	if persistent {
		flags = 1
	}
	if pointer.Key != key || pointer.Flags != flags || pointer.Weight != weight || pointer.Provider != nil || pointer.Metadata.Size == 0 || pointer.Metadata.Size > 16384 || pointer.Metadata.Data == nil {
		return nil, false, fmt.Errorf("WFP baseline sublayer lost its exact owner: key_match=%t flags=%#x expected_flags=%#x weight=%d expected_weight=%d provider_present=%t metadata_size=%d metadata_present=%t", pointer.Key == key, pointer.Flags, flags, pointer.Weight, weight, pointer.Provider != nil, pointer.Metadata.Size, pointer.Metadata.Data != nil)
	}
	if err := e.assertLayerSecurity(key); err != nil {
		return nil, false, err
	}
	return append([]byte(nil), unsafe.Slice(pointer.Metadata.Data, int(pointer.Metadata.Size))...), true, nil
}
func (e *desktopWFPEngine) DeleteSublayer(key syscall.GUID) error {
	s, _, _ := e.api.deleteLayer.Call(uintptr(e.handle), uintptr(unsafe.Pointer(&key)))
	if uint32(s) == 0x80320007 {
		return nil
	}
	return desktopWFPError("delete exact baseline sublayer", s)
}
func (e *desktopWFPEngine) SublayerAbsent(key syscall.GUID) error {
	var pointer *desktopWFPSubLayer
	status, _, _ := e.api.getLayer.Call(uintptr(e.handle), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&pointer)))
	if uint32(status) == 0x80320007 {
		return nil
	}
	if pointer != nil {
		e.free(unsafe.Pointer(pointer))
	}
	return errors.Join(desktopWFPError("confirm sublayer removal", status), errors.New("owned WFP sublayer absence was not proved"))
}

func (e *desktopWFPEngine) Add(rule *desktopWFPRule) error {
	arena := &desktopWFPArena{}
	value := desktopWFPFilter{Key: rule.Key, Layer: rule.Layer, Sublayer: rule.Sublayer, Weight: desktopWFPValue{Type: 4, Data: arena.number(rule.Weight)}, Metadata: arena.blob(rule.Metadata), Display: desktopWFPDisplay{Name: arena.text("Router VPN " + rule.Name)}}
	if rule.Persistent {
		value.Flags = 1
	}
	value.Action.Type = 0x1001
	if rule.Permit {
		value.Action.Type = 0x1002
	}
	conditions := make([]desktopWFPConditionNative, len(rule.Conditions))
	for i, condition := range rule.Conditions {
		conditions[i] = arena.condition(condition)
	}
	if len(conditions) > 0 {
		value.Conditions = &conditions[0]
		value.ConditionCount = uint32(len(conditions))
	}
	sd, err := desktopWFPOwnerSD(e.api)
	if err != nil {
		return err
	}
	status, _, _ := e.api.addFilter.Call(uintptr(e.handle), uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&sd[0])), uintptr(unsafe.Pointer(&rule.ID)))
	runtime.KeepAlive(arena)
	runtime.KeepAlive(conditions)
	runtime.KeepAlive(sd)
	if err := desktopWFPError("add exact filter", status); err != nil {
		return err
	}
	if rule.ID == 0 {
		return errors.New("WFP filter did not receive a kernel identity")
	}
	return nil
}
func desktopWFPAssertRule(value *desktopWFPFilter, rule desktopWFPRule) error {
	flags, action := uint32(0), uint32(0x1001)
	if rule.Persistent {
		flags = 1
	}
	if rule.Permit {
		action = 0x1002
	}
	if value == nil || value.Key != rule.Key || value.Layer != rule.Layer || value.Sublayer != rule.Sublayer || value.Flags&^0x40 != flags || value.Provider != nil || value.Action.Type != action || value.Action.Key != (syscall.GUID{}) || value.ID == 0 || rule.ID != 0 && value.ID != rule.ID || !desktopWFPBlobEqual(value.Metadata, rule.Metadata) || value.Weight.Type != 4 || value.Weight.Data == 0 || *(*uint64)(unsafe.Pointer(uintptr(value.Weight.Data))) != rule.Weight || value.ConditionCount != uint32(len(rule.Conditions)) {
		return errors.New("WFP filter identity, action, weight or lifetime changed")
	}
	if value.ConditionCount > 0 {
		if value.Conditions == nil || value.ConditionCount > 32 {
			return errors.New("WFP exact conditions disappeared")
		}
		for i, actual := range unsafe.Slice(value.Conditions, int(value.ConditionCount)) {
			if !desktopWFPConditionEqual(actual, rule.Conditions[i]) {
				return errors.New("WFP filter changed a captured identity or tuple condition")
			}
		}
	}
	return nil
}
func (e *desktopWFPEngine) Assert(rule desktopWFPRule) error {
	var pointer *desktopWFPFilter
	status, _, _ := e.api.getFilter.Call(uintptr(e.handle), uintptr(unsafe.Pointer(&rule.Key)), uintptr(unsafe.Pointer(&pointer)))
	if err := desktopWFPError("read exact filter", status); err != nil {
		return err
	}
	if pointer != nil {
		defer e.free(unsafe.Pointer(pointer))
	}
	if err := desktopWFPAssertRule(pointer, rule); err != nil {
		return err
	}
	return e.assertObjectSecurity(e.api.getFilterSecurity, rule.Key)
}
func (e *desktopWFPEngine) Delete(key syscall.GUID) error {
	s, _, _ := e.api.deleteFilter.Call(uintptr(e.handle), uintptr(unsafe.Pointer(&key)))
	if uint32(s) == 0x80320003 {
		return nil
	}
	return desktopWFPError("delete exact filter", s)
}
func (e *desktopWFPEngine) Absent(key syscall.GUID) error {
	var pointer *desktopWFPFilter
	status, _, _ := e.api.getFilter.Call(uintptr(e.handle), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&pointer)))
	if uint32(status) == 0x80320003 {
		return nil
	}
	if pointer != nil {
		e.free(unsafe.Pointer(pointer))
	}
	return errors.Join(desktopWFPError("confirm filter removal", status), errors.New("owned WFP filter absence was not proved"))
}

// Enumerate the captured sublayer's complete filter set. A new broader permit
// inside that same sublayer must not become an unnoticed new baseline.
func (e *desktopWFPEngine) AssertComplete(sublayer syscall.GUID, expected []desktopWFPRule) (result error) {
	var enumeration syscall.Handle
	status, _, _ := e.api.createEnum.Call(uintptr(e.handle), 0, uintptr(unsafe.Pointer(&enumeration)))
	if err := desktopWFPError("capture filter enumeration", status); err != nil {
		return err
	}
	defer func() {
		s, _, _ := e.api.closeEnum.Call(uintptr(e.handle), uintptr(enumeration))
		result = errors.Join(result, desktopWFPError("close filter enumeration", s))
	}()
	wanted := make(map[syscall.GUID]desktopWFPRule, len(expected))
	for _, rule := range expected {
		if _, duplicate := wanted[rule.Key]; duplicate {
			return errors.New("WFP expected filter identity repeated")
		}
		wanted[rule.Key] = rule
	}
	for total := 0; total <= 65536; {
		var page **desktopWFPFilter
		var count uint32
		status, _, _ := e.api.enumerate.Call(uintptr(e.handle), uintptr(enumeration), 128, uintptr(unsafe.Pointer(&page)), uintptr(unsafe.Pointer(&count)))
		if err := desktopWFPError("read filter enumeration", status); err != nil {
			if page != nil {
				e.free(unsafe.Pointer(page))
			}
			return err
		}
		if count > 128 || count > 0 && page == nil {
			if page != nil {
				e.free(unsafe.Pointer(page))
			}
			return errors.New("WFP enumeration exceeded its bound")
		}
		if count == 0 {
			if page != nil {
				e.free(unsafe.Pointer(page))
			}
			if len(wanted) != 0 {
				return errors.New("WFP complete baseline lost an owned filter")
			}
			return nil
		}
		var failure error
		for _, filter := range unsafe.Slice(page, int(count)) {
			if filter == nil {
				failure = errors.New("WFP enumeration contains an absent filter")
				break
			}
			if filter.Sublayer != sublayer {
				continue
			}
			rule, ok := wanted[filter.Key]
			if !ok {
				failure = errors.New("WFP captured sublayer acquired an extra or repeated filter")
				break
			}
			if failure = desktopWFPAssertRule(filter, rule); failure != nil {
				break
			}
			if failure = e.assertObjectSecurity(e.api.getFilterSecurity, rule.Key); failure != nil {
				break
			}
			delete(wanted, filter.Key)
		}
		e.free(unsafe.Pointer(page))
		if failure != nil {
			return failure
		}
		total += int(count)
	}
	return errors.New("WFP host filter enumeration exceeded its safety bound")
}

func desktopWFPUserCondition(api *desktopWFPAPI, sid []byte) (desktopWFPCondition, error) {
	if len(sid) < 8 || len(sid) > 68 || sid[0] != 1 || sid[1] > 15 || len(sid) != 8+int(sid[1])*4 {
		return desktopWFPCondition{}, errors.New("WFP socket owner has no bounded SID")
	}
	value := (*syscall.SID)(unsafe.Pointer(&sid[0]))
	text, err := value.String()
	if err != nil {
		return desktopWFPCondition{}, err
	}
	// FWP_ACTRL_MATCH_FILTER is 1. This ACL makes the user condition true only
	// for the independently captured isolated account, not a shared app path.
	sddl, err := syscall.UTF16PtrFromString("D:(A;;0x1;;;" + text + ")")
	if err != nil {
		return desktopWFPCondition{}, err
	}
	var descriptor unsafe.Pointer
	var size uint32
	status, _, callErr := api.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(sddl)
	runtime.KeepAlive(sid)
	if descriptor != nil {
		defer api.freeLocal.Call(uintptr(descriptor))
	}
	if status == 0 || descriptor == nil || size < 20 || size > 4096 {
		return desktopWFPCondition{}, errors.Join(callErr, errors.New("WFP isolated user ACL could not be created"))
	}
	return desktopWFPCondition{Field: desktopWFPUserID, Type: 14, Bytes: append([]byte(nil), unsafe.Slice((*byte)(descriptor), int(size))...)}, nil
}
