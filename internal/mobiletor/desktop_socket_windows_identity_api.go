//go:build windows

package mobiletor

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// These declarations follow the Windows SDK's lmaccess.h, winnt.h, fwpsu.h
// and fwpstypes.h. The native desktop targets are amd64 and arm64; both use the
// same eight-byte Windows structure alignment. No token or account authority
// is accepted from a JSON receipt or a caller-supplied executable path.
type desktopWindowsTokenStatistics struct {
	TokenID, AuthenticationID uint64
	ExpirationTime            int64
	TokenType                 uint32
	ImpersonationLevel        uint32
	DynamicCharged            uint32
	DynamicAvailable          uint32
	GroupCount                uint32
	PrivilegeCount            uint32
	ModifiedID                uint64
}

type desktopWindowsUser2 struct {
	Name, Password                                           *uint16
	PasswordAge, Privilege                                   uint32
	HomeDirectory, Comment                                   *uint16
	Flags                                                    uint32
	ScriptPath                                               *uint16
	AuthFlags                                                uint32
	FullName, UserComment, Parameters, Workstations          *uint16
	LastLogon, LastLogoff, Expires, MaxStorage, UnitsPerWeek uint32
	LogonHours                                               *byte
	BadPasswordCount, NumberLogons                           uint32
	LogonServer                                              *uint16
	CountryCode, CodePage                                    uint32
}

type desktopWindowsUser23 struct {
	Name, FullName, Comment *uint16
	Flags                   uint32
	SID                     *syscall.SID
}

type desktopWindowsBlob struct {
	Size uint32
	Data *byte
}

type desktopWindowsALEProperties struct {
	EndpointID                  uint64
	IPVersion                   uint32
	LocalAddress, RemoteAddress [16]byte
	Protocol                    uint8
	LocalPort, RemotePort       uint16
	TokenModifiedID             uint64
	MMSAID, QMSAID              uint64
	IPsecStatus, Flags          uint32
	AppID                       desktopWindowsBlob
}

type desktopWindowsAccount struct {
	SID     []byte
	Comment string
	Flags   uint32
	Expires uint32
}

type desktopWindowsIdentityAPI struct {
	processImage, finalPath                        *syscall.Proc
	userAdd, userGet, userSet, userDelete, netFree *syscall.Proc
	logon, impersonate, revert, openThreadToken    *syscall.Proc
	validSID, socket                               *syscall.Proc
	engineOpen, engineClose, appID, freeWFP        *syscall.Proc
	endpoint                                       *syscall.Proc
}

var desktopWindowsIdentityAPIs struct {
	sync.Once
	api *desktopWindowsIdentityAPI
	err error
}

const (
	desktopWindowsAccountDisabled = uint32(2)
	desktopWindowsUserNotFound    = syscall.Errno(2221)
	desktopWindowsUserExists      = syscall.Errno(2224)
	desktopWindowsNoToken         = syscall.Errno(1008)
	// FwpsAleEndpointGetById0 is the user-mode ALE query. It reports
	// ERROR_NOT_FOUND for a retired endpoint, not the Fwpm object-management
	// FWP_E_NOT_FOUND HRESULT. No other lookup error proves retirement.
	desktopWindowsEndpointNotFound = syscall.Errno(1168) // ERROR_NOT_FOUND
)

func desktopWindowsIdentityNativeAPI() (*desktopWindowsIdentityAPI, error) {
	desktopWindowsIdentityAPIs.Do(func() {
		if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
			desktopWindowsIdentityAPIs.err = errors.New("Windows isolated sockets require a supported 64-bit native host")
			return
		}
		// Obtain System32 from the OS, never PATH, the working directory, or an
		// environment variable. In particular fwpuclnt.dll must not be searched
		// beside a user-controlled portable installation.
		kernel := syscall.NewLazyDLL("kernel32.dll")
		getSystemDirectory := kernel.NewProc("GetSystemDirectoryW")
		if err := getSystemDirectory.Find(); err != nil {
			desktopWindowsIdentityAPIs.err = err
			return
		}
		buffer := make([]uint16, 32768)
		n, _, callErr := getSystemDirectory.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
		if n == 0 || n >= uintptr(len(buffer)) {
			desktopWindowsIdentityAPIs.err = desktopWindowsCallFailure("system directory", callErr)
			return
		}
		directory := syscall.UTF16ToString(buffer[:n])
		api := new(desktopWindowsIdentityAPI)
		libraries := []struct {
			name  string
			procs map[string]**syscall.Proc
		}{
			{"kernel32.dll", map[string]**syscall.Proc{"QueryFullProcessImageNameW": &api.processImage, "GetFinalPathNameByHandleW": &api.finalPath}},
			{"netapi32.dll", map[string]**syscall.Proc{"NetUserAdd": &api.userAdd, "NetUserGetInfo": &api.userGet, "NetUserSetInfo": &api.userSet, "NetUserDel": &api.userDelete, "NetApiBufferFree": &api.netFree}},
			{"advapi32.dll", map[string]**syscall.Proc{"LogonUserW": &api.logon, "ImpersonateLoggedOnUser": &api.impersonate, "RevertToSelf": &api.revert, "OpenThreadToken": &api.openThreadToken, "IsValidSid": &api.validSID}},
			{"ws2_32.dll", map[string]**syscall.Proc{"WSASocketW": &api.socket}},
			{"fwpuclnt.dll", map[string]**syscall.Proc{"FwpmEngineOpen0": &api.engineOpen, "FwpmEngineClose0": &api.engineClose, "FwpmGetAppIdFromFileName0": &api.appID, "FwpmFreeMemory0": &api.freeWFP, "FwpsAleEndpointGetById0": &api.endpoint}},
		}
		for _, library := range libraries {
			dll, err := syscall.LoadDLL(filepath.Join(directory, library.name))
			if err != nil {
				desktopWindowsIdentityAPIs.err = err
				return
			}
			// The proc table and loaded system modules share process lifetime.
			for name, destination := range library.procs {
				proc, err := dll.FindProc(name)
				if err != nil {
					desktopWindowsIdentityAPIs.err = err
					return
				}
				*destination = proc
			}
		}
		var wsa syscall.WSAData
		if err := syscall.WSAStartup(0x202, &wsa); err != nil {
			desktopWindowsIdentityAPIs.err = err
			return
		}
		desktopWindowsIdentityAPIs.api = api
	})
	return desktopWindowsIdentityAPIs.api, desktopWindowsIdentityAPIs.err
}

func desktopWindowsCallFailure(operation string, err error) error {
	if err == nil || errors.Is(err, syscall.Errno(0)) {
		return errors.New("Windows isolated socket " + operation + " failed without a status")
	}
	// Account passwords never appear in operation or an error argument.
	return fmt.Errorf("Windows isolated socket %s: %w", operation, err)
}

func desktopWindowsRequireElevation() error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	var elevated, returned uint32
	if err := syscall.GetTokenInformation(token, 20 /* TokenElevation */, (*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &returned); err != nil || returned != 4 || elevated != 1 {
		return errors.Join(err, errors.New("Windows isolated socket creation requires the elevated native host"))
	}
	return nil
}

func desktopWindowsTokenIdentity(token syscall.Token) ([]byte, desktopWindowsTokenStatistics, error) {
	var statistics desktopWindowsTokenStatistics
	var returned uint32
	if err := syscall.GetTokenInformation(token, 10 /* TokenStatistics */, (*byte)(unsafe.Pointer(&statistics)), uint32(unsafe.Sizeof(statistics)), &returned); err != nil {
		return nil, statistics, err
	}
	if returned != uint32(unsafe.Sizeof(statistics)) || statistics.TokenID == 0 || statistics.AuthenticationID == 0 || statistics.ModifiedID == 0 {
		return nil, statistics, errors.New("Windows socket token has no complete kernel identity")
	}
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, statistics, errors.Join(err, errors.New("Windows socket token has no kernel SID"))
	}
	length := user.User.Sid.Len()
	if length < 8 || length > 68 {
		return nil, statistics, errors.New("Windows socket token SID has an invalid bound")
	}
	sid := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(user.User.Sid)), length)...)
	runtime.KeepAlive(user)
	return sid, statistics, nil
}

func (a *desktopWindowsIdentityAPI) account(name string) (desktopWindowsAccount, error) {
	var result desktopWindowsAccount
	name16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return result, err
	}
	var info *desktopWindowsUser23
	status, _, _ := a.userGet.Call(0, uintptr(unsafe.Pointer(name16)), 23, uintptr(unsafe.Pointer(&info)))
	if info != nil {
		defer a.netFree.Call(uintptr(unsafe.Pointer(info)))
	}
	if status != 0 {
		return result, syscall.Errno(status)
	}
	if info == nil || info.SID == nil {
		return result, errors.New("Windows isolated account readback has no SID")
	}
	valid, _, _ := a.validSID.Call(uintptr(unsafe.Pointer(info.SID)))
	if valid == 0 || info.SID.Len() < 8 || info.SID.Len() > 68 {
		return result, errors.New("Windows isolated account has an invalid SID")
	}
	if info.Comment == nil {
		return result, errors.New("Windows isolated account lost its creation marker")
	}
	// The owned creation marker is short. Do not walk an unbounded string from
	// the system allocation, even if another administrator changed the record.
	comment, err := desktopWindowsBoundedUTF16(info.Comment, 256)
	if err != nil {
		return result, err
	}
	result.SID = append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(info.SID)), info.SID.Len())...)
	result.Comment, result.Flags = comment, info.Flags
	// Level 23 supplies the SID; level 2 independently verifies the atomic
	// creation-time expiry. It bounds a process crash before logon/disable.
	var details *desktopWindowsUser2
	status, _, _ = a.userGet.Call(0, uintptr(unsafe.Pointer(name16)), 2, uintptr(unsafe.Pointer(&details)))
	if details != nil {
		defer a.netFree.Call(uintptr(unsafe.Pointer(details)))
	}
	if status != 0 {
		return desktopWindowsAccount{}, syscall.Errno(status)
	}
	if details == nil || details.Flags != info.Flags {
		return desktopWindowsAccount{}, errors.New("Windows isolated account changed between identity readbacks")
	}
	otherComment, err := desktopWindowsBoundedUTF16(details.Comment, 256)
	if err != nil || otherComment != result.Comment {
		return desktopWindowsAccount{}, errors.Join(err, errors.New("Windows isolated account expiry has another creation marker"))
	}
	result.Expires = details.Expires
	return result, nil
}

func desktopWindowsBoundedUTF16(pointer *uint16, limit int) (string, error) {
	if pointer == nil || limit <= 0 {
		return "", errors.New("Windows identity string is absent")
	}
	var value []uint16
	for i := 0; i < limit; i++ {
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(pointer), uintptr(i)*2))
		if c == 0 {
			return syscall.UTF16ToString(value), nil
		}
		value = append(value, c)
	}
	return "", errors.New("Windows identity string exceeds its captured bound")
}

func (a *desktopWindowsIdentityAPI) disableAccount(name string, expected desktopWindowsAccount) error {
	observed, err := a.account(name)
	if err != nil || !bytes.Equal(observed.SID, expected.SID) || observed.Comment != expected.Comment {
		return errors.Join(err, errors.New("Windows isolated account changed before quarantine"))
	}
	name16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	flags := observed.Flags | desktopWindowsAccountDisabled
	var parameter uint32
	status, _, _ := a.userSet.Call(0, uintptr(unsafe.Pointer(name16)), 1008, uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Pointer(&parameter)))
	if status != 0 {
		return desktopWindowsCallFailure("account quarantine", syscall.Errno(status))
	}
	observed, err = a.account(name)
	if err != nil || !bytes.Equal(observed.SID, expected.SID) || observed.Comment != expected.Comment || observed.Flags&desktopWindowsAccountDisabled == 0 {
		return errors.Join(err, errors.New("Windows isolated account quarantine was not independently confirmed"))
	}
	return nil
}

func desktopWindowsPassword() ([]uint16, error) {
	// Generate directly into a mutable UTF-16 buffer. The password never enters
	// a string, environment, command line, log, or persistent file.
	var entropy [48]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, err
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-=?@"
	secret := make([]uint16, len(entropy)+5)
	for i, b := range entropy {
		secret[i] = uint16(alphabet[int(b)%len(alphabet)])
		entropy[i] = 0
	}
	copy(secret[len(entropy):], []uint16{'A', 'a', '1', '!', 0})
	runtime.KeepAlive(entropy)
	return secret, nil
}

func desktopWindowsErasePassword(secret []uint16) {
	for i := range secret {
		secret[i] = 0
	}
	runtime.KeepAlive(secret)
}

func (a *desktopWindowsIdentityAPI) threadToken() (syscall.Token, error) {
	var token syscall.Token
	// GetCurrentThread's documented pseudo-handle is (HANDLE)-2. OpenAsSelf
	// checks access as the elevated host while reading the actual thread token.
	status, _, callErr := a.openThreadToken.Call(^uintptr(1), syscall.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&token)))
	if status == 0 {
		return 0, callErr
	}
	return token, nil
}

func (a *desktopWindowsIdentityAPI) createUnderToken(token syscall.Token, sid []byte, expected desktopWindowsTokenStatistics, family, kind, protocol int) (result DesktopSocketNative, resultErr error) {
	// This runs only on a new operation goroutine. If reversion cannot be proved,
	// leaving the goroutine locked makes the runtime terminate that OS thread;
	// an impersonated thread must never return to the general scheduler pool.
	runtime.LockOSThread()
	unlock := false
	defer func() {
		if unlock {
			runtime.UnlockOSThread()
		}
	}()
	prior, err := a.threadToken()
	if !errors.Is(err, desktopWindowsNoToken) {
		if prior != 0 {
			_ = prior.Close()
		}
		return nil, errors.New("Windows socket creation found a pre-existing thread identity")
	}
	status, _, callErr := a.impersonate.Call(uintptr(token))
	if status == 0 {
		// Failed impersonation is also followed by explicit reversion/readback.
		resultErr = desktopWindowsCallFailure("token impersonation", callErr)
	} else {
		actual, readErr := a.threadToken()
		if readErr == nil {
			actualSID, statistics, identityErr := desktopWindowsTokenIdentity(actual)
			readErr = errors.Join(identityErr, actual.Close())
			if !bytes.Equal(actualSID, sid) || statistics != expected {
				readErr = errors.Join(readErr, errors.New("Windows socket creation changed the captured thread token"))
			}
		}
		if readErr != nil {
			resultErr = readErr
		} else {
			handle, _, _ := a.socket.Call(uintptr(family), uintptr(kind), uintptr(protocol), 0, 0, 0x81 /* OVERLAPPED | NO_HANDLE_INHERIT */)
			if syscall.Handle(handle) == syscall.InvalidHandle {
				resultErr = desktopWindowsCallFailure("native socket creation", desktopSocketWinsockError())
			} else {
				result = desktopWindowsNativeOwn(syscall.Handle(handle))
			}
		}
	}
	status, _, callErr = a.revert.Call()
	if status == 0 {
		return result, errors.Join(resultErr, desktopWindowsCallFailure("thread identity reversion", callErr))
	}
	remaining, readErr := a.threadToken()
	if !errors.Is(readErr, desktopWindowsNoToken) {
		if remaining != 0 {
			_ = remaining.Close()
		}
		return result, errors.Join(resultErr, errors.New("Windows socket creation could not prove thread identity removal"))
	}
	unlock = true
	return result, resultErr
}

func (a *desktopWindowsIdentityAPI) executableAppID() ([]byte, error) {
	executable, held, err := a.canonicalExecutable()
	if err != nil {
		return nil, err
	}
	defer held.Close()
	path, err := syscall.UTF16PtrFromString(executable)
	if err != nil {
		return nil, err
	}
	var blob *desktopWindowsBlob
	status, _, _ := a.appID.Call(uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&blob)))
	if blob != nil {
		defer a.freeWFP.Call(uintptr(unsafe.Pointer(&blob)))
	}
	if status != 0 {
		return nil, syscall.Errno(status)
	}
	if blob == nil || blob.Data == nil || blob.Size < 2 || blob.Size > 65536 || blob.Size%2 != 0 {
		return nil, errors.New("Windows socket process has no bounded kernel application identity")
	}
	return append([]byte(nil), unsafe.Slice(blob.Data, int(blob.Size))...), nil
}

func (a *desktopWindowsIdentityAPI) canonicalExecutable() (string, *os.File, error) {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return "", nil, err
	}
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	status, _, callErr := a.processImage.Call(uintptr(process), 0 /* Win32 image path */, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)))
	if status == 0 || length == 0 || length >= uint32(len(buffer)) {
		return "", nil, desktopWindowsCallFailure("actual process image path", callErr)
	}
	// Query the running image, not argv[0] or a caller-supplied path. Windows
	// may launch through an 8.3 alias (for example RUNNER~1); the kernel's ALE
	// application identity names the normalized image. Keep its actual file
	// open while resolving and asking WFP for the application identifier.
	held, err := os.Open(syscall.UTF16ToString(buffer[:length]))
	if err != nil {
		return "", nil, err
	}
	failed := func(err error) (string, *os.File, error) {
		return "", nil, errors.Join(err, held.Close())
	}
	info, err := held.Stat()
	if err != nil {
		return failed(err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return failed(errors.New("Windows process image is not a held regular executable"))
	}
	opened, err := os.Executable()
	if err != nil {
		return failed(err)
	}
	openedInfo, err := os.Stat(opened)
	if err != nil || !os.SameFile(info, openedInfo) {
		return failed(errors.Join(err, errors.New("Windows process image differs from the running executable file")))
	}
	lengthValue, _, callErr := a.finalPath.Call(held.Fd(), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0 /* FILE_NAME_NORMALIZED | VOLUME_NAME_DOS */)
	if lengthValue == 0 || lengthValue >= uintptr(len(buffer)) {
		return failed(desktopWindowsCallFailure("normalized held process image", callErr))
	}
	canonical := syscall.UTF16ToString(buffer[:lengthValue])
	canonicalInfo, err := os.Stat(canonical)
	if err != nil || !os.SameFile(info, canonicalInfo) {
		return failed(errors.Join(err, errors.New("Windows normalized image path lost its held file identity")))
	}
	return canonical, held, nil
}

func desktopWindowsALEEndpoint(raw syscall.RawConn) (uint64, error) {
	var endpoint uint64
	var nativeErr error
	if raw == nil {
		return 0, errors.New("Windows ALE proof requires the retained socket")
	}
	err := raw.Control(func(handle uintptr) {
		var returned uint32
		// mstcpip.h: _WSAIOR(IOC_VENDOR, 205).
		nativeErr = syscall.WSAIoctl(syscall.Handle(handle), 0x580000cd, nil, 0, (*byte)(unsafe.Pointer(&endpoint)), 8, &returned, nil, 0)
		if nativeErr == nil && (returned != 8 || endpoint == 0) {
			nativeErr = errors.New("Windows socket has no independently identified ALE endpoint")
		}
	})
	return endpoint, errors.Join(err, nativeErr)
}

func (a *desktopWindowsIdentityAPI) endpointProperties(engine syscall.Handle, endpoint uint64) (desktopWindowsALEProperties, []byte, error) {
	var properties *desktopWindowsALEProperties
	status, _, _ := a.endpoint.Call(uintptr(engine), uintptr(endpoint), uintptr(unsafe.Pointer(&properties)))
	if properties != nil {
		defer a.freeWFP.Call(uintptr(unsafe.Pointer(&properties)))
	}
	if status != 0 {
		return desktopWindowsALEProperties{}, nil, fmt.Errorf("Windows ALE endpoint lookup status %#x: %w", status, syscall.Errno(status))
	}
	if properties == nil || properties.EndpointID != endpoint || properties.TokenModifiedID == 0 || properties.AppID.Size < 2 || properties.AppID.Size > 65536 || properties.AppID.Data == nil {
		return desktopWindowsALEProperties{}, nil, errors.New("Windows ALE readback lacks its independent owner properties")
	}
	appID := append([]byte(nil), unsafe.Slice(properties.AppID.Data, int(properties.AppID.Size))...)
	copy := *properties
	copy.AppID = desktopWindowsBlob{}
	return copy, appID, nil
}

func desktopWindowsALEAddress(version uint32, address [16]byte) (netip.Addr, error) {
	switch version {
	case 0: // FWP_IP_VERSION_V4 stores the UINT32 address in host byte order.
		var network [4]byte
		binary.BigEndian.PutUint32(network[:], binary.LittleEndian.Uint32(address[:4]))
		return netip.AddrFrom4(network), nil
	case 1: // FWP_IP_VERSION_V6 stores sixteen network-order bytes.
		return netip.AddrFrom16(address), nil
	default:
		return netip.Addr{}, errors.New("Windows ALE endpoint has an unsupported address family")
	}
}
