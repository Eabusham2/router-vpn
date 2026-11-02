//go:build windows

package windowscontroller

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const fixtureFreshUACName = "TestWindowsControllerUACAcceptanceFreshLogonThreadAccess"
const fixtureFreshUACEnvironment = "ROUTERVPN_CONTROLLER_FRESH_UAC_WORKER"

type fixtureFreshUACReceipt struct {
	Role, Nonce, Report string
	FullReport          string
	Limited, Full       fixtureFreshUACIdentity
	File                syscall.ByHandleFileInformation
	FullFile            syscall.ByHandleFileInformation
}

var fixtureFreshUACWorkerReceipt *fixtureFreshUACReceipt

// Redirect only the exact dedicated worker before testing creates its logger.
// Ordinary fixture children retain their normal entry point, even if they
// inherit the nonsecret receipt. This is test plumbing, never token authority.
func TestMain(m *testing.M) {
	selector := "-test.run=^" + fixtureFreshUACName + "$"
	worker := false
	for _, arg := range os.Args[1:] {
		worker = worker || arg == selector
	}
	raw := os.Getenv(fixtureFreshUACEnvironment)
	if fixtureFreshUACWorkerReceipt != nil {
		encoded, err := json.Marshal(fixtureFreshUACWorkerReceipt)
		if err != nil {
			os.Exit(125)
		}
		raw = string(encoded)
	}
	if !worker || raw == "" {
		os.Exit(m.Run())
	}
	var receipt fixtureFreshUACReceipt
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 8192 || decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF || len(receipt.Nonce) != 32 || receipt.Report == "" ||
		(receipt.Role != "limited" && receipt.Role != "full") {
		fmt.Fprintln(os.Stderr, "fresh UAC worker receipt is malformed")
		os.Exit(125)
	}
	if _, err := hex.DecodeString(receipt.Nonce); err != nil {
		os.Exit(125)
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		os.Exit(125)
	}
	api, err := native()
	actual, tokenErr := fixtureFreshUACObserveToken(api, token)
	closeErr := token.Close()
	expected := receipt.Limited
	if receipt.Role == "full" {
		expected = receipt.Full
	}
	if err != nil || tokenErr != nil || closeErr != nil || !fixtureFreshUACPrimaryMatches(actual, expected) {
		fmt.Fprintln(os.Stderr, "fresh UAC worker did not retain its captured native primary logon")
		os.Exit(125)
	}
	name, err := syscall.UTF16PtrFromString(receipt.Report)
	if err != nil {
		os.Exit(125)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, 0x00200000 /* OPEN_REPARSE_POINT */, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fresh UAC worker cannot open its original report", err)
		os.Exit(125)
	}
	var info syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(handle, &info) != nil || !fixtureFreshUACSameFile(info, receipt.File) {
		_ = syscall.CloseHandle(handle)
		os.Exit(125)
	}
	report := os.NewFile(uintptr(handle), "owned-fresh-uac-report")
	os.Stdout, os.Stderr = report, report
	fixtureFreshUACWorkerReceipt = &receipt
	fmt.Fprintln(report, "Fresh interactive UAC", receipt.Role, "worker receipt:", receipt.Nonce)
	code := m.Run()
	if err := fixtureFreshUACFinishBootstrap(); err != nil {
		fmt.Fprintln(report, "fresh UAC bootstrap lifetime did not join:", err)
		code = 125
	}
	if err := errors.Join(report.Sync(), report.Close()); err != nil {
		code = 125
	}
	os.Exit(code)
}

func fixtureFreshUACSameFile(a, b syscall.ByHandleFileInformation) bool {
	return a.FileAttributes&(0x400|syscall.FILE_ATTRIBUTE_DIRECTORY) == 0 && a.NumberOfLinks == 1 && b.NumberOfLinks == 1 &&
		a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileIndexHigh == b.FileIndexHigh && a.FileIndexLow == b.FileIndexLow
}

type fixtureFreshUACAPI struct {
	native                                              *nativeAPI
	userAdd, userGet, userDel, memberAdd, memberDel     *syscall.Proc
	bufferFree, bufferSize, logon, create, lookup, read *syscall.Proc
}

func fixtureFreshUACAPIs(t *testing.T) *fixtureFreshUACAPI {
	t.Helper()
	n, err := native()
	if err != nil {
		t.Fatal(err)
	}
	netapi, err := syscall.LoadDLL(filepath.Join(n.systemDirectory, "netapi32.dll"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := netapi.Release(); err != nil {
			t.Error(err)
		}
	})
	a := &fixtureFreshUACAPI{native: n}
	for _, item := range []struct {
		dll    *syscall.DLL
		name   string
		output **syscall.Proc
	}{
		{netapi, "NetUserAdd", &a.userAdd}, {netapi, "NetUserGetInfo", &a.userGet}, {netapi, "NetUserDel", &a.userDel},
		{netapi, "NetLocalGroupAddMembers", &a.memberAdd}, {netapi, "NetLocalGroupDelMembers", &a.memberDel},
		{netapi, "NetApiBufferFree", &a.bufferFree}, {netapi, "NetApiBufferSize", &a.bufferSize},
		{n.convertSD.Dll, "LogonUserW", &a.logon}, {n.convertSD.Dll, "CreateProcessWithTokenW", &a.create},
		{n.convertSD.Dll, "LookupPrivilegeValueW", &a.lookup}, {n.convertSD.Dll, "RegGetValueW", &a.read},
	} {
		*item.output, err = item.dll.FindProc(item.name)
		if err != nil {
			t.Fatal(err)
		}
	}
	return a
}

type fixtureFreshUACPolicyValue struct {
	Exists bool
	Value  uint32
}

func (a *fixtureFreshUACAPI) policies() (map[string]fixtureFreshUACPolicyValue, error) {
	key, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`)
	result := map[string]fixtureFreshUACPolicyValue{}
	for _, name := range []string{"EnableLUA", "ConsentPromptBehaviorAdmin", "FilterAdministratorToken", "PromptOnSecureDesktop"} {
		field, _ := syscall.UTF16PtrFromString(name)
		var value, kind uint32
		size := uint32(4)
		status, _, _ := a.read.Call(uintptr(syscall.HKEY_LOCAL_MACHINE), uintptr(unsafe.Pointer(key)), uintptr(unsafe.Pointer(field)),
			0x10|0x10000|0x20000000, uintptr(unsafe.Pointer(&kind)), uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&size)))
		runtime.KeepAlive(key)
		runtime.KeepAlive(field)
		if syscall.Errno(status) == syscall.ERROR_FILE_NOT_FOUND {
			result[name] = fixtureFreshUACPolicyValue{}
			continue
		}
		if status != 0 || kind != 4 || size != 4 {
			return nil, fmt.Errorf("read-only UAC policy %s is unproved (status=%d kind=%d size=%d)", name, status, kind, size)
		}
		result[name] = fixtureFreshUACPolicyValue{true, value}
	}
	return result, nil
}

type fixtureFreshUACAccount struct {
	api                              *fixtureFreshUACAPI
	name, comment, sid, alias        string
	created, member, joined, deleted bool
}

func (a *fixtureFreshUACAccount) create(password []uint16) (uint32, error) {
	if a.created || a.name == "" || a.comment == "" || len(password) < 16 || password[len(password)-1] != 0 {
		return 0, errors.New("fresh account creation lost its new owned request")
	}
	name, _ := syscall.UTF16PtrFromString(a.name)
	comment, _ := syscall.UTF16PtrFromString(a.comment)
	type userInfo1 struct {
		Name, Password         *uint16
		PasswordAge, Privilege uint32
		Home, Comment          *uint16
		Flags                  uint32
		Script                 *uint16
	}
	user := userInfo1{Name: name, Password: &password[0], Privilege: 1, Comment: comment, Flags: 0x201 /* NORMAL_ACCOUNT | SCRIPT */}
	var field uint32
	status, _, _ := a.api.userAdd.Call(0, 1, uintptr(unsafe.Pointer(&user)), uintptr(unsafe.Pointer(&field)))
	runtime.KeepAlive(user)
	runtime.KeepAlive(password)
	runtime.KeepAlive(name)
	runtime.KeepAlive(comment)
	if status != 0 {
		return field, syscall.Errno(status)
	}
	a.created = true
	return 0, nil
}

func fixtureFreshUACString(buffer unsafe.Pointer, size uint32, value *uint16) (string, error) {
	base, point := uintptr(buffer), uintptr(unsafe.Pointer(value))
	if value == nil || point < base || point-base >= uintptr(size) || point%2 != 0 {
		return "", errors.New("native account string is outside its captured buffer")
	}
	data := unsafe.Slice(value, int((uintptr(size)-(point-base))/2))
	for index, unit := range data {
		if index > 512 {
			break
		}
		if unit == 0 {
			return syscall.UTF16ToString(data[:index]), nil
		}
	}
	return "", errors.New("native account string exceeds its captured bound")
}

func (a *fixtureFreshUACAccount) observe() (sid, comment string, result error) {
	name, _ := syscall.UTF16PtrFromString(a.name)
	var buffer unsafe.Pointer
	status, _, _ := a.api.userGet.Call(0, uintptr(unsafe.Pointer(name)), 23, uintptr(unsafe.Pointer(&buffer)))
	runtime.KeepAlive(name)
	if buffer != nil {
		defer func() {
			code, _, _ := a.api.bufferFree.Call(uintptr(buffer))
			if code != 0 {
				result = errors.Join(result, fmt.Errorf("account buffer close status=%d", code))
			}
		}()
	}
	if status != 0 {
		return "", "", syscall.Errno(status)
	}
	type userInfo23 struct {
		Name, FullName, Comment *uint16
		Flags                   uint32
		SID                     *syscall.SID
	}
	var size uint32
	code, _, _ := a.api.bufferSize.Call(uintptr(buffer), uintptr(unsafe.Pointer(&size)))
	if buffer == nil || code != 0 || size < uint32(unsafe.Sizeof(userInfo23{})) || size > 65536 {
		return "", "", errors.New("created account readback has no bounded native record")
	}
	user := (*userInfo23)(buffer)
	actualName, nameErr := fixtureFreshUACString(buffer, size, user.Name)
	comment, result = fixtureFreshUACString(buffer, size, user.Comment)
	start, pointer := uintptr(buffer), uintptr(unsafe.Pointer(user.SID))
	if nameErr != nil || result != nil || !strings.EqualFold(actualName, a.name) || user.SID == nil || pointer < start || pointer-start > uintptr(size)-8 {
		return "", "", errors.New("created account name, ownership marker or SID storage changed")
	}
	length := user.SID.Len()
	if length < 8 || uintptr(length) > uintptr(size)-(pointer-start) {
		return "", "", errors.New("created account SID exceeds native buffer")
	}
	sid, result = user.SID.String()
	return sid, comment, result
}

func (a *fixtureFreshUACAccount) close() error {
	if !a.created || a.deleted {
		return nil
	}
	if !a.joined {
		return errors.New("fresh CI account retained because its exact worker Job has not joined")
	}
	sid, comment, err := a.observe()
	if err != nil || a.sid == "" || sid != a.sid || comment != a.comment {
		return errors.Join(err, errors.New("fresh CI account cleanup lost its original SID or ownership marker"))
	}
	principal, err := syscall.StringToSid(a.sid)
	if err != nil {
		return err
	}
	if a.member {
		alias, _ := syscall.UTF16PtrFromString(a.alias)
		status, _, _ := a.api.memberDel.Call(0, uintptr(unsafe.Pointer(alias)), 0, uintptr(unsafe.Pointer(&principal)), 1)
		runtime.KeepAlive(alias)
		runtime.KeepAlive(principal)
		if status != 0 {
			return fmt.Errorf("owned CI alias membership removal status=%d", status)
		}
		a.member = false
	}
	// Recheck the name after changing only our own alias membership. Never
	// delete a pre-existing or concurrently replaced account by name.
	if observed, marker, err := a.observe(); err != nil || observed != a.sid || marker != a.comment {
		return errors.Join(err, errors.New("fresh CI account changed before deletion"))
	}
	name, _ := syscall.UTF16PtrFromString(a.name)
	status, _, _ := a.api.userDel.Call(0, uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(name)
	if status != 0 {
		return fmt.Errorf("owned CI account removal status=%d", status)
	}
	a.deleted = true
	if _, _, err := a.observe(); !errors.Is(err, syscall.Errno(2221) /* NERR_UserNotFound */) {
		return errors.Join(err, errors.New("owned CI account deletion was not observed"))
	}
	return nil
}

// Windows, not CreateRestrictedToken, creates this pair from a real local
// interactive logon. UAC policy is observed and left unchanged.
// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-logonuserw
// https://learn.microsoft.com/windows/win32/api/lmaccess/nf-lmaccess-netuseradd
func fixtureCreateFreshUACAccount(t *testing.T, api *fixtureFreshUACAPI) (*fixtureFreshUACAccount, syscall.Token) {
	t.Helper()
	var nonce [16]byte
	var secret [48]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	password := make([]uint16, len(secret)+5)
	copy(password, []uint16{'R', 'v', '7', '!'})
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for index, value := range secret {
		password[index+4] = uint16(alphabet[int(value)%len(alphabet)])
	}
	defer func() { clear(secret[:]); clear(password); runtime.KeepAlive(secret[:]); runtime.KeepAlive(password) }()
	account := &fixtureFreshUACAccount{api: api, name: "rvuac" + hex.EncodeToString(nonce[:6]), comment: "RouterVPN owned CI UAC " + hex.EncodeToString(nonce[:]), joined: true}
	t.Cleanup(func() {
		if err := account.close(); err != nil {
			t.Error(err)
		} else if account.created && account.deleted {
			t.Log("Owned fresh CI account and its exact alias membership removed after worker/descendant join and token closure")
		}
	})
	field, err := account.create(password)
	if err != nil {
		t.Fatalf("new owned CI account creation failed (field=%d): %v; no existing account is adopted or removed", field, err)
	}
	sid, marker, err := account.observe()
	if err != nil || marker != account.comment || !strings.HasPrefix(sid, "S-1-5-21-") || strings.HasSuffix(sid, "-500") {
		t.Fatal("new CI account native identity was not captured", err)
	}
	account.sid = sid
	collision := &fixtureFreshUACAccount{api: api, name: account.name, comment: account.comment + " collision", joined: true}
	if _, err := collision.create(password); !errors.Is(err, syscall.Errno(2224) /* NERR_UserExists */) || collision.created {
		t.Fatal("native account-name collision was not refused without adopting ownership", err)
	}
	if err := collision.close(); err != nil {
		t.Fatal("refused account-name collision acquired cleanup authority", err)
	}
	if observed, marker, err := account.observe(); err != nil || observed != account.sid || marker != account.comment {
		t.Fatal("refused collision changed or deleted the original native account", err)
	}
	t.Log("Native duplicate-account creation was refused; failed creator cleanup preserved the original SID and marker")
	administrator, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		t.Fatal(err)
	}
	account.alias, _, field, err = administrator.LookupAccount("")
	if err != nil || field != 4 || account.alias == "" {
		t.Fatal("actual local Administrators alias was not resolved", err)
	}
	resolved, _, kind, err := syscall.LookupSID("", account.alias)
	if err != nil || kind != 4 {
		t.Fatal("local Administrators alias readback failed", err)
	}
	if value, err := resolved.String(); err != nil || value != "S-1-5-32-544" {
		t.Fatal("local Administrators alias changed identity", err)
	}
	member, err := syscall.StringToSid(account.sid)
	if err != nil {
		t.Fatal(err)
	}
	alias, _ := syscall.UTF16PtrFromString(account.alias)
	status, _, _ := api.memberAdd.Call(0, uintptr(unsafe.Pointer(alias)), 0, uintptr(unsafe.Pointer(&member)), 1)
	runtime.KeepAlive(alias)
	runtime.KeepAlive(member)
	if status != 0 {
		t.Fatalf("new CI account membership was not independently added (status=%d)", status)
	}
	account.member = true
	for _, changed := range []string{"sid", "marker"} {
		stale := *account
		if changed == "sid" {
			stale.sid += "1"
		} else {
			stale.comment += " stale"
		}
		if err := stale.close(); err == nil || !strings.Contains(err.Error(), "cleanup lost its original SID or ownership marker") {
			t.Fatal("stale account receipt reached native mutation instead of the exact ownership refusal", changed, err)
		}
		if observed, marker, err := account.observe(); err != nil || observed != account.sid || marker != account.comment {
			t.Fatal("stale account receipt changed the live owned account", changed, err)
		}
	}
	t.Log("Native account readback rejected stale SID and marker receipts before membership/account mutation")
	name, _ := syscall.UTF16PtrFromString(account.name)
	domain, _ := syscall.UTF16PtrFromString(".")
	var token syscall.Token
	ok, _, callErr := api.logon.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(&password[0])),
		2 /* LOGON32_LOGON_INTERACTIVE */, 0 /* LOGON32_PROVIDER_DEFAULT */, uintptr(unsafe.Pointer(&token)))
	runtime.KeepAlive(name)
	runtime.KeepAlive(domain)
	runtime.KeepAlive(password)
	if token != 0 {
		t.Cleanup(func() {
			if err := token.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	if ok == 0 || token == 0 {
		t.Fatal(nativeError("fresh local interactive logon", callErr))
	}
	return account, token
}

func fixtureFreshUACLinked(token syscall.Token) (syscall.Token, error) {
	var linked syscall.Token
	var returned uint32
	err := syscall.GetTokenInformation(token, 19 /* TokenLinkedToken */, (*byte)(unsafe.Pointer(&linked)), uint32(unsafe.Sizeof(linked)), &returned)
	if err != nil || linked == 0 || returned != uint32(unsafe.Sizeof(linked)) {
		if linked != 0 {
			err = errors.Join(err, linked.Close())
		}
		return 0, errors.Join(err, errors.New("native UAC reciprocal token handle is unavailable"))
	}
	return linked, nil
}

func fixtureFreshUACObserveToken(api *nativeAPI, token syscall.Token) (fixtureFreshUACIdentity, error) {
	var result fixtureFreshUACIdentity
	if api == nil || token == 0 {
		return result, errors.New("native UAC token observation has no original handle")
	}
	identity, _, err := readTokenIdentity(token)
	if err != nil {
		return result, err
	}
	// Linked handles are evidence only. A SecurityIdentification link cannot
	// become a worker token; every real worker is checked independently below.
	var statistics tokenStatistics
	var returned uint32
	err = syscall.GetTokenInformation(token, 10, (*byte)(unsafe.Pointer(&statistics)), uint32(unsafe.Sizeof(statistics)), &returned)
	if err != nil || unsafe.Sizeof(statistics) != 56 || returned != 56 || statistics.TokenID == 0 ||
		(statistics.Type != 1 && statistics.Type != 2) || (statistics.Type == 2 && statistics.ImpersonationLevel != 1) {
		return result, errors.Join(err, fmt.Errorf("native UAC observed carrier is unproved (bytes=%d type=%d level=%d)", returned, statistics.Type, statistics.ImpersonationLevel))
	}
	if statistics.Type == 1 {
		statistics.ImpersonationLevel = 0 // This field has no meaning for primary tokens.
	}
	level, err := fixtureTokenElevationType(token)
	if err != nil {
		return result, err
	}
	integrity, err := fixtureTokenIntegrity(token)
	if err != nil {
		return result, err
	}
	numeric, err := strconv.ParseUint(strings.TrimPrefix(integrity, "S-1-16-"), 10, 32)
	if err != nil {
		return result, err
	}
	lookup, err := api.convertSD.Dll.FindProc("LookupPrivilegeValueW")
	if err != nil {
		return result, err
	}
	name, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	var debug fixturePrivilegeLUID
	ok, _, callErr := lookup.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&debug)))
	runtime.KeepAlive(name)
	if ok == 0 {
		return result, nativeError("native UAC debug privilege identity", callErr)
	}
	privileges, err := fixtureTokenPrivileges(token)
	if err != nil {
		return result, err
	}
	_, present := privileges[debug]
	return fixtureFreshUACIdentity{SID: identity.SID, AuthenticationID: identity.AuthenticationID, TokenID: statistics.TokenID, Session: identity.SessionID, ImpersonationLevel: statistics.ImpersonationLevel,
		ElevationType: level, Integrity: uint32(numeric), Primary: identity.Primary, Elevated: identity.Elevated, Admin: identity.Administrator, DebugPresent: present}, nil
}

func fixtureFreshUACReadPair(api *nativeAPI, token syscall.Token, sid string) (limited, full fixtureFreshUACIdentity, result error) {
	root, err := fixtureFreshUACObserveToken(api, token)
	if err != nil {
		return limited, full, fmt.Errorf("UAC pair root observation: %w", err)
	}
	linked, err := fixtureFreshUACLinked(token)
	if err != nil {
		return limited, full, fmt.Errorf("UAC pair root-to-linked acquisition: %w", err)
	}
	defer func() { result = errors.Join(result, linked.Close()) }()
	other, err := fixtureFreshUACObserveToken(api, linked)
	if err != nil {
		return limited, full, fmt.Errorf("UAC pair linked observation: %w", err)
	}
	back, err := fixtureFreshUACLinked(linked)
	if err != nil {
		return limited, full, fmt.Errorf("UAC pair linked-to-back acquisition: %w", err)
	}
	defer func() { result = errors.Join(result, back.Close()) }()
	backRoot, err := fixtureFreshUACObserveToken(api, back)
	if err != nil {
		return limited, full, fmt.Errorf("UAC pair back observation: %w", err)
	}
	again, err := fixtureFreshUACLinked(back)
	if err != nil {
		return limited, full, fmt.Errorf("UAC pair back-to-again acquisition: %w", err)
	}
	defer func() { result = errors.Join(result, again.Close()) }()
	backOther, err := fixtureFreshUACObserveToken(api, again)
	if err != nil {
		return limited, full, fmt.Errorf("UAC pair again observation: %w", err)
	}
	if root.ElevationType == 3 {
		limited, full = root, other
		err = fixtureFreshUACObservedPairValid(sid, root, limited, full, backRoot, backOther)
		if err == nil {
			err = fixtureDenyOnlyAdministrator(token)
		}
	} else {
		limited, full = other, root
		err = fixtureFreshUACObservedPairValid(sid, root, limited, full, backOther, backRoot)
		if err == nil {
			err = fixtureDenyOnlyAdministrator(linked)
		}
	}
	return limited, full, err
}

func TestWindowsControllerUACAcceptanceFreshLogonThreadAccess(t *testing.T) {
	if receipt := fixtureFreshUACWorkerReceipt; receipt != nil {
		if receipt.Role == "limited" {
			fixtureFreshUACNormalRunas(t, receipt)
			return
		}
		token, err := syscall.OpenCurrentProcessToken()
		if err != nil {
			t.Fatal(err)
		}
		defer token.Close()
		api, err := native()
		if err != nil {
			t.Fatal(err)
		}
		limited, full, err := fixtureFreshUACReadPair(api, token, receipt.Full.SID)
		if err != nil || !fixtureFreshUACFullWorkerMatches(limited, full, receipt.Limited, receipt.Full) {
			t.Fatal("Full worker lost its independently captured reciprocal interactive logons", err)
		}
		for _, item := range []struct {
			name string
			run  func(*testing.T)
		}{
			{"retained-limited-parent", fixtureFreshUACVerifyLimitedParentLifetime},
			{"linked-limited-access", TestWindowsControllerUACAcceptanceLimitedTokenThreadAccess},
			{"cancelled-uac", TestWindowsControllerFoundationRejectCancelledUAC},
			{"replacement-image", TestWindowsControllerFoundationSuspendedLaunchRejectsReplacement},
			{"missing-callback", TestWindowsControllerFoundationSuspendedLaunchRejectsMissingCallback},
			{"cancelled-suspended-owner", TestWindowsControllerFoundationSuspendedLaunchCancellation},
		} {
			t.Run(item.name, item.run)
		}
		t.Logf("Fresh native Limited/Full pair: session=%d Limited authentication LUID=%d Full authentication LUID=%d; normal runas, reciprocal identities and original native negative cases checked. Existing policy did not display a consent prompt; cross-account product and physical-device acceptance remain separate.", full.Session, limited.AuthenticationID, full.AuthenticationID)
		return
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" {
		t.Fatal("fresh-account UAC fixture is restricted to its disposable GitHub-hosted Windows job")
	}
	api := fixtureFreshUACAPIs(t)
	policies, err := api.policies()
	if err != nil || policies["EnableLUA"] != (fixtureFreshUACPolicyValue{true, 1}) {
		t.Fatal("fresh interactive logon requires already-enabled native UAC; no registry changes or synthetic token fallback", err)
	}
	for _, name := range []string{"EnableLUA", "ConsentPromptBehaviorAdmin", "FilterAdministratorToken", "PromptOnSecureDesktop"} {
		value := policies[name]
		t.Logf("Existing native UAC policy: %s present=%t value=%d (read-only)", name, value.Exists, value.Value)
	}
	if policies["ConsentPromptBehaviorAdmin"] != (fixtureFreshUACPolicyValue{true, 0}) {
		t.Fatal("disposable noninteractive CI requires its existing no-prompt administrator policy; no UAC policy is changed or consent bypassed")
	}
	before, err := CurrentIdentity()
	if err != nil || !before.Primary || !before.Elevated || !before.Administrator {
		t.Fatal("fresh UAC fixture has no elevated CI caller", err)
	}
	t.Cleanup(func() {
		after, err := api.policies()
		identity, identityErr := CurrentIdentity()
		if err != nil || identityErr != nil || !maps.Equal(policies, after) || identity != before {
			t.Error("fresh UAC fixture changed existing policy or parent identity", err, identityErr)
		}
	})
	account, logon := fixtureCreateFreshUACAccount(t, api)
	limited, full, err := fixtureFreshUACReadPair(api.native, logon, account.sid)
	if err != nil {
		t.Fatal("actual fresh interactive UAC pair is unavailable", err)
	}
	if observed, err := fixtureFreshUACObserveToken(api.native, logon); err != nil || observed.ElevationType != 3 {
		t.Fatal("LogonUser did not return its native Limited interactive token", err)
	}
	t.Logf("Fresh native linked Full observation: primary=%t identification_level=%d; this handle is never supplied to a launcher", full.Primary, full.ImpersonationLevel)
	fixtureRunFreshUACWorker(t, api, account, logon, limited, full)
}

// The first worker uses the OS-produced Limited primary token. It asks normal
// Windows runas to create the Full owner through the shipping protected launch.
// No linked identification token is converted or supplied to a launcher.
// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
func fixtureRunFreshUACWorker(t *testing.T, api *fixtureFreshUACAPI, account *fixtureFreshUACAccount, token syscall.Token, limited, full fixtureFreshUACIdentity) {
	t.Helper()
	worker := &fixtureRestrictedWorker{api: fixtureRestrictedAPIs(t)}
	var image, reportOwner, fullReportOwner *fixtureMediumImage
	var fullReport *os.File
	var closeDesktop func() error
	closed := false
	fullJoined := true // No runas process can exist before the Limited worker resumes.
	closeAll := func() error {
		if closed {
			return nil
		}
		// The generic worker closer also releases its image. A separate runas
		// process may still own that protected source, so retain this exact pin
		// when Full retirement is unproved, even after the Limited Job joins.
		retainedImage := worker.image
		if !fullJoined {
			worker.image = nil
		}
		closeErr := worker.close()
		if !fullJoined {
			worker.image = retainedImage
		}
		if closeErr != nil {
			return closeErr
		}
		if !fullJoined {
			return errors.New("fresh runas Full join is unproved; retain the owned account, protected image and report receipts for disposable-host cleanup")
		}
		account.joined = true
		var result error
		if closeDesktop != nil {
			result = errors.Join(result, closeDesktop())
		}
		if fullReport != nil {
			result = errors.Join(result, fullReport.Close())
			fullReport = nil
		}
		result = errors.Join(result, fullReportOwner.close(), reportOwner.close(), image.close())
		if result == nil {
			closed = true
		}
		return result
	}
	t.Cleanup(func() {
		if err := closeAll(); err != nil {
			t.Error("fresh UAC worker did not close its exact resources", err)
		}
	})
	if err := syscall.OpenProcessToken(^syscall.Handle(0), syscall.TOKEN_QUERY, &worker.parent); err != nil {
		t.Fatal(err)
	}
	var err error
	worker.privileges, err = fixtureTokenPrivileges(worker.parent)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := syscall.UTF16PtrFromString("SeImpersonatePrivilege")
	var privilege fixturePrivilegeLUID
	ok, _, callErr := api.lookup.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&privilege)))
	runtime.KeepAlive(name)
	if ok == 0 || worker.privileges[privilege]&2 == 0 {
		t.Fatal("fresh UAC worker requires the caller's existing enabled SeImpersonatePrivilege; no privilege adjustment", callErr)
	}
	current, err := PinCurrentImage()
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	image, err = fixtureCaptureMediumImage(worker.api, current, account.sid)
	if err != nil {
		t.Fatal("fresh UAC worker cannot retain its exact compiler image", err)
	}
	worker.image = image.image
	executable, err := fixtureFreshUACDOSImage(api.native, worker.image)
	if err != nil {
		t.Fatal(err)
	}
	worker.directory = filepath.Dir(executable)
	worker.desktop, closeDesktop = fixtureFreshUACDesktop(t, worker.api, account.sid)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(worker.directory, "fresh-uac-limited-"+hex.EncodeToString(nonce[:])+".txt")
	reportOwner, worker.report, err = fixtureFreshUACReport(api.native, image.dispose, reportPath, account.sid, true)
	if err != nil {
		t.Fatal(err)
	}
	var file syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(reportOwner.file, &file); err != nil {
		t.Fatal(err)
	}
	fullReportPath := filepath.Join(worker.directory, "fresh-uac-full-"+hex.EncodeToString(nonce[:])+".txt")
	fullReportOwner, fullReport, err = fixtureFreshUACReport(api.native, image.dispose, fullReportPath, account.sid, false)
	if err != nil {
		t.Fatal(err)
	}
	var fullFile syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(fullReportOwner.file, &fullFile); err != nil {
		t.Fatal(err)
	}
	receipt := fixtureFreshUACReceipt{Role: "limited", Nonce: hex.EncodeToString(nonce[:]), Report: reportPath, FullReport: fullReportPath, Limited: limited, Full: full, File: file, FullFile: fullFile}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var environment []uint16
	for _, item := range []string{fixtureFreshUACEnvironment + "=" + string(raw), "SystemRoot=" + filepath.Dir(api.native.systemDirectory),
		"TEMP=" + worker.directory, "TMP=" + worker.directory, "GORACE=atexit_sleep_ms=0"} {
		encoded, err := syscall.UTF16FromString(item)
		if err != nil {
			t.Fatal(err)
		}
		environment = append(environment, encoded...)
	}
	environment = append(environment, 0)
	job, _, callErr := api.native.createJob.Call(0, 0)
	worker.job = syscall.Handle(job)
	if job == 0 {
		t.Fatal(nativeError("fresh UAC private Job", callErr))
	}
	limits := jobLimits{Flags: 0x2008, ActiveProcesses: 4}
	ok, _, callErr = api.native.setJob.Call(job, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if ok == 0 {
		t.Fatal(nativeError("fresh UAC Job bounds", callErr))
	}
	var bound jobLimits
	var size uint32
	ok, _, callErr = worker.api.queryJob.Call(job, 9, uintptr(unsafe.Pointer(&bound)), unsafe.Sizeof(bound), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || size != uint32(unsafe.Sizeof(bound)) || bound.Flags != limits.Flags || bound.ActiveProcesses != limits.ActiveProcesses {
		t.Fatal("fresh UAC Job bounds were not retained", callErr)
	}
	// The real CreateProcessWithTokenW call rejected the extended Job-list
	// creation request with ERROR_INVALID_PARAMETER. Use its basic documented
	// STARTUPINFO form and retain the original creation suspension while binding
	// and independently verifying the exact Job, token and executable.
	// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
	// https://learn.microsoft.com/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject
	startup := syscall.StartupInfo{Cb: uint32(unsafe.Sizeof(syscall.StartupInfo{}))}
	startup.Desktop, err = syscall.UTF16PtrFromString(worker.desktop)
	if err != nil {
		t.Fatal(err)
	}
	application, _ := syscall.UTF16PtrFromString(executable)
	command, _ := syscall.UTF16FromString(syscall.EscapeArg(executable) + " -test.run=^" + fixtureFreshUACName + "$ -test.count=1 -test.timeout=65s -test.v")
	directory, _ := syscall.UTF16PtrFromString(worker.directory)
	account.joined = false
	ok, _, callErr = api.create.Call(uintptr(token), 0 /* no user profile or network-only logon */, uintptr(unsafe.Pointer(application)), uintptr(unsafe.Pointer(&command[0])),
		0x08000404 /* NO_WINDOW | UNICODE_ENVIRONMENT | SUSPENDED */, uintptr(unsafe.Pointer(&environment[0])), uintptr(unsafe.Pointer(directory)),
		uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&worker.process)))
	runtime.KeepAlive(startup)
	runtime.KeepAlive(environment)
	runtime.KeepAlive(application)
	runtime.KeepAlive(command)
	runtime.KeepAlive(directory)
	if ok == 0 || worker.process.Process == 0 || worker.process.Thread == 0 {
		t.Fatal(nativeError("fresh native Limited-token suspended worker creation", callErr))
	}
	suspend, err := api.native.processID.Dll.FindProc("SuspendThread")
	if err != nil {
		t.Fatal(err)
	}
	previous, _, callErr := suspend.Call(uintptr(worker.process.Thread))
	if uint32(previous) != 1 {
		t.Fatal("fresh Limited worker did not retain exactly its original creation suspension", callErr)
	}
	previous, _, callErr = worker.api.resume.Call(uintptr(worker.process.Thread))
	if uint32(previous) != 2 {
		t.Fatal("fresh Limited worker suspension observation did not restore the original count", callErr)
	}
	ok, _, callErr = api.native.assignJob.Call(uintptr(worker.job), uintptr(worker.process.Process))
	if ok == 0 {
		t.Fatal(nativeError("bind original still-suspended Limited worker to its exact Job", callErr))
	}
	var member uint32
	ok, _, callErr = api.native.inJob.Call(uintptr(worker.process.Process), uintptr(worker.job), uintptr(unsafe.Pointer(&member)))
	if ok == 0 || member != 1 {
		t.Fatal("fresh Limited worker has no verified bounded Job before its first resume", callErr)
	}
	var actualToken syscall.Token
	if err := syscall.OpenProcessToken(worker.process.Process, syscall.TOKEN_QUERY, &actualToken); err != nil {
		t.Fatal(err)
	}
	actual, observeErr := fixtureFreshUACObserveToken(api.native, actualToken)
	closeErr := actualToken.Close()
	if observeErr != nil || closeErr != nil || !fixtureFreshUACPrimaryMatches(actual, limited) {
		t.Fatal("fresh suspended worker changed its exact native Limited logon/session", observeErr, closeErr)
	}
	var duplicate syscall.Handle
	if err := syscall.DuplicateHandle(^syscall.Handle(0), worker.process.Process, ^syscall.Handle(0), &duplicate, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal(err)
	}
	process, err := adoptProcess(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	proofErr := verifySuspendedShellImage(api.native, process, worker.image)
	proofCloseErr := process.Close()
	if proofErr != nil || proofCloseErr != nil {
		t.Fatal("fresh suspended worker lost its exact retained image", proofErr, proofCloseErr)
	}
	fullJoined = false
	resumed, _, callErr := worker.api.resume.Call(uintptr(worker.process.Thread))
	if resumed != 1 {
		t.Fatal(nativeError("fresh native Limited worker initial resume", callErr))
	}
	if err := worker.wait(70 * time.Second); err != nil {
		t.Fatal("fresh native Limited/Full workers did not join", err, worker.output())
	}
	// The Limited worker may fail because an original case in its actual
	// runas Full child failed. Read both retained, bounded reports before
	// rejecting its exit status so the native cause remains observable.
	// Diagnostic output does not establish Full retirement or permit cleanup.
	fullOutput, err := io.ReadAll(io.LimitReader(fullReport, 1<<20))
	if err != nil || len(fullOutput) == 1<<20 {
		t.Fatal("fresh Full report has no bounded completed output", err)
	}
	output := worker.output() + "\n" + string(fullOutput)
	var exit uint32
	if err := syscall.GetExitCodeProcess(worker.process.Process, &exit); err != nil || exit != 0 {
		t.Fatalf("fresh native Limited worker failed (exit=%d): %v\n%s", exit, err, output)
	}
	for _, marker := range []string{"Fresh interactive UAC limited worker receipt: " + receipt.Nonce, "Fresh interactive UAC full worker receipt: " + receipt.Nonce, "Normal runas retained the genuine Limited/Full pair", "--- PASS: " + fixtureFreshUACName + " (", "--- PASS: " + fixtureFreshUACName + "/retained-limited-parent (", "--- PASS: " + fixtureFreshUACName + "/linked-limited-access (", "--- PASS: " + fixtureFreshUACName + "/cancelled-uac (", "--- PASS: " + fixtureFreshUACName + "/replacement-image (", "--- PASS: " + fixtureFreshUACName + "/missing-callback (", "--- PASS: " + fixtureFreshUACName + "/cancelled-suspended-owner ("} {
		if !strings.Contains(output, marker) {
			t.Fatal("fresh native UAC worker did not execute a required original case", marker, output)
		}
	}
	if strings.Contains(output, "--- SKIP:") || strings.Contains(output, "DATA RACE") || strings.Contains(output, "--- FAIL:") {
		t.Fatal("fresh UAC worker did not establish all required native results", output)
	}
	fullJoined = true // Exact Limited owner waited for its actual Shell Full process.
	t.Log(output)
	if err := closeAll(); err != nil {
		t.Fatal("fresh UAC worker cleanup did not join", err)
	}
	t.Log("Fresh Limited worker, runas Full worker and their exact descendants joined; original caller token and UAC policies remain unchanged. A displayed consent prompt, cross-account product and GLOBALROOT acceptance remain separate.")
}

func fixtureFreshUACDOSImage(api *nativeAPI, image *Image) (string, error) {
	image.mu.Lock()
	defer image.mu.Unlock()
	if image.closed || len(image.handles) == 0 {
		return "", ErrClosed
	}
	buffer := make([]uint16, 32768)
	length, _, callErr := api.finalPath.Call(uintptr(image.handles[len(image.handles)-1]), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0)
	if length == 0 || length >= uintptr(len(buffer)) {
		return "", nativeError("fresh UAC original DOS image spelling", callErr)
	}
	return localExecutablePath(strings.TrimPrefix(syscall.UTF16ToString(buffer[:length]), `\\?\`))
}

func fixtureFreshUACReport(api *nativeAPI, dispose *syscall.Proc, path, sid string, limitedWrite bool) (*fixtureMediumImage, *os.File, error) {
	owner := &fixtureMediumImage{native: api, dispose: dispose}
	access := "FR"
	if limitedWrite {
		access = "FRFW"
	}
	sddl, _ := syscall.UTF16PtrFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;" + access + ";;;" + sid + ")S:(ML;;NW;;;ME)")
	var descriptor unsafe.Pointer
	ok, _, callErr := api.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if descriptor != nil {
		defer api.localFree.Call(uintptr(descriptor))
	}
	if ok == 0 || descriptor == nil {
		return owner, nil, nativeError("fresh UAC private report descriptor", callErr)
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(descriptor)}
	name, _ := syscall.UTF16PtrFromString(path)
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		&attributes, syscall.CREATE_NEW, 0x00200000, 0)
	runtime.KeepAlive(sddl)
	runtime.KeepAlive(name)
	runtime.KeepAlive(attributes)
	if err != nil {
		return owner, nil, err
	}
	owner.file = handle
	read, err := owner.open(handle, syscall.GENERIC_READ, 0x00200000)
	if err != nil {
		return owner, nil, err
	}
	return owner, os.NewFile(uintptr(read), "captured-fresh-uac-report"), nil
}

func fixtureFreshUACDesktop(t *testing.T, api *fixtureRestrictedAPI, sid string) (string, func() error) {
	t.Helper()
	library, err := syscall.LoadDLL(filepath.Join(api.native.systemDirectory, "user32.dll"))
	if err != nil {
		t.Fatal(err)
	}
	var station, desktop uintptr
	names := []string{"CreateWindowStationW", "CloseWindowStation", "GetProcessWindowStation", "SetProcessWindowStation", "CreateDesktopW", "CloseDesktop", "GetUserObjectSecurity"}
	procedures := make([]*syscall.Proc, len(names))
	for index, name := range names {
		procedures[index], err = library.FindProc(name)
		if err != nil {
			_ = library.Release()
			t.Fatal(err)
		}
	}
	closed := false
	closeAll := func() error {
		if closed {
			return nil
		}
		if desktop != 0 {
			if ok, _, err := procedures[5].Call(desktop); ok == 0 {
				return nativeError("fresh UAC private desktop close", err)
			}
			desktop = 0
		}
		if station != 0 {
			if ok, _, err := procedures[1].Call(station); ok == 0 {
				return nativeError("fresh UAC private station close", err)
			}
			station = 0
		}
		if err := library.Release(); err != nil {
			return err
		}
		closed = true
		return nil
	}
	transferred := false
	t.Cleanup(func() {
		if !transferred {
			if err := closeAll(); err != nil {
				t.Error(err)
			}
		}
	})
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	stationName := "RouterVPN-FreshUAC-" + hex.EncodeToString(nonce[:])
	stationText, _ := syscall.UTF16PtrFromString(stationName)
	desktopText, _ := syscall.UTF16PtrFromString("default")
	// This is a newly created private fixture desktop. Grant its exact captured
	// fresh user access without changing the shared interactive desktop ACL.
	sddl, _ := syscall.UTF16PtrFromString("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + sid + ")S:(ML;;NW;;;ME)")
	var descriptor unsafe.Pointer
	ok, _, callErr := api.native.convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if descriptor != nil {
		defer api.native.localFree.Call(uintptr(descriptor))
	}
	if ok == 0 || descriptor == nil {
		t.Fatal(nativeError("fresh UAC private USER descriptor", callErr))
	}
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(descriptor)}
	runtime.LockOSThread()
	old, _, callErr := procedures[2].Call()
	if old == 0 {
		runtime.UnlockOSThread()
		t.Fatal(nativeError("fresh UAC original station capture", callErr))
	}
	defer func() {
		ok, _, callErr := procedures[3].Call(old)
		actual, _, readErr := procedures[2].Call()
		if ok == 0 || actual != old {
			t.Error("fresh UAC fixture did not restore its original station selection", callErr, readErr)
			return
		}
		runtime.UnlockOSThread()
	}()
	station, _, callErr = procedures[0].Call(uintptr(unsafe.Pointer(stationText)), 1 /* CWF_CREATE_ONLY */, 0x000f037f, uintptr(unsafe.Pointer(&attributes)))
	if station == 0 {
		t.Fatal(nativeError("fresh UAC owned private station creation", callErr))
	}
	ok, _, callErr = procedures[3].Call(station)
	if ok == 0 {
		t.Fatal(nativeError("fresh UAC private station selection", callErr))
	}
	desktop, _, callErr = procedures[4].Call(uintptr(unsafe.Pointer(desktopText)), 0, 0, 0, 0x000f01ff, uintptr(unsafe.Pointer(&attributes)))
	runtime.KeepAlive(stationText)
	runtime.KeepAlive(desktopText)
	runtime.KeepAlive(sddl)
	runtime.KeepAlive(attributes)
	if desktop == 0 {
		t.Fatal(nativeError("fresh UAC owned private desktop creation", callErr))
	}
	fixtureVerifyMediumUserObjectPrincipals(t, procedures[6], station, "S-1-5-32-544", 0x000f037f, sid)
	fixtureVerifyMediumUserObjectPrincipals(t, procedures[6], desktop, "S-1-5-32-544", 0x000f01ff, sid)
	transferred = true
	return stationName + `\default`, closeAll
}
