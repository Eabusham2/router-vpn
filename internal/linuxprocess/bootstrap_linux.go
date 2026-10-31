//go:build linux

package linuxprocess

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
)

type bootstrapMessage struct {
	Schema        int    `json:"schema"`
	Kind          string `json:"kind"`
	Step          string `json:"step"`
	CaptureSHA256 string `json:"capture_sha256"`
	Challenge     string `json:"challenge"`
	ParentSHA256  string `json:"parent_sha256"`
	ChildSHA256   string `json:"child_sha256"`
	ChildChannel  Object `json:"child_channel"`
}

// Bootstrap retains an authenticated inherited connection and the actual
// native task witnesses. It authorizes neither a firewall mutation nor a
// durable journal acknowledgment; the caller still owns its captured policy,
// original controller lifetime, created command, and journal transaction.
type Bootstrap struct {
	gate          chan struct{}
	channel       *Channel
	parent        *Witness
	borrowParent  bool
	self          *Witness
	child         *CreatedWitness
	pending       *Packet
	file          *os.File
	pidfd         *os.File
	parentRecord  Observation
	childRecord   Observation
	captureSHA256 string
	peerPID       int
	complete      bool
	revoked       bool
	closed        bool
	closeErr      error
}

func digest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value && value != string(bytes.Repeat([]byte{'0'}, 64))
}

func observationHash(value Observation) string {
	body, _ := json.Marshal(value)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func encodeBootstrap(message bootstrapMessage) ([]byte, error) {
	if message.Schema != 1 || message.Kind != "routervpn-linux-child-bootstrap-v1" ||
		!digest(message.CaptureSHA256) || !digest(message.Challenge) || !digest(message.ParentSHA256) || !socketObject(message.ChildChannel) ||
		(message.Step == "parent" && message.ChildSHA256 != "") ||
		(message.Step != "parent" && !digest(message.ChildSHA256)) ||
		(message.Step != "parent" && message.Step != "child" && message.Step != "accepted") {
		return nil, errors.New("Linux child bootstrap has an invalid captured message")
	}
	return json.Marshal(message)
}

func decodeBootstrap(body []byte) (bootstrapMessage, error) {
	var message bootstrapMessage
	if len(body) == 0 || len(body) > 2048 {
		return message, errors.New("Linux child bootstrap exceeds its native message bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&message); err != nil {
		return message, err
	}
	canonical, err := encodeBootstrap(message)
	if err != nil || !bytes.Equal(body, canonical) {
		return message, errors.Join(err, errors.New("Linux child bootstrap is not its exact canonical captured message"))
	}
	return message, nil
}

// BindCreatedChild consumes channel and clonePIDFD on every result. parent is
// borrowed from the original installed controller; it is never closed here.
// childPID comes directly from the successful Start, and image from its pinned
// executable. No decoded message supplies these native creation constraints.
func BindCreatedChild(ctx context.Context, channel *Channel, parent *Witness, clonePIDFD *os.File,
	childPID int, image Object, captureSHA256 string) (*Bootstrap, error) {
	b := &Bootstrap{gate: readyGate(), channel: channel, parent: parent, borrowParent: true,
		pidfd: clonePIDFD, peerPID: childPID, captureSHA256: captureSHA256}
	if ctx == nil || ctx.Err() != nil || channel == nil || !channel.createdPair || parent == nil || clonePIDFD == nil || childPID < 1 || !digest(captureSHA256) {
		return b, errors.New("Linux child bootstrap requires its complete original launch")
	}
	var err error
	b.parentRecord, err = parent.Current(ctx)
	if err != nil || channel.CreatorPID() != b.parentRecord.ProcessID || childPID == b.parentRecord.ProcessID {
		return b, errors.Join(err, errors.New("Linux child bootstrap lost its original pair creator"))
	}
	if _, err := channel.currentIdentity(); err != nil {
		return b, err
	}
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return b, err
	}
	message := bootstrapMessage{Schema: 1, Kind: "routervpn-linux-child-bootstrap-v1", Step: "parent",
		CaptureSHA256: captureSHA256, Challenge: hex.EncodeToString(challenge[:]), ParentSHA256: observationHash(b.parentRecord), ChildChannel: channel.peerIdentity}
	body, err := encodeBootstrap(message)
	if err != nil {
		return b, err
	}
	if err := channel.Send(ctx, body, nil); err != nil {
		return b, err
	}
	b.pending, err = channel.Receive(ctx, childPID, true)
	if err != nil {
		return b, err
	}
	reply, err := decodeBootstrap(b.pending.Payload)
	if err != nil || reply.Step != "child" || reply.CaptureSHA256 != message.CaptureSHA256 ||
		reply.Challenge != message.Challenge || reply.ParentSHA256 != message.ParentSHA256 || reply.ChildChannel != message.ChildChannel {
		return b, errors.Join(err, errors.New("Linux child bootstrap did not answer its exact original challenge"))
	}
	directory, err := b.pending.TakeFile()
	if err != nil {
		return b, err
	}
	// CaptureDirectory consumes the transferred descriptor even on error.
	task, taskErr := CaptureDirectory(ctx, directory, childPID)
	// CaptureCreated likewise retains both partial owners. Never discard one
	// because construction or the following comparison failed.
	b.child, err = CaptureCreated(ctx, b.pidfd, task, b.parent, image)
	b.pidfd = nil
	if taskErr != nil || err != nil {
		return b, errors.Join(taskErr, err)
	}
	b.childRecord, err = b.child.Current(ctx)
	if err != nil || reply.ChildSHA256 != observationHash(b.childRecord) {
		return b, errors.Join(err, errors.New("Linux child bootstrap changed its actual created task"))
	}
	if err := b.closePacket(); err != nil {
		return b, err
	}
	if actual, err := parent.Current(ctx); err != nil || actual != b.parentRecord {
		return b, errors.Join(err, errors.New("Linux child bootstrap lost its original parent before acknowledgment"))
	}
	reply.Step = "accepted"
	body, err = encodeBootstrap(reply)
	if err != nil {
		return b, err
	}
	if err := channel.Send(ctx, body, nil); err != nil {
		return b, err
	}
	if _, err := b.child.Current(ctx); err != nil {
		return b, err
	}
	if actual, err := parent.Current(ctx); err != nil || actual != b.parentRecord || ctx.Err() != nil {
		return b, errors.Join(err, ctx.Err(), errors.New("Linux child bootstrap changed during its acknowledgment"))
	}
	b.complete = true
	return b, nil
}

// BindInheritedParent consumes the child's original channel and inherited
// parent task directory. It must finish before the child reads private node
// inputs. The parent PID is read from the pair's native creator, then checked
// against that retained directory and each message's SCM credentials.
func BindInheritedParent(ctx context.Context, channel *Channel, parentDirectory *os.File, captureSHA256 string) (*Bootstrap, error) {
	b := &Bootstrap{gate: readyGate(), channel: channel, file: parentDirectory, captureSHA256: captureSHA256}
	if ctx == nil || ctx.Err() != nil || channel == nil || parentDirectory == nil || !digest(captureSHA256) {
		return b, errors.New("Linux child requires its original inherited parent capture")
	}
	b.peerPID = channel.CreatorPID()
	var err error
	b.parent, err = CaptureDirectory(ctx, b.file, b.peerPID)
	b.file = nil
	if err != nil {
		return b, err
	}
	b.parentRecord, err = b.parent.Current(ctx)
	if err != nil {
		return b, err
	}
	b.self, err = CaptureSelf(ctx)
	if err != nil {
		return b, err
	}
	b.childRecord, err = b.self.Current(ctx)
	if err != nil || b.childRecord.ProcessID == b.parentRecord.ProcessID ||
		b.childRecord.ProcParentID != b.parentRecord.ProcProcessID || b.childRecord.BootID != b.parentRecord.BootID ||
		b.childRecord.NetworkNamespace != b.parentRecord.NetworkNamespace || b.childRecord.PIDNamespace != b.parentRecord.PIDNamespace {
		return b, errors.Join(err, errors.New("Linux child changed the original parent or namespaces before authentication"))
	}
	b.pending, err = channel.Receive(ctx, b.peerPID, false)
	if err != nil {
		return b, err
	}
	message, err := decodeBootstrap(b.pending.Payload)
	channelIdentity, channelErr := channel.currentIdentity()
	if err != nil || channelErr != nil || message.Step != "parent" || message.CaptureSHA256 != captureSHA256 ||
		message.ParentSHA256 != observationHash(b.parentRecord) || message.ChildChannel != channelIdentity {
		return b, errors.Join(err, channelErr, errors.New("Linux child received a foreign original parent challenge"))
	}
	if err := b.closePacket(); err != nil {
		return b, err
	}
	b.file, err = b.self.DuplicateDirectory(ctx)
	if err != nil {
		return b, err
	}
	message.Step, message.ChildSHA256 = "child", observationHash(b.childRecord)
	body, err := encodeBootstrap(message)
	if err != nil {
		return b, err
	}
	if err := channel.Send(ctx, body, b.file); err != nil {
		return b, err
	}
	if err := b.closeFile(); err != nil {
		return b, err
	}
	b.pending, err = channel.Receive(ctx, b.peerPID, false)
	if err != nil {
		return b, err
	}
	reply, err := decodeBootstrap(b.pending.Payload)
	message.Step = "accepted"
	if err != nil || reply != message {
		return b, errors.Join(err, errors.New("Linux child did not receive its exact native parent acknowledgment"))
	}
	if err := b.closePacket(); err != nil {
		return b, err
	}
	if actual, err := b.parent.Current(ctx); err != nil || actual != b.parentRecord {
		return b, errors.Join(err, errors.New("Linux child lost its retained parent after acknowledgment"))
	}
	if actual, err := b.self.Current(ctx); err != nil || actual != b.childRecord || ctx.Err() != nil {
		return b, errors.Join(err, ctx.Err(), errors.New("Linux child changed its native task during acknowledgment"))
	}
	b.complete = true
	return b, nil
}

func (b *Bootstrap) closePacket() error {
	if b.pending != nil {
		if err := b.pending.Close(); err != nil {
			return err
		}
		b.pending = nil
	}
	return nil
}

func (b *Bootstrap) closeFile() error {
	if b.file != nil {
		if err := b.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			b.closeErr = errors.Join(b.closeErr, err)
			return err
		}
		b.file = nil
	}
	return b.closeErr
}

func (b *Bootstrap) enter(ctx context.Context) error {
	if b == nil || ctx == nil || b.gate == nil {
		return errors.New("Linux child bootstrap has no captured native owner")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.gate:
		return nil
	}
}

func (b *Bootstrap) current(ctx context.Context) error {
	if ctx.Err() != nil || !b.complete || b.revoked || b.closed || b.parent == nil || b.pending != nil || b.channel == nil || b.channel.stopping.Load() {
		return errors.Join(ctx.Err(), errors.New("Linux child bootstrap is incomplete or retired"))
	}
	if _, err := b.channel.currentIdentity(); err != nil {
		b.revoked = true
		return err
	}
	parent, err := b.parent.Current(ctx)
	if err != nil || parent != b.parentRecord {
		b.revoked = true
		return errors.Join(err, errors.New("Linux child bootstrap lost its original captured parent"))
	}
	var child Observation
	if b.borrowParent {
		child, err = b.child.Current(ctx)
	} else {
		child, err = b.self.Current(ctx)
	}
	if err != nil || child != b.childRecord {
		b.revoked = true
		return errors.Join(err, errors.New("Linux child bootstrap lost its original created child"))
	}
	return ctx.Err()
}

func (b *Bootstrap) Current(ctx context.Context) error {
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	return b.current(ctx)
}

// Send and Receive preserve the original process proof around each real native
// frame. Their bytes are still only a transport: native admission and durable
// settlement require the caller's independent exact captured policy checks.
func (b *Bootstrap) Send(ctx context.Context, body []byte) error {
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if err := b.current(ctx); err != nil {
		return err
	}
	if err := b.channel.Send(ctx, body, nil); err != nil {
		b.revoked = true
		return err
	}
	return b.current(ctx)
}

func (b *Bootstrap) Receive(ctx context.Context) ([]byte, error) {
	if err := b.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { b.gate <- struct{}{} }()
	if err := b.current(ctx); err != nil {
		return nil, err
	}
	var err error
	b.pending, err = b.channel.Receive(ctx, b.peerPID, false)
	if err != nil {
		b.revoked = true
		return nil, err
	}
	body := append([]byte(nil), b.pending.Payload...)
	if err := b.closePacket(); err != nil {
		b.revoked = true
		return body, err
	}
	return body, b.current(ctx)
}

// Close interrupts the inherited channel first and joins entered operations.
// It never closes the parent's borrowed process witness, signals the child,
// normalizes a failed native Close, or claims native policy retirement.
func (b *Bootstrap) Close(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if b.channel != nil {
		if err := b.channel.Close(ctx); err != nil {
			return err
		}
	}
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	b.revoked = true
	if err := b.closePacket(); err != nil {
		return err
	}
	if err := b.closeFile(); err != nil {
		return err
	}
	if b.child != nil {
		if err := b.child.Close(ctx); err != nil {
			return err
		}
		b.child = nil
	}
	if b.pidfd != nil {
		if err := b.pidfd.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			b.closeErr = errors.Join(b.closeErr, err)
			return err
		}
		b.pidfd = nil
	}
	for _, witness := range []**Witness{&b.self, &b.parent} {
		if witness == &b.parent && b.borrowParent {
			continue
		}
		if *witness != nil {
			if err := (*witness).Close(ctx); err != nil {
				return err
			}
			*witness = nil
		}
	}
	if b.closeErr != nil {
		return b.closeErr
	}
	b.closed = true
	return nil
}
