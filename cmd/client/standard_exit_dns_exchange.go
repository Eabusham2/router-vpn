package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"router-vpn/internal/common"
	"router-vpn/internal/dnsmeasure"
)

// The caller retains the original process's listening socket throughout this
// exchange. The fixed target is intercepted only by the captured DNS rule;
// there is no resolver lookup or alternate network destination in this client.
func exchangeLegacyStandardDNS(ctx context.Context, endpoint string) error {
	query, err := common.NewDNSProbeQuery(1)
	if err != nil {
		return err
	}
	response, err := exchangeLegacyStandardDNSQuery(ctx, endpoint, query)
	if err != nil {
		return err
	}
	return dnsmeasure.ValidateUsableDNSResponse(query, response)
}

func exchangeLegacyStandardDNSQuery(ctx context.Context, endpoint string, query []byte) (response []byte, failure error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("legacy DNS proof requires a live bounded request")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("legacy DNS proof has no deadline")
	}
	if err := common.ValidateDNSForwardQuery(query); err != nil {
		return nil, err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", endpoint)
	if err != nil {
		return nil, err
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(joined); _ = connection.Close() })
	defer func() {
		if !stop() {
			<-joined
		}
		failure = errors.Join(failure, connection.Close(), ctx.Err())
	}()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	write := func(raw []byte) error { _, err := io.Copy(connection, bytes.NewReader(raw)); return err }
	if err := write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var greeting [2]byte
	if _, err := io.ReadFull(connection, greeting[:]); err != nil {
		return nil, err
	}
	if greeting != [2]byte{5, 0} {
		return nil, errors.New("original DNS proof listener rejected its exact SOCKS method")
	}
	if err := write([]byte{5, 1, 0, 1, 198, 18, 0, 53, 0, 53}); err != nil {
		return nil, err
	}
	var reply [4]byte
	if _, err := io.ReadFull(connection, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return nil, errors.New("original DNS proof listener refused its captured DNS route")
	}
	var addressLength int
	switch reply[3] {
	case 1:
		addressLength = 6
	case 4:
		addressLength = 18
	default:
		return nil, errors.New("DNS proof listener returned an unowned address family")
	}
	if _, err := io.ReadFull(connection, make([]byte, addressLength)); err != nil {
		return nil, err
	}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if err := write(frame); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(connection, size[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	if length < 12 || length > 16*1024 {
		return nil, errors.New("DNS proof response exceeds its exact message bound")
	}
	response = make([]byte, length)
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, err
	}
	return response, ctx.Err()
}
