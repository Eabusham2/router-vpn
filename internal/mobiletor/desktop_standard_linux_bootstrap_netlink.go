//go:build linux

package mobiletor

import (
	"context"
	"encoding/binary"
	"errors"
	"syscall"
)

const desktopLinuxNFTDeleteRule = 0x0a08

// The generation comes from the original creator's complete, bracketed table
// inventory. Names only locate that already-proved object within the atomic
// changeset; they cannot supply authority or recover an unacknowledged grant.
// Linux UAPI: NFTA_RULE_TABLE=1, NFTA_RULE_CHAIN=2, NFTA_RULE_HANDLE=3, and
// NFNL_BATCH_GENID=1. See docs.kernel.org/netlink/specs/nftables.html.
func desktopLinuxBootstrapDeleteRequests(generation uint32, table string, handle uint64, seq, port uint32) ([3][]byte, error) {
	if generation == 0 || !desktopLinuxOwnedTableName(table) || handle == 0 || handle > 1<<53-1 || seq == 0 || seq > ^uint32(0)-2 || port == 0 {
		return [3][]byte{}, errors.New("bootstrap deletion requires its exact original table, rule and generation")
	}
	var gen [4]byte
	binary.BigEndian.PutUint32(gen[:], generation)
	var object [8]byte
	binary.BigEndian.PutUint64(object[:], handle)
	attributes := desktopLinuxBaselineAttribute(1, append([]byte(table), 0))
	attributes = append(attributes, desktopLinuxBaselineAttribute(2, []byte("output\x00"))...)
	attributes = append(attributes, desktopLinuxBaselineAttribute(3, object[:])...)
	return [3][]byte{
		desktopLinuxBaselineMessage(desktopLinuxNFTBatchBegin, syscall.NLM_F_REQUEST, seq, port, 0, desktopLinuxNFTSubsystem, desktopLinuxBaselineAttribute(1, gen[:])),
		desktopLinuxBaselineMessage(desktopLinuxNFTDeleteRule, syscall.NLM_F_REQUEST, seq+1, port, desktopLinuxNFTInet, 0, attributes),
		desktopLinuxBaselineMessage(desktopLinuxNFTBatchEnd, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, seq+2, port, 0, desktopLinuxNFTSubsystem, nil),
	}, nil
}

// deleteBootstrapRule uses the same retained native endpoint and strict commit
// receipt as baseline retirement. A concurrent ruleset change rejects the whole
// transaction. A lost or malformed acknowledgement retains the uncertain owner;
// it never authorizes a second send or deletion of a matching replacement.
func (n *desktopLinuxBaselineNetlink) deleteBootstrapRule(ctx context.Context, generation uint32, table string, handle uint64) (acknowledged, sent bool, failure error) {
	if n == nil {
		return false, false, errors.New("bootstrap deletion lost its original native endpoint")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	seq, err := n.nextSequence()
	if err != nil {
		return false, false, err
	}
	requests, err := desktopLinuxBootstrapDeleteRequests(generation, table, handle, seq, n.port)
	if err != nil {
		return false, false, err
	}
	request := append(append(append([]byte{}, requests[0]...), requests[1]...), requests[2]...)
	reply, sent, err := n.exchange(ctx, request, seq, seq+1, seq+2)
	if reply == nil {
		return false, sent, err
	}
	acknowledged, receiptErr := n.deleteReceipt(reply, requests)
	return acknowledged, sent, errors.Join(err, receiptErr)
}
