package main

import "router-vpn/internal/multihoprelay"

// The process gate serializes publication, status and joined retirement. The
// original private policy sealed this HY2 identity before candidate Prepare;
// companion identities never become selected packet key reservations.
func (op *relayNodeChainPrefixCandidateOperation) hysteriaCurrent() bool {
	if op == nil || op.self != op || op.process == nil || op.process.self != op.process {
		return false
	}
	if !op.capture.Request.IsHysteria() {
		return op.hysteria == ""
	}
	return op.process.hysteriaCandidateIdentity != nil && op.hysteria != "" &&
		op.hysteria == op.capture.Request.CandidateHysteriaSHA256 && op.packetKeys == nil && op.pairing == ""
}

func (op *relayNodeChainPrefixCandidateOperation) hysteriaReceiptCurrent(receipt *multihoprelay.NodeChainPrefixCandidateReceipt) bool {
	return receipt != nil && op.hysteriaCurrent() && receipt.HysteriaSHA256 == op.hysteria
}
