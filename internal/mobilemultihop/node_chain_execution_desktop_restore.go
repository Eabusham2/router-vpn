package mobilemultihop

// NewDesktopNodeChainExecutionRestoreRuntime admits a newly sealed physical
// session without changing the captured logical source, execution choice or
// probe target. The platform must first join the old native Box/TUN and derive
// restored MTU from its original readback; shared runtime cleanup proves only
// its own proof/control/remote owners. This method accepts no caller hash.
func NewDesktopNodeChainExecutionRestoreRuntime(capture NodeChainExecutionRestoreCapture, projection *NodeChainExecutionProjection, engine NodeChainExecutionEngine) (*NodeChainExecutionRuntime, error) {
	if capture.projection.validateCapture() != nil || projection.validateCapture() != nil ||
		capture.projection.Source() != projection.Source() || capture.projection.SourceSHA256() != projection.SourceSHA256() ||
		capture.projection.Execution() != projection.Execution() {
		return nil, nodeChainExecutionError
	}
	previous, err := capture.projection.DesktopPhysicalPolicy()
	if err != nil {
		return nil, err
	}
	next, err := projection.DesktopPhysicalPolicy()
	if err != nil || previous == next {
		return nil, nodeChainExecutionError
	}
	oldMeta, newMeta := previous.original.Metadata(), next.original.Metadata()
	if oldMeta.TargetOS != newMeta.TargetOS || oldMeta.SessionID == newMeta.SessionID ||
		oldMeta.OriginalSourceSHA256 != newMeta.OriginalSourceSHA256 || oldMeta.OriginalCaptureSHA256 != newMeta.OriginalCaptureSHA256 {
		return nil, nodeChainExecutionError
	}
	runtime, err := NewNodeChainExecutionRestoreRuntime(capture, engine)
	if err != nil {
		return nil, err
	}
	// The constructor above retains positive original cleanup and the complete
	// immutable restore result. Only this unopened runtime's actual physical
	// projection changes; Run still requires a fresh EngineID and SessionID.
	runtime.projection = projection
	return runtime, nil
}
