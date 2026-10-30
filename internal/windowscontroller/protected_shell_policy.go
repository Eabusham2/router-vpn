package windowscontroller

// Object Manager directory rights differ from filesystem directory rights.
// A symbolic link permits query (1); a directory permits query/traverse (3).
// READ_CONTROL and SYNCHRONIZE are non-mutating standard rights. Reject generic
// or unknown effective grants rather than applying a file's generic mapping.
func validateProtectedShellDescriptor(data []byte, directory bool) error {
	readOnly := uint32(0x00120001)
	if directory {
		readOnly |= 2
	}
	return validateSystemObjectDescriptor(data, readOnly)
}
