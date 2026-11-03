package macosprocess

// Identity is read from the actual main image across a PID and exec fence.
// It is not a process handle and cannot authorize reopening a saved PID.
type Identity struct {
	PID                             int
	StartSeconds, StartMicroseconds uint64
	UniqueID                        uint64
	IDVersion                       int32
	UUID                            [16]byte
	CodeHash                        [20]byte
}

func (i Identity) Valid() bool {
	return i.PID > 1 && i.PID < 1<<31 && i.StartSeconds != 0 && i.StartMicroseconds < 1000000 && i.UniqueID != 0 && i.IDVersion > 0 && i.CodeHash != [20]byte{}
}

func (i Identity) Matches(image Image) bool {
	if !i.Valid() || image.SHA256 == [32]byte{} {
		return false
	}
	for _, slice := range image.Slices {
		if slice.UUID == i.UUID {
			for _, hash := range slice.CodeHashes {
				if hash == i.CodeHash {
					return true
				}
			}
		}
	}
	return false
}
