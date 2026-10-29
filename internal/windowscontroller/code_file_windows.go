//go:build windows

package windowscontroller

// CodeFile retains a packaged script, assembly or other code input and its
// resolved local-volume ancestry. It denies writes/deletion of the file and
// renames of its ancestors until its owner closes it. It is deliberately not an
// Image: pinning data does not authorize it as a process executable.
type CodeFile struct {
	image *Image
}

func PinFile(path string) (*CodeFile, error) {
	image, err := pinPackageObject(path, false, localPackageFilePath)
	if err != nil {
		return nil, err
	}
	return &CodeFile{image: image}, nil
}

func (file *CodeFile) Path() string {
	if file == nil || file.image == nil {
		return ""
	}
	return file.image.Path()
}

func (file *CodeFile) Close() error {
	if file == nil || file.image == nil {
		return nil
	}
	return file.image.Close()
}
