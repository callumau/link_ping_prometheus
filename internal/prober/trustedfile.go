package prober

import (
	"fmt"
	"io"
	"os"
)

// ReadTrustedFile reads an operator-supplied file with the provenance rule the
// targets file, the log sink and the metrics TLS pair all rely on: the object
// must be a regular, non-symlink file owned by root or this process, and the
// decision must be bound to the descriptor that is actually read rather than to
// a path that can be swapped between check and use.
//
// The open is non-blocking on unix because a FIFO (or a device) at the path
// would otherwise sleep in open(2) forever; the type check refuses it either
// way. On Windows the DACL is the control and the owner check compares SIDs.
//
// The returned FileInfo describes the verified descriptor, so a caller can add
// its own mode rule (LoadTargets refuses group/world-writable; the metrics TLS
// key may not be readable by others).
func ReadTrustedFile(path string, maxBytes int64) ([]byte, os.FileInfo, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("refusing symlinked file %q: a symlink lets another local user repoint it", path)
	}
	if !li.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("refusing non-regular file %q (%s): only a regular file may be read", path, li.Mode().Type())
	}
	if li.Size() > maxBytes {
		return nil, nil, fmt.Errorf("file %q is too large (%d bytes, max %d)", path, li.Size(), maxBytes)
	}
	f, err := openTrustedFile(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(li, fi) {
		return nil, nil, fmt.Errorf("file %q changed between check and open; refusing", path)
	}
	if err := checkTrustedOwner(f); err != nil {
		return nil, nil, fmt.Errorf("file %q %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, nil, fmt.Errorf("file %q grew past its limit while reading (max %d)", path, maxBytes)
	}
	return data, fi, nil
}
