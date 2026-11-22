package filetrust

import (
	"fmt"
	"io"
	"os"
)

// VerifyExistingRegular opens an existing path through a symlink/non-regular/SameFile/owner
// provenance chain, binding all checks to the returned open descriptor.
// If maxBytes > 0, files larger than maxBytes are refused before reading.
func VerifyExistingRegular(path string, maxBytes int64, open func(string) (*os.File, error)) (*os.File, os.FileInfo, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("refusing symlinked file %q: a symlink lets another local user repoint it", path)
	}
	if !li.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("refusing non-regular file %q (%s): only a regular file may be used", path, li.Mode().Type())
	}
	if maxBytes > 0 && li.Size() > maxBytes {
		return nil, nil, fmt.Errorf("file %q is too large (%d bytes, max %d)", path, li.Size(), maxBytes)
	}
	f, err := open(path)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("refusing non-regular file %q (%s): only a regular file may be used", path, fi.Mode().Type())
	}
	if !os.SameFile(li, fi) {
		f.Close()
		return nil, nil, fmt.Errorf("file %q changed between check and open; refusing", path)
	}
	if err := CheckOwner(f); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("file %q %w", path, err)
	}
	return f, fi, nil
}

// ReadFile reads an operator-supplied file using default trust checks (regular,
// non-symlink, SameFile, trusted owner, bounded size).
func ReadFile(path string, maxBytes int64) ([]byte, os.FileInfo, error) {
	return ReadFileWith(path, maxBytes, TrustOptions{})
}

// ReadFileWith reads an operator-supplied file enforcing TrustOptions (Windows
// DACL read/write restrictions) in addition to the standard provenance chain.
func ReadFileWith(path string, maxBytes int64, opts TrustOptions) ([]byte, os.FileInfo, error) {
	f, fi, err := VerifyExistingRegular(path, maxBytes, openTrustedFile)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	if err := checkTrustedDACL(f, opts); err != nil {
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
