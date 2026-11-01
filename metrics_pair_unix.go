//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// openPairFile opens a metrics TLS file read-only without following a
// symlink and without blocking on a FIFO. O_NONBLOCK is load-bearing: a FIFO
// at the key path with no writer would otherwise sleep in the kernel forever,
// inside the reloader mutex that serialises every handshake.
func openPairFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// checkPairOwner refuses a TLS file owned by another local account: the owner
// keeps implicit WRITE_DAC, so a "repaired" mode can always be re-widened.
func checkPairOwner(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("owned by uid %d, not root or this process", st.Uid)
	}
	return nil
}
