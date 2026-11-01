//go:build !windows

package prober

import (
	"fmt"
	"os"
	"syscall"
)

// openTrustedFile opens a file read-only without following a symlink and
// without blocking on a FIFO. O_NONBLOCK is load-bearing: a FIFO with no
// writer would otherwise sleep in the kernel forever, inside a reload
// supervisor or the metrics reloader mutex.
func openTrustedFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// checkTrustedOwner refuses a file owned by another local account: the owner
// keeps implicit WRITE_DAC (and can chmod), so a mode repair or a DACL
// restriction can always be undone by that account.
func checkTrustedOwner(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("is owned by uid %d, not root or this process", st.Uid)
	}
	return nil
}
