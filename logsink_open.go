//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// openLogFileForRepair opens an existing log file without following a
// symlink and without blocking on a FIFO. O_NONBLOCK is load-bearing: a FIFO
// planted at -log-file with no reader makes a plain O_WRONLY open sleep in
// the kernel forever, before any post-open type check could run. With
// O_NONBLOCK the open of a reader-less FIFO fails with ENXIO instead.
func openLogFileForRepair(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
}

// createLogFile creates the log file exclusive-or-fails: O_EXCL means a
// symlink or FIFO raced into place since the Lstat is never adopted.
func createLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
}

// checkLogFileOwner refuses a log file owned by another local account. The
// mode repair cannot fix ownership: an owner keeps implicit WRITE_DAC and can
// re-widen the file after the repair, which is the exact redirect
// hardenLogSink exists to prevent.
func checkLogFileOwner(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("log file is owned by uid %d, not root or this process: another local account could re-widen it", st.Uid)
	}
	return nil
}
