//go:build !windows

package main

import (
	"os"
	"syscall"
)

// openLogFileForRepair opens an existing log file without following a
// symlink and without blocking on a FIFO.
func openLogFileForRepair(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
}

// createLogFile creates the log file exclusive-or-fails so a raced-in symlink
// or FIFO is never adopted.
func createLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
}
