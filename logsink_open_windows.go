//go:build windows

package main

import "os"

// openLogFileForRepair opens an existing log file for append.
func openLogFileForRepair(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
}

// createLogFile creates the log file exclusive-or-fails so a raced-in
// reparse point or FIFO is never adopted.
func createLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
}
