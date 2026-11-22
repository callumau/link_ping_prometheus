//go:build !windows

package filetrust

import (
	"fmt"
	"os"
	"syscall"
)

func openTrustedFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func checkTrustedDACL(*os.File, TrustOptions) error { return nil }

// CheckOwner refuses a file owned by an account other than root or this process,
// because an owner retains implicit permission to widen access later.
func CheckOwner(f *os.File) error {
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
