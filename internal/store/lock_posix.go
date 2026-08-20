//go:build unix

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lock takes an advisory lock on a sidecar file. Locking a separate file rather
// than the state file itself means the state can be replaced by rename (which
// would otherwise drop the lock along with the old inode).
//
// The returned function releases the lock and must always be called.
func (s *Store) lock(shared bool) (func(), error) {
	path := filepath.Join(s.dir, lockName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	how := syscall.LOCK_EX
	if shared {
		how = syscall.LOCK_SH
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
