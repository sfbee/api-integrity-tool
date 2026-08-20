//go:build !unix

package store

// lock is a no-op on platforms without flock. Single-process use is still safe
// because Store.mu serializes writers within the process; concurrent use from
// several processes is not protected, which the doctor command reports.
func (s *Store) lock(shared bool) (func(), error) {
	return func() {}, nil
}
