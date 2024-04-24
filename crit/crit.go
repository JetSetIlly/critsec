package crit

import (
	"sync"
)

// Section can be embedded in a struct to indicate that the fields in that
// struct are being accessed in a critical section
type Section struct {
	lock sync.Mutex
}

// Lease locks a critical section for the entire duration of the supplied
// function
func (crit *Section) Lease(f func() error) error {
	crit.lock.Lock()
	defer crit.lock.Unlock()
	return f()
}
