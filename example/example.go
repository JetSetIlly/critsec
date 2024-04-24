package main

import (
	"github.com/jetsetilly/critsec/crit"
)

// a crit.Section derived type. access to fields in this type will trigger
// critcheck reports unless the access is protected by a lease
type critSectionExample struct {
	crit.Section
	value int
}

// a normal type for comparison purposes
type nonCriticalExample struct {
	value int
}

// this function is never called, so even though it accepts a crit.Section
// derived type as a parameter, it should not appear in the analysis report
func unused(c *critSectionExample) {
	c.value = -1
}

// this function is called and so should trigger a critcheck report about the
// use of a crit.Section derived type as a parameter
func used(c *critSectionExample) {
	c.value = -1
}

func main() {
	var C critSectionExample
	var N nonCriticalExample

	go func() {
		C.Lease(func() error {
			for i := 0; i < 1000; i++ {
				C.value = 1
				_ = C.value
			}
			return nil
		})
	}()

	go func() {
		for i := 0; i < 1000; i++ {
			C.value = 2
		}
	}()

	// this is fine because bar is not a crit.Section type
	N.value = 3

	// deliberate critical section violations
	C.value = 4
	_ = C.value

	// passing a crit.Section derived type
	used(&C)

	// call subtask otherwise it won't be included in an analysis report
	subtask()
}

// subtask() declares another instance of critSectionExample, which isn't allowed
func subtask() {
	var D critSectionExample

	D.Lease(func() error {
		D.value = 5
		return nil
	})
}

// like subtask() but not called. this means that any violations in it should
// not be included in an analysis report
func unusedSubtask() {
	var E critSectionExample

	E.Lease(func() error {
		E.value = 5
		return nil
	})
}
