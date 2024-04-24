# critsec

Proof-of concept for a method of treating critical sections such that they can
be statically analysed for violations.

### Critical Sectioning

In this scheme critical sections are defined by embedding the `crit.Section`
type into a new struct type.

```
type exampleCritSectioning struct {
	crit.Section
	
	a int
	b bool
}
```

Any fields in this new struct type can then only be accessed if the critical
section has been `leased`

```
var A exampleCritSectioning

_ = A.Lease(func() error {
	A.a = 10
	A.b = true
	return nil
})
```

### Limitations

For simplicity and for the purposes of the proof-of-concept there are two
significant restrictions on `crit.Section` usage:

- instances of types derived from `crit.Section` cannot be passed as arguments
  to functions
- only one instance of each `crit.Section` derived type can be declared

To be clear these limitations are enforced by the static analysis and the
`critcheck` driver. They only exist to make the job of Lease enforcment easier
and with more sophisticated parsing of the AST the limitations can most probably
be lifted.

### Static Analysis

The project provides a [static
analyser](https://pkg.go.dev/golang.org/x/tools@v0.20.0/go/analysis) to report critical section violations.

A `critcheck` command is also provided. This is a standalone driver for the
analysis package and will be used for the following demonstration. The
demonstration uses the `example/example.go` program for input.

#### Example output

When run without arguments, as in the example below, the static analysis issues
single line reports with a brief description of the violation.

```
> critcheck example.go
/home/steve/critsec/example/example.go:27:1: crit.Section types cannot be passed to a function
/home/steve/critsec/example/example.go:28:2: assignment to crit.Section without Lease
/home/steve/critsec/example/example.go:47:4: assignment to crit.Section without Lease
/home/steve/critsec/example/example.go:55:2: assignment to crit.Section without Lease
/home/steve/critsec/example/example.go:56:6: access of crit.Section without Lease
/home/steve/critsec/example/example.go:63:6: multiple instance of a crit.Section derived type
```

`critcheck` accepts the standard command line arguments for Go analysis drivers.
For example, the `-c` option instructs the program to print the line of source
that caused the violation and additional lines to provide context.

```
> critcheck -c 1 example.go
/home/steve/critsec/example/example.go:27:1: crit.Section types cannot be passed to a function
26	// use of a crit.Section derived type as a parameter
27	func used(c *critSectionExample) {
28		c.value = -1
/home/steve/critsec/example/example.go:28:2: assignment to crit.Section without Lease
27	func used(c *critSectionExample) {
28		c.value = -1
29	}
/home/steve/critsec/example/example.go:47:4: assignment to crit.Section without Lease
46			for i := 0; i < 1000; i++ {
47				C.value = 2
48			}
/home/steve/critsec/example/example.go:55:2: assignment to crit.Section without Lease
54		// deliberate critical section violations
55		C.value = 4
56		_ = C.value
/home/steve/critsec/example/example.go:56:6: access of crit.Section without Lease
55		C.value = 4
56		_ = C.value
57	
/home/steve/critsec/example/example.go:63:6: multiple instance of a crit.Section derived type
62	func subtask() {
63		var D critSectionExample
64
```

