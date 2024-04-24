package analysis

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"log"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

var CritSection = &analysis.Analyzer{
	Name:     "CritSection",
	Doc:      "check for access of critical sections outside of a lease function",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

// information about the crit package
const (
	critName      = "github.com/jetsetilly/critsec/crit.Section"
	leaseFunction = "Lease"
)

func run(pass *analysis.Pass) (any, error) {
	pcfg := packages.Config{
		Mode: packages.LoadAllSyntax,
		Fset: pass.Fset,
	}
	initial, err := packages.Load(&pcfg, ".")
	if err != nil {
		log.Fatalf(err.Error())
	}

	// create VTA graph. the construct of the graph is important for the
	// checkLease() function, particularly the recursive check() function
	prog, _ := ssautil.AllPackages(initial, ssa.InstantiateGenerics)
	prog.Build()
	funcs := ssautil.AllFunctions(prog)
	graph := vta.CallGraph(funcs, cha.CallGraph(prog))

	for _, f := range pass.Files {
		critSecTypesByName := make(map[string]types.Type)
		critSecTypesUsed := make(map[string]bool)

		// identify crit.Section types
		var newCritSecType types.Type
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				if newCritSecType == nil {
					return true
				}
				critSecTypesByName[n.Name] = newCritSecType
				critSecTypesByName[fmt.Sprintf("*%s", n.Name)] = types.NewPointer(newCritSecType)
				newCritSecType = nil
			case *ast.TypeSpec:
				t, ok := n.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, fld := range t.Fields.List {
					if len(fld.Names) == 0 {
						if s, ok := fld.Type.(*ast.SelectorExpr); ok {
							if pass.TypesInfo.Types[s].Type.String() == critName {
								newCritSecType = pass.TypesInfo.TypeOf(t)
							}
						}
					}
				}
			}
			return true
		})

		// map of inspected tokens. if we've seen one before we ignore it
		inspectedPos := make(map[token.Pos]bool)

		// inspect the AST and match with SelectorExprs and AssignStmts
		inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
		inspect.WithStack(nil, func(n ast.Node, push bool, stack []ast.Node) bool {
			// update inspectedPos map with new token position
			if _, ok := inspectedPos[n.Pos()]; ok {
				return true
			}
			inspectedPos[n.Pos()] = true

			var msg string

			switch m := n.(type) {

			// make sure no crit.Section types are passed as function parameters
			case *ast.FuncDecl:
				if m.Type.Params == nil {
					return true
				}

				// check function is in graph before making any more decisions
				if !isFunctionInGraph(pass, graph, m) {
					return true
				}

				for _, p := range m.Type.Params.List {
					switch e := p.Type.(type) {
					case *ast.StarExpr:
						id, ok := e.X.(*ast.Ident)
						if !ok {
							return true
						}
						if _, ok := critSecTypesByName[id.Name]; ok {
							pass.Reportf(n.Pos(), "crit.Section types cannot be passed to a function")
							return true
						}
					case *ast.Ident:
						id := e
						if _, ok := critSecTypesByName[id.Name]; ok {
							pass.Reportf(n.Pos(), "crit.Section types cannot be passed to a function")
							return true
						}
					}
				}
				return true

			// reading a value from a critical section will begin with a
			// selector expression
			case *ast.SelectorExpr:
				ct := pass.TypesInfo.TypeOf(m.X)

				// check that the node type is one that we're interested in
				var found bool
				for _, c := range critSecTypesByName {
					if types.ConvertibleTo(ct, c) {
						found = true
						break // for loop
					}
				}
				if !found {
					return true
				}

				// we don't want to match with the selector that calls the
				// lease function
				if m.Sel.Name == leaseFunction {
					return true
				}

				// report message for selector expression
				msg = "access of crit.Section without Lease"

			case *ast.ValueSpec:
				id, ok := m.Type.(*ast.Ident)
				if !ok {
					return true
				}

				// for simplicity, only one instance of a critsec type can
				// be instantiated
				if _, ok := critSecTypesUsed[id.Name]; ok {
					// bit only report on it if the function is in the graph
					nf, ok := nearestFunction(stack)
					if !ok {
						return true
					}

					if !isFunctionInGraph(pass, graph, nf) {
						return true
					}

					pass.Reportf(n.Pos(), "multiple instance of a crit.Section derived type")
					return true
				}

				critSecTypesUsed[id.Name] = true
				return true

			// assignment includes short var declarations
			case *ast.AssignStmt:
				switch m.Tok.String() {
				// short var declaration
				case ":=":
					compexpr, ok := m.Rhs[0].(*ast.CompositeLit)
					if !ok {
						return true
					}
					id, ok := compexpr.Type.(*ast.Ident)
					if !ok {
						return true
					}

					// for simplicity, only one instance of a critsec type can
					// be instantiated
					if _, ok := critSecTypesUsed[id.Name]; ok {
						// bit only report on it if the function is in the graph
						nf, ok := nearestFunction(stack)
						if !ok {
							return true
						}

						if !isFunctionInGraph(pass, graph, nf) {
							return true
						}

						pass.Reportf(n.Pos(), "multiple instance of a crit.Section derived type")
						return true
					}

					critSecTypesUsed[id.Name] = true
					return true

				default:
					lhs := m.Lhs[len(m.Lhs)-1]
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok {
						return true
					}

					ct := pass.TypesInfo.TypeOf(sel.X)

					// check that the node type is one that we're interested in
					var found bool
					for _, c := range critSecTypesByName {
						if types.ConvertibleTo(ct, c) {
							found = true
							break // for loop
						}
					}
					if !found {
						return true
					}

					// report message for assignment statements
					msg = "assignment to crit.Section without Lease"
				}

			default:
				return true
			}

			nf, ok := nearestFunction(stack)
			if !ok {
				return true
			}

			if !isFunctionInGraph(pass, graph, nf) {
				return true
			}

			if ok := checkLease(pass, graph, nf); !ok {
				pass.Reportf(n.Pos(), msg)
			}

			return true
		})
	}

	return nil, nil
}

// find the most recent function declaration or function literal that was
// pushed onto the stack
func nearestFunction(stack []ast.Node) (ast.Node, bool) {
	for i := len(stack) - 1; i >= 0; i-- {
		n := stack[i]
		switch n.(type) {
		case *ast.FuncDecl:
			return n, true
		case *ast.FuncLit:
			return n, true
		}
	}
	return nil, false
}

// check if the crit.Section.Lease() function is part of the call graph for the
// node. the node represents the nearest containing function
//
// the nf argument is the containing function of the access being checked,
// returned by nearestFunction(), of the critical section access
func checkLease(pass *analysis.Pass, graph *callgraph.Graph, nf ast.Node) bool {

	// recursive check to find the deepest call to leaseFunction
	var check func(*callgraph.Edge) bool

	// the implementation of the check function is reliant on the callgraph
	// being a VTA graph. it is likely that a differently constructed callgraph
	// will not produce the same results
	check = func(e *callgraph.Edge) bool {
		if e.Caller.Func.Name() == leaseFunction {
			return true
		}

		for _, in := range e.Caller.In {
			return check(in)
		}

		return false
	}

	done := errors.New("done")

	err := callgraph.GraphVisitEdges(graph, func(e *callgraph.Edge) error {
		if positionCompare(pass, nf.Pos(), e.Callee.Func.Pos()) {
			if check(e) {
				return done
			}
		}
		return nil
	})
	if errors.Is(err, done) {
		return true
	}
	if err != nil {
		log.Fatalf(err.Error())
	}

	return false
}

// isFunctionInGraph checks that the function (represented by ast.Node) we've
// found in the AST is actually in the callgraph. if it is not in the graph then
// we do not need to call checkLease()
//
// this function could probably be part of the checkLease() loop but it's
// clearer as a separate function
func isFunctionInGraph(pass *analysis.Pass, graph *callgraph.Graph, nf ast.Node) bool {
	// special condition: we assume that the main function is always in the graph
	if mf, ok := nf.(*ast.FuncDecl); ok {
		if mf.Name.Name == "main" {
			return true
		}
	}

	// if the node is found in the callgraph then inGraph is set to true and the
	// GraphVisitEdges() ends
	inGraph := false

	// sentinal error returned by callgraph.GraphVisitEdges()
	var functionFound = errors.New("functionFound")

	err := callgraph.GraphVisitEdges(graph, func(e *callgraph.Edge) error {
		if positionCompare(pass, nf.Pos(), e.Callee.Func.Pos()) {
			inGraph = true
			return functionFound
		}
		return nil
	})
	if err != nil && !errors.Is(err, functionFound) {
		log.Fatalf(err.Error())
	}

	return inGraph
}

// positionCompare is used to match ast.Nodes with callgraph.Nodes. using
// positions for this purpose seems a little rough-and-ready but it works for
// the purposes of a proof of concept
//
// it's also used during AST inspection to decide whether to ignore an AST node.
// when used for this purpose the granularity might not be fine enough in all
// cases, but during testing matching by filename and line number (ie. not
// column number) was sufficient
func positionCompare(pass *analysis.Pass, a token.Pos, b token.Pos) bool {
	A := pass.Fset.Position(a)
	B := pass.Fset.Position(b)
	return A.Filename == B.Filename && A.Line == B.Line
}
