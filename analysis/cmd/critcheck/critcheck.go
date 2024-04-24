package main

import (
	"github.com/jetsetilly/critsec/analysis"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(analysis.CritSection)
}
