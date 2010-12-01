package gojabber

import (
	"fmt"
	"os"
)

/**************************************************************
 * CONSTANTS
 **************************************************************/
const (
	Silent = iota
	Normal
	Verbose
)

var verbosity = Normal

/**************************************************************
 * EXPORTED
 **************************************************************/
func SetVerbosity(level int) {
	verbosity = level
}

func LogPrompt() {
	if verbosity > Silent {
		fmt.Printf("->")
	}
}

func Log(f string, args ...interface{}) {
	if verbosity > Silent {
		fmt.Printf(f+"\n->", args...)
	}
}

func LogVerbose(f string, args ...interface{}) {
	if verbosity > Normal {
		fmt.Printf(f+"\n->", args...)
	}
}

func LogError(err os.Error) {
	if err != nil {
		fmt.Printf("%s\n->", err.String())
	}
}
