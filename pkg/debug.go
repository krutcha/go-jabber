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

/**************************************************************
 * VARS
 **************************************************************/
var verbosity = Normal

/**************************************************************
 * EXPORTED
 **************************************************************/
func SetVerbosity(level int) {
	verbosity = level
}

func log(f string, args ...interface{}) {
	if verbosity > Silent {
		fmt.Printf(f+"\n", args...)
	}
}

func logVerbose(f string, args ...interface{}) {
	if verbosity > Normal {
		fmt.Printf(f+"\n", args...)
	}
}

func logError(err os.Error) {
	if err != nil {
		fmt.Printf("%s\n", err.String())
	}
}
