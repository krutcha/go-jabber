package main

import (
	"flag"
	"fmt"
	"gojabber"
	"bufio"
	"os"
	"strings"
)

/**
 * Process user commands and pass them to XMPP gateway
 */
func input(outchan chan string) {
	in := bufio.NewReader(os.Stdin)

	gojabber.Log("")
	for {
		if cmd, err := in.ReadString('\n'); err == nil && cmd != "\n" {
			outchan <- strings.Trim(cmd, "\n")
		}
		gojabber.LogPrompt()
	}
}

/**
 * Sample Client Program entrypoint
 *  1) initialize an XMPP gateway
 *  2) begin processing user commands
 *  3) wait for exit
 */
func main() {

	var verbose bool

	flag.BoolVar(&verbose, "V", false, "enable verbose logging")
	flag.Parse()

	/**
	 * INITIAL SETUP STUFF 
	 */
	//set debug verbosity
	if verbose {
		gojabber.SetVerbosity(gojabber.Verbose)
	}

	/**
	 * Working with Go-jabber
	 */
	//Kickoff jabber gateway 
	cmdchan, quitchan, err := gojabber.XmppGatewayInit()
	if err != nil {
		fmt.Printf("Error in gojabber.Init:", err)
		return
	}

	//Spawn goroutine for user io
	go input(cmdchan)

	//Chill until termination requested
	<-quitchan
}
