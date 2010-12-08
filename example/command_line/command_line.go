package main

import (
	"flag"
	"fmt"
	"gojabber"
	"bufio"
	"os"
	"strings"
	"sort"
)

/**************************************************************
 * CONSTANTS
 **************************************************************/
const (
	Normal = iota
	Verbose
)

/**************************************************************
 * VARS
 **************************************************************/
var verbosity = Normal

/**************************************************************
 * Utility Functions
 **************************************************************/
func log(f string, args ...interface{}) {
	if verbosity >= Normal {
		fmt.Printf(f+"\n->", args...)
	}
}

func logVerbose(f string, args ...interface{}) {
	if verbosity >= Verbose {
		fmt.Printf(f+"\n->", args...)
	}
}

func logPrompt() {
	if verbosity >= Normal {
		fmt.Printf("->")
	}
}

func logError(err os.Error) {
	if err != nil {
		fmt.Printf("%s\n->", err.String())
	}
}

func printHelp() {
	log("/?,/help")
	log("/quit")
	log("/who")
	log("/tell <contact name> <message>")
	log("/servers")
	log("/connect")
	log("/disconnect X")

	log("Sample connect strings:")
	log("/connect -u=user -pw=pass -h=talk.google.com -d=gmail.com -useTLS ")
	log("/connect -u=user -pw=pass -h=chat.facebook.com")
	log("/connect -u=user -pw=pass -h=jabber.org")
}

func printWelcomeBanner(){
	log("WELCOME to Go-Jabber")
	log("")
	log("Available commands:")
	printHelp();
}

func deleteCon(S []*gojabber.JabberCon, i int) []*gojabber.JabberCon {
	copy(S[i:], S[i+1:])
	return S[:len(S)-1]
}

/**************************************************************
 * Goroutines
 **************************************************************/
/**
 * Process user commands and pass them to XMPP gateway
 */
func input(cmd_chan chan string) {
	in := bufio.NewReader(os.Stdin)

	log("")
	for {
		if cmd, err := in.ReadString('\n'); err == nil && cmd != "\n" {
			cmd_chan <- strings.Trim(cmd, "\n")
		}
		logPrompt()
	}
}

/**************************************************************
 * Entrypoint
 **************************************************************/
func main() {
	user_cmdchan := make(chan string, 10)

	var verbose bool

	flag.BoolVar(&verbose, "V", false, "enable verbose logging")
	flag.Parse()

	/**
	 * INITIAL SETUP STUFF 
	 */
	printWelcomeBanner()
	
	//Set local and gojabber pkg logging levels
	if verbose {
		gojabber.SetVerbosity(gojabber.Verbose)
		verbosity = Verbose
	}

	//User input goroutine for command line in
	go input(user_cmdchan)

	//List of active connections, to be cleaned up on exit
	jabberCons := make([]*gojabber.JabberCon, 0)
	defer func() {
		for i, jcon := range jabberCons {
			logVerbose("Signalling connection %d disconnect\n", i)
			jcon.Disconnect()
		}
	}()

	/**
	 * Process user commands from Client
	 */
	for msg := range user_cmdchan {
		tokens := strings.Split(msg, " ", -1)
		if len(tokens) > 0 {
			switch tokens[0] {
			case "/disconnect":
				var serverNum int
				fmt.Sscanf(tokens[1], "%d", &serverNum)
				if len(jabberCons)-1 > serverNum {
					jabberCons[serverNum].Disconnect()
					jabberCons = deleteCon(jabberCons, serverNum)
				}
			case "/servers":
				i := 0
				for _, jcon := range jabberCons {
					log("[%d]%s:%s\n", i, jcon.Host, jcon.JID)
					i++
				}
			case "/connect":
				var host = ""
				var username = ""
				var password = ""
				var domain = ""
				var useTLS = "N"
				var port = "5222"

				for _, token := range tokens {
					if strings.Contains(token, "-u=") {
						username = strings.Replace(token, "-u=", "", 1)
					}
					if strings.Contains(token, "-pw=") {
						password = strings.Replace(token, "-pw=", "", 1)
					}
					if strings.Contains(token, "-h=") {
						host = strings.Replace(token, "-h=", "", 1)
						if domain == "" {
							domain = host
						}
					}
					if strings.Contains(token, "-d=") {
						domain = strings.Replace(token, "-d=", "", 1)
					}
					if strings.Contains(token, "-useTLS") {
						useTLS = "Y"
						port = "5223"
					}
				}
				if host != "" && username != "" && password != "" && domain != "" && useTLS != "" && port != "" {
					//Start Active Connection
					if jcon, err := gojabber.SpawnConnection(host, domain, username, password, port, useTLS == "Y"); err == nil {
						jabberCons = append(jabberCons, jcon)
						//Register Callbacks
						jcon.ConnectHook_AvatarUpdate(
							func(host string, avatar gojabber.AvatarUpdate){
								log(" +++Avatar Received, [%s,%s--%s,%s]", host, avatar.JID, jcon.JidToContact[avatar.JID].Name, avatar.Type)
							})
						jcon.ConnectHook_Msg(
							func(host string, msg gojabber.MessageUpdate){
								log(".oO(%s:%s: %s)", host, jcon.JidToContact[msg.JID].Name, msg.Body)
							})
						jcon.ConnectHook_Typing(
							func(host string, JID string){
								log(" +++%s:%s: -> typing <-", host, jcon.JidToContact[JID].Name)
							})
						jcon.ConnectHook_Status(
							func(host string, JID string, status string){
								log(" +++%s:%s: -> %s <-", host, jcon.JidToContact[JID].Name, status)
							})
					} else {
						logError(err)
						break
					}
				} else {
					printHelp()
				}
			case "/?", "/help":
				printHelp()
			case "/who":
				for _, jcon := range jabberCons {
					log("%s - who", jcon.Host)
					sorted := make([]string, len(jcon.JidToContact))
					//stash names in a slice
					i := 0
					for _, contact := range jcon.JidToContact {
						sorted[i] = contact.Name
						i++
					}
					//sort em
					sort.SortStrings(sorted)
					//display records, sorted by name
					for _, name := range sorted {
						contact := jcon.JidToContact[jcon.NameToJid[name]]
						if contact.Show != "offline" {
							log("\t%s,(%s:%s)", contact.Name, contact.Show, contact.Status)
						}
					}
				}
			case "/tell":
				if len(tokens) > 2 {
					for _, jcon := range jabberCons {
						var matches []*gojabber.Contact
						logVerbose("%s - /tell", jcon.Host)
						for _, contact := range jcon.JidToContact {
							if strings.Contains(contact.Name, tokens[1]) {
								if contact.Show != "offline" {
									logVerbose("Matched: %s -> %s", tokens[1], contact.Name)
									matches = append(matches, contact)
								}
							}
						}
						if len(matches) == 1 {
							jcon.SendMessage(strings.Join(tokens[2:], " "), matches[0], jcon.JID)
						} else if len(matches) > 1 {
							log("Be more specific [%s] matched: ", jcon.Host)
							for _, contact := range matches {
								log("%s", contact.Name)
							}
						} else {
							log("No matches found")
						}
					}
				}
			case "/quit":
				return
			}
		}
	}
}
