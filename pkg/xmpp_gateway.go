package gojabber

import (
	"net"
	"io"
	"os"
	"crypto/tls"
	"crypto/sha1"
	"sort"
	"strings"
	"encoding/base64"
	"fmt"
)

/**************************************************************
 * CONSTANTS
 **************************************************************/
const (
	State_Auth1 = iota
	State_Auth2
	State_Auth3
	State_Connected
)

const (
	ConDead = iota
	ConOK
)
/**************************************************************
 * TYPES
 **************************************************************/
type JabberCon struct {
	user_cmd     chan string
	user_resp    chan int
	JID          string
	JidToContact map[string]*Contact
	NameToJid    map[string]string
	cleanup      func()
	host         string
}

/**************************************************************
 * EXPORTED
 **************************************************************/
/**
 * Create an XMPP gateway which will maintain a slice of XMPP server connections
 * to various servers.  Responsible for managing connections, and forwarding
 * requests.
 * 
 * channels returned: 
 *		user_cmdchan  - go-jabber command strings FROM client/user
 *      user_quitchan - a channel back to client to signal termination
 */
func XmppGatewayInit() (chan string, chan int, os.Error) {
	user_quitchan := make(chan int)
	user_cmdchan := make(chan string, 10)
	var err os.Error

	go func() {
		jabberCons := make([]*JabberCon, 0)

		defer func() {
			Log("Requesting Client Shutdown")
			user_quitchan <- 0
		}()
		defer func() {
			for i, jcon := range jabberCons {
				//jcon.cleanup()
				Log("Signalling connection %d disconnect", i)
				jcon.user_cmd <- "/disconnect"
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
						jabberCons[serverNum].user_cmd <- "/disconnect"
					}
					jabberCons = deleteCon(jabberCons, serverNum)
				case "/servers":
					i := 0
					for _, jcon := range jabberCons {
						Log("[%d]%s:%s", i, jcon.host, jcon.JID)
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
							LogVerbose("username:%s", username)
						}
						if strings.Contains(token, "-pw=") {
							password = strings.Replace(token, "-pw=", "", 1)
							LogVerbose("password:%s", password)
						}
						if strings.Contains(token, "-h=") {
							host = strings.Replace(token, "-h=", "", 1)
							if domain == "" {
								domain = host
							}
							LogVerbose("host:%s", host)
						}
						if strings.Contains(token, "-d=") {
							domain = strings.Replace(token, "-d=", "", 1)
							LogVerbose("domain:%s", domain)
						}
						if strings.Contains(token, "-useTLS") {
							useTLS = "Y"
							port = "5223"
							LogVerbose("TLS:%s", useTLS)
						}
					}
					if host != "" && username != "" && password != "" && domain != "" && useTLS != "" && port != "" {
						//Start Active Connection
						if jcon, err := spawnConnection(host, domain, username, password, port, useTLS == "Y"); err == nil {
							jabberCons = append(jabberCons, jcon)
						} else {
							LogError(err)
							break
						}
					} else {
						printHelp()
					}
				case "/?", "/help":
					printHelp()

				case "/quit":
					return
				default:
					for i, jcon := range jabberCons {
						jcon.user_cmd <- msg
						if x := <-jcon.user_resp; x == ConDead {
							Log("Connection Stale: %s", jcon.host)
							jcon.user_cmd <- "/disconnect"
							jabberCons = deleteCon(jabberCons, i)
						}
					}
				}
			}
		}
	}()
	return user_cmdchan, user_quitchan, err
}


/**************************************************************
 * LOCAL
 **************************************************************/
func printHelp() {
	Log("/?,/help")
	Log("/quit")
	Log("/who")
	Log("/tell <contact name> <message>")
	Log("/servers")
	Log("/connect")
	Log("/disconnect X")

	Log("Sample connect strings:")
	Log("/connect -u=user -pw=pass -h=talk.google.com -d=gmail.com -useTLS ")
	Log("/connect -u=user -pw=pass -h=chat.facebook.com")
	Log("/connect -u=user -pw=pass -h=jabber.org")
}

func deleteCon(S []*JabberCon, i int) []*JabberCon {
	copy(S[i:], S[i+1:])
	return S[:len(S)-1]
}

func startReader(con net.Conn) chan string {
	inchan := make(chan string, 100)
	respBuf := make([]uint8, 4096)

	go func() {
		defer func() {
			Log("READER TERMINATING")
			close(inchan)
		}()

		var stringBuff []uint8

		//read forever
		for {
			if count, err := con.Read(respBuf); err == nil {
				stringBuff = append(stringBuff, respBuf[0:count]...)

				//temporary hack, pull until a matching the last char of a
				//multipart reat is a />
				if stringBuff[len(stringBuff)-1] == '>' {
					LogVerbose("RECEIVING:\"" + string(stringBuff) + "\"")
					inchan <- string(stringBuff)
					stringBuff = stringBuff[:0]
				}
			} else {
				LogVerbose("Connection: %s", err.String())
				break
			}
		}
	}()

	return inchan
}

func startWriter(con net.Conn) chan string {
	outchan := make(chan string, 100)

	go func() {
		defer func() {
			Log("WRITER TERMINATING")
			close(outchan)
		}()

		for msg := range outchan {
			LogVerbose("SENDING:\"" + msg + "\"")
			io.WriteString(con, msg)
		}
	}()

	return outchan
}

/**
 * Create a network connection to XMPP server, authenticate, request roster, and broadcast initial presence
 * 
 * channels returned: 
 *		user_cmdchan - go-jabber command strings FROM XMPPGateway
 */
func spawnConnection(host string, domain string, username string, password string, port string, useTLS bool) (*JabberCon, os.Error) {
	var jcon JabberCon
	var err os.Error
	var state int = State_Auth1
	//requiring cleanup
	var net_in chan string
	var net_out chan string
	var con net.Conn

	//open socket
	LogVerbose("Opening Connection to " + host + ":" + port)

	switch useTLS {
	case true:
		con, err = tls.Dial("tcp", "", host+":"+port)
	case false:
		con, err = net.Dial("tcp", "", host+":"+port)
	}

	if err != nil {
		LogVerbose("Connection Failed")
		return nil, err
	} else {
		LogVerbose("Connection created")
	}

	//kick off read/write threads
	net_out = startWriter(con)
	net_in = startReader(con)
	
	jcon.user_cmd = make(chan string, 10)
	jcon.user_resp = make(chan int)
	jcon.NameToJid = make(map[string]string)
	jcon.JidToContact = make(map[string]*Contact)
	jcon.host = host
	jcon.cleanup = func() {
		Log("gojabber - cleaning up: %s", host)
		EndStream(net_out)
		close(net_in)
		close(net_out)
		close(jcon.user_cmd)
		close(jcon.user_resp)
		con.Close()
	}

	//<session establishment - [1], initiate stream>
	StartStream(net_out, domain)

	state = State_Auth1
	LogVerbose("STATE: Auth1")

	go func() {
		defer func() { jcon.cleanup() }()
		for {
			var msg string

			select {
			/**
			 * process incoming network traffic, 
			 * manage XMPP connection state, etc
			 */
			case msg = <-net_in:
				if closed(net_in) {
					return
				}
				LogVerbose("HANDLING: %s", msg)

				msgType, err := GetMessageType(msg)
				LogError(err)

				switch msgType {
				case Presence:
					if updates, err := GetPresenceUpdates(msg); err == nil {
						for _, update := range updates {
							if contact, exists := jcon.JidToContact[update.JID]; exists == true {
								if update.Type == "unavailable" {
									contact.Show = "offline"
								} else {
									if update.Show != "" {
										contact.Show = update.Show
									} else {
										contact.Show = "online"
									}
									if update.Status != "" {
										contact.Status = update.Status
									}
									if update.PhotoHash != "" {
										if(contact.Avatar.PhotoHash != update.PhotoHash) {
											LogVerbose("existing photo %s doesn't match %s", contact.Avatar.PhotoHash, update.PhotoHash)
											//a new avatar must be present, request vcard
											net_out <- "<iq from='" + jcon.JID + "' to='" + update.JID + "' type='get' id='vc2'><vCard xmlns='vcard-temp'/></iq>"
										}
									}
								}
								LogVerbose("UPDATE[%s, %s, %s, hasphoto:%s]", contact.Name, contact.Show, contact.Status, contact.Avatar.PhotoHash)

							} else {
								LogVerbose("UPDATE[%s] not found")
							}
						}
					}
				case VCard:
					if avatars, err := GetAvatars(msg); err == nil {
						for _, avatar := range avatars {
							Log("VCARD[%s, %s]", avatar.JID, avatar.Type)
							if contact, exists := jcon.JidToContact[avatar.JID]; exists == true {
								contact.Avatar.Photo = avatar.Photo
								contact.Avatar.Type  = avatar.Type
								hash := sha1.New()
								hash.Write(avatar.Photo)
								contact.Avatar.PhotoHash = string(hash.Sum())
							}
						}
					}

				case Message:
					if message, err := GetMessage(msg); err == nil {
						if message.State == "composing" {
							Log("INFO[%s is typing]", jcon.JidToContact[message.From].Name)

						} else if message.Body != "" {
							Log("MSG[from:%s, body:%s]", jcon.JidToContact[message.From].Name, message.Body)

						}
					}
				case Features:
					featureMap, err := GetFeatures(msg)
					LogError(err)

					if err == nil {
						if state == State_Auth1 {
							//<session establishment - [2], note mechanisms>
							for _, mechanism := range featureMap["mechanism"] {
								if mechanism == "DIGEST-MD5" {
									net_out <- "<auth xmlns='"+nsSASL+"' mechanism='DIGEST-MD5'/>"
									break
								} else if mechanism == "PLAIN" {
									resp := "\u0000" + username + "\u0000" + password
									base64buf := make([]byte, base64.StdEncoding.EncodedLen(len(resp)))
									base64.StdEncoding.Encode(base64buf, []byte(resp))
									net_out <- "<auth xmlns='"+nsSASL+"' mechanism='PLAIN'>"+string(base64buf)+"</auth>"
									break
								} else if mechanism == "X-GOOGLE-TOKEN" {
									net_out <- "<starttls xmlns='"+nsTLS+"' />"
									break
								}
							}
						} else if state == State_Auth3 {
							//<session establishment - [5], bind a resource>
							net_out <- "<iq type='set' id='bind_1'><bind xmlns='"+nsBind+"'/></iq>"
						}
					}
				case Proceed:
					StartStream(net_out, domain)
				case Challenge:
					//<session establishment - [3], respond to challenge>
					response, err := GetChallengeResp_DIGESTMD5(msg, username, password, "wakawaka", "")
					LogError(err)

					if err == nil {
						if state == State_Auth1 {
							state = State_Auth2
							LogVerbose("STATE: Challenge Received")
							net_out <- response
						} else {
							net_out <- "<response xmlns='"+nsSASL+"'/>"
						}
					}
				case Success:
					//<session establishment - [4], re-start stream>
					state = State_Auth3
					LogVerbose("STATE: Challenge Accepted")
					StartStream(net_out, domain)
				case JID:
					//<session establishment - [6], request session>
					jcon.JID, err = GetJID(msg)
					LogError(err)

					if err == nil {
						state = State_Connected
						LogVerbose("STATE: Connected")
						LogVerbose("Got JID: %s", jcon.JID)
						RequestSession(net_out, domain)
					}
				case Session:
					//<session establishment - [7], get the roster>
					RequestRoster(net_out, jcon.JID)
				case Roster:
					//<session establishment - [8], indicate presence>
					jcon.JidToContact, err = GetRoster(msg)
					for _, contact := range jcon.JidToContact {
						jcon.NameToJid[contact.Name] = contact.JID
					}
					LogError(err)
					net_out <- "<presence/>"
				case Error, SASLFailure:
					return
				default:
					LogVerbose("Nothing useful received")
				}
			/**
			 * Process user commands for this connection
			 * as forwarded from XMPPGateway
			 */
			case msg = <-jcon.user_cmd:
				tokens := strings.Split(msg, " ", -1)
				if len(tokens) > 0 {
					switch tokens[0] {
					case "/disconnect":
						return
					case "/who":
						Log("%s:%s - who", host, username)
						sorted := make([]string, len(jcon.JidToContact))
						i := 0
						//stash names in a slice
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
								Log("\t%s,(%s:%s)", contact.Name, contact.Show, contact.Status)
							}
						}
						jcon.user_resp <- ConOK
					case "/tell":
						if len(tokens) > 2 {
							matches := make([]*Contact, 0)
							for _, contact := range jcon.JidToContact {
								if strings.Contains(contact.Name, tokens[1]) {
									LogVerbose("Matched: %s -> %s", tokens[1], contact.Name)
									matches = append(matches, contact)
								}
							}
							if len(matches) == 1 {
								SendMessage(net_out, strings.Join(tokens[2:], " "), matches[0], jcon.JID)
							} else {
								Log("Be more specific, matched: ")
								for _, contact := range matches {
									Log("%s", contact.Name)
								}
							}
						} else {
							printHelp()
						}
						jcon.user_resp <- ConOK
					default:
						jcon.user_resp <- ConOK
					}
				}
			}
		}
	}()

	return &jcon, err
}
