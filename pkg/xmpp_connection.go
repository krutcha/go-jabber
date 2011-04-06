package gojabber

import (
	"net"
	"io"
	"os"
	"crypto/tls"
	"crypto/sha1"
	"encoding/base64"
	"sync"
	"strings"
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

/**************************************************************
 * TYPES AND THEIR METHODS
 **************************************************************/
//JabberCon
type JabberCon struct {
	//public
	JidToContact map[string]*Contact
	NameToJid    map[string]string
	//private
	rwlock    sync.RWMutex
	host      string
	jid       string
	user_cmd  chan string
	user_resp chan string
	net_in    chan string
	net_out   chan string
	cleanup   func()
	//callbacks
	callBackVCard  func(host string, avatar AvatarUpdate)
	callBackMsg    func(host string, msg MessageUpdate)
	callBackTyping func(host string, JID string)
	callBackStatus func(host string, JID string, status string)
}

// JabberCon - CLIENT CALLBACK REGISTRATION 
func (jcon *JabberCon) ConnectHook_AvatarUpdate(onVCardUpdate func(host string, avatar AvatarUpdate)) {
	jcon.callBackVCard = onVCardUpdate
}

func (jcon *JabberCon) ConnectHook_Msg(onMsg func(host string, msg MessageUpdate)) {
	jcon.callBackMsg = onMsg
}

func (jcon *JabberCon) ConnectHook_Typing(onTyping func(host string, JID string)) {
	jcon.callBackTyping = onTyping
}

func (jcon *JabberCon) ConnectHook_Status(onStatus func(host string, JID string, status string)) {
	jcon.callBackStatus = onStatus
}

// JabberCon - CLIENT FUNCTIONS
func (jcon *JabberCon) Disconnect() {
	jcon.cleanup()
}

func (jcon *JabberCon) SendMessage(msg string, contact *Contact, fromJID string) {
	sendMessage(jcon.net_out, msg, contact, fromJID)
}

func (jcon *JabberCon) GetJID() string {
	return jcon.jid
}

func (jcon *JabberCon) GetHost() string {
	return jcon.host
}

func (jcon *JabberCon) GetName(jid string) string {
	jcon.RLock()
	name := jcon.JidToContact[jid].Name
	jcon.RUnlock()
	return name
}

func (jcon *JabberCon) GetContact(jid string) (*Contact, bool) {
	jcon.RLock()
	contact, exists := jcon.JidToContact[jid]
	jcon.RUnlock()
	return contact, exists
}

// JabberCon - CLIENT READ LOCKS (play nice!)
func (jcon *JabberCon) RLock() {
	logVerbose("R LOCK TAKEN")
	jcon.rwlock.RLock()
}

func (jcon *JabberCon) RUnlock() {
	logVerbose("R LOCK RELEASED")
	jcon.rwlock.RUnlock()
}
/**************************************************************
 * EXPORTED
 **************************************************************/
/**
 * Create a network connection to XMPP server, authenticate, request roster, and broadcast initial presence
 */
func SpawnConnection(host string, domain string, username string, password string, port string, useTLS bool) (*JabberCon, os.Error) {
	var jcon JabberCon
	var err os.Error
	var state int = State_Auth1
	//requiring cleanup
	var con net.Conn

	//open socket

	switch useTLS {
	case true:
		con, err = tls.Dial("tcp", host+":"+port, nil)
	case false:
		con, err = net.Dial("tcp", host+":"+port)
	}

	if err != nil {
		logVerbose("Connection to %s Failed", host+":"+port)
		return nil, err
	} else {
		logVerbose("Connection to %s Created", host+":"+port)
	}

	//kick off read/write threads
	jcon.net_out = startNetWriter(con)
	jcon.net_in = startNetReader(con)
	jcon.user_cmd = make(chan string, 10)
	jcon.user_resp = make(chan string)
	jcon.NameToJid = make(map[string]string)
	jcon.JidToContact = make(map[string]*Contact)
	jcon.host = host
	jcon.cleanup = func() {
		logVerbose("gojabber - cleaning up: %s", host)
		endStream(jcon.net_out)
		close(jcon.net_out) //will bring down net writer
		close(jcon.user_cmd)
		close(jcon.user_resp)
		con.Close()         //will bring down net reader
	}

	//<session establishment - [1], initiate stream>
	startStream(jcon.net_out, domain)

	state = State_Auth1
	logVerbose("STATE: Auth1")

	go func() {
		/**
		 * process incoming network traffic, 
		 * manage XMPP connection state, etc
		 */
		for msg := range jcon.net_in {
			logVerbose("HANDLING: %s", msg)

            if(msg == "") {
                return
            }
			msgType, err := getMessageType(msg)
			logError(err)

			switch msgType {
			case Presence:
				if updates, err := getPresenceUpdates(msg); err == nil {
					for _, update := range updates {
						if contact, exists := jcon.GetContact(update.JID); exists == true {
							jcon.wLock() //LOCK FOR WRITE
							{
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
										if contact.Avatar.PhotoHash != update.PhotoHash {
											logVerbose("existing photo %s doesn't match %s", contact.Avatar.PhotoHash, update.PhotoHash)
											//a new avatar must be present, request vcard
											requestVcard(jcon.net_out, jcon.jid, update.JID)
										}
									}
								}
							}
							jcon.wUnlock() //UNLOCK
							logVerbose("UPDATE[%s, %s, %s, hasphoto:%s]", contact.Name, contact.Show, contact.Status, contact.Avatar.PhotoHash)
							if jcon.callBackStatus != nil {
								jcon.callBackStatus(jcon.host, contact.JID, contact.Status)
							}
						} else {
							logVerbose("UPDATE[%s] not found", update.JID)
						}
					}
				}
			case VCard:
				if avatars, err := getAvatars(msg); err == nil {
					for _, avatar := range avatars {
						logVerbose("VCARD[%s, %s]", avatar.JID, avatar.Type)
						if contact, exists := jcon.GetContact(avatar.JID); exists == true {
							jcon.wLock() //LOCK FOR WRITE
							{
								contact.Avatar.Photo = avatar.Photo
								contact.Avatar.Type = avatar.Type
								hash := sha1.New()
								hash.Write(avatar.Photo)
								contact.Avatar.PhotoHash = string(hash.Sum())
							}
							jcon.wUnlock() //UNLOCK
							if jcon.callBackVCard != nil {
								jcon.callBackVCard(jcon.host, avatar)
							}
						}
					}
				}

			case Message:
				if message, err := getMessage(msg); err == nil {
					if message.State == "composing" {
						logVerbose("INFO[%s is typing]", jcon.GetName(message.JID))
						if jcon.callBackTyping != nil {
							jcon.callBackTyping(jcon.host, message.JID)
						}

					} else if message.Body != "" {
						logVerbose("MSG[from:%s, body:%s]", jcon.GetName(message.JID), message.Body)
						if jcon.callBackMsg != nil {
							jcon.callBackMsg(jcon.host, message)
						}
					}
				}
			case Features:
				featureMap, err := getFeatures(msg)
				logError(err)

				if err == nil {
					if state == State_Auth1 {
						//<session establishment - [2], note mechanisms>
						for _, mechanism := range featureMap["mechanism"] {
							if mechanism == "DIGEST-MD5" {
								requestAuthMD5(jcon.net_out)
								break
							} else if mechanism == "PLAIN" {
								requestAuthPLAIN(jcon.net_out, username, password)
								break
							} /* else if mechanism == "X-GOOGLE-TOKEN" {
								jcon.net_out <- "<starttls xmlns='"+nsTLS+"' />"
								break
							}*/
						}
					} else if state == State_Auth3 {
						//<session establishment - [5], bind a resource>
						bind(jcon.net_out, "bind_1")
					}
				}
			case Proceed:
				startStream(jcon.net_out, domain)
			case Challenge:
				//<session establishment - [3], respond to challenge>
				response, err := getChallengeResp_DIGESTMD5(msg, username, password, "wakawaka", "")
				logError(err)

				if err == nil {
					if state == State_Auth1 {
						state = State_Auth2
						logVerbose("STATE: Challenge Received")
						sendChallengeResponse1(jcon.net_out, response)
					} else {
						sendChallengeResponse2(jcon.net_out)
					}
				}
			case Success:
				//<session establishment - [4], re-start stream>
				state = State_Auth3
				logVerbose("STATE: Challenge Accepted")
				startStream(jcon.net_out, domain)
			case JID:
				//<session establishment - [6], request session>
				jcon.jid, err = getJID(msg)
				logError(err)

				if err == nil {
					state = State_Connected
					logVerbose("STATE: Connected")
					logVerbose("Got JID: %s", jcon.jid)
					requestSession(jcon.net_out, domain)
				}
			case Session:
				//<session establishment - [7], get the roster>
				requestRoster(jcon.net_out, jcon.jid)
			case Roster:
				//<session establishment - [8], indicate presence>
				jcon.wLock() //LOCK FOR WRITE
				{
					jcon.JidToContact, err = getRoster(msg)
					for _, contact := range jcon.JidToContact {
						jcon.NameToJid[contact.Name] = contact.JID
					}
				}
				jcon.wUnlock() //UNLOCK

				logError(err)
				sendInitialPresence(jcon.net_out)
			case Error, SASLFailure:
				return
			default:
				logVerbose("Nothing useful received")
			}
		}
	}()

	return &jcon, err
}

/**************************************************************
 * INTERNAL - Locking Mechanism
 **************************************************************/
func (jcon *JabberCon) wLock() {
	logVerbose("W LOCK TAKEN")
	jcon.rwlock.Lock()
}

func (jcon *JabberCon) wUnlock() {
	logVerbose("W LOCK RELEASED")
	jcon.rwlock.Unlock()
}

/**************************************************************
 * INTERNAL - Simple XMPP message functions
 **************************************************************/

func startStream(writechan chan string, domain string) {
	logVerbose("Sending Stream Start")
	writechan <- XMLVERSION + "<stream:stream " + "to='" + domain + "' " + "xmlns='" + nsClient + "' " + "xmlns:stream='" + nsStream + "' " + "version='1.0'>"
}

func endStream(writechan chan string) {
	logVerbose("Sending Stream Termination")
	writechan <- "</stream:stream>"
}

func startTLS(writechan chan string) {
	logVerbose("sending startTLS")
	writechan <- "<starttls xmlns='" + nsTLS + "'/>"
}

func requestRoster(writechan chan string, JID string) {
	logVerbose("Requesting Roster")
	writechan <- "<iq from='" + JID + "' type='get' id='roster_1'><query xmlns='" + nsRoster + "'/></iq>"
}

func requestSession(writechan chan string, domain string) {
	logVerbose("Requesting Session")
	writechan <- "<iq to='" + domain + "' type='set' id='sess_1'><session xmlns='" + nsSession + "'/></iq>"
}

func sendMessage(writechan chan string, msg string, contact *Contact, fromJID string) {
	logVerbose("Sending msg [%s] to [%s]", msg, contact.Name)
	writechan <- "<message to='" + contact.JID + "' from='" + fromJID + "' type='chat' xml:lang='en'><body>" + msg + "</body></message>"
}

func requestVcard(writechan chan string, fromJID string, toJID string) {
	writechan <- "<iq from='" + fromJID + "' to='" + toJID + "' type='get' id='vc2'><vCard xmlns='vcard-temp'/></iq>"
}

func requestAuthMD5(writechan chan string) {
	writechan <- "<auth xmlns='" + nsSASL + "' mechanism='DIGEST-MD5'/>"
}

func requestAuthPLAIN(writechan chan string, username string, password string) {
	resp := "\u0000" + username + "\u0000" + password
	base64buf := make([]byte, base64.StdEncoding.EncodedLen(len(resp)))
	base64.StdEncoding.Encode(base64buf, []byte(resp))
	writechan <- "<auth xmlns='" + nsSASL + "' mechanism='PLAIN'>" + string(base64buf) + "</auth>"
}

func bind(writechan chan string, id string) {
	writechan <- "<iq type='set' id='" + id + "'><bind xmlns='" + nsBind + "'/></iq>"
}

func sendChallengeResponse1(writechan chan string, response string) {
	writechan <- response
}

func sendChallengeResponse2(writechan chan string) {
	writechan <- "<response xmlns='" + nsSASL + "'/>"
}

func sendInitialPresence(writechan chan string) {
	writechan <- "<presence/>"
}

/**************************************************************
 * INTERNAL - Stream Parsing to match up tags
 **************************************************************/
func getTagType(tag string) string {
	//stream:stream id="EB0F9B28" from="chat.facebook.com" .. becomes stream:stream 
	//mechanisms xmlns="urn:ietf:params:xml:ns:xmpp-sasl"> becomes mechanisms
	tagTokens := strings.Split(tag, " ", -1)

	//stream:stream becomes [stream,stream]
	//mechanisms becomes [mechanisms]
	tagTokens = strings.Split(tagTokens[0], ":", -1)

	if len(tagTokens) == 1 {
		return tagTokens[0]
	}

	return tagTokens[1]
}

func hasMatchingTags(buff []uint8) bool {
	startToken := 1
	startString := string(buff)

	//good solid painful example
	/*
	   <?xml version="1.0"?>
	   <stream:stream id="EB0F9B28" from="chat.facebook.com" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" version="1.0" xml:lang="en">
	       <stream:features>
	           <mechanisms xmlns="urn:ietf:params:xml:ns:xmpp-sasl">
	               <mechanism>X-FACEBOOK-PLATFORM</mechanism>
	               <mechanism>DIGEST-MD5</mechanism>
	           </mechanisms>
	       </stream:features>
	*/

	logVerbose("checking start end match[%s]", buff)

	//strip <'s and tokenize around them
	tokens := strings.Split(startString, "<", -1)

	//need a start nil, and at least a start tag and end tag
	if len(tokens) < 3 {
		logVerbose("throwaway token")
		return true
	}

	//first char of any XML should be <, so first token should be nil
	if tokens[0] != "" {
		logVerbose("no match, bad XML")
		return false
	}

	for _, token := range tokens[1:] {
		//chew through invalid start tokens
		logVerbose("token [%s]", token)
		if token[0] == '?' {
			logVerbose("skipping ? tag")
			startToken++
			continue
		}

		//stream:stream ... may or may not contain namespace (should)
		//but accept XXXXX:stream or stream
		tag := getTagType(token)
		if tag == "stream" {
			logVerbose("skipping stream tag")
			startToken++
			continue
		}

		//otherwise, we should have our start point
		break
	}

	if startToken >= (len(tokens) - 1) {
		logVerbose("no match, too few tokens")
		return false
	}

	tag1 := getTagType(tokens[startToken])
	logVerbose("Tag1:%s", tag1)
	tag2 := getTagType(tokens[len(tokens)-1])
	logVerbose("Tag2:%s", tag2)

	if strings.Contains(tokens[len(tokens)-1], "/"+tag1) || strings.Contains(tokens[len(tokens)-1], "/stream:"+tag1) {
		logVerbose("MATCH")
		return true
	}

	logVerbose("MISMATCH")
	return false
}

/**************************************************************
 * INTERNAL - Connection goroutines to sit on sockets
 **************************************************************/
func startNetReader(con net.Conn) chan string {
	inchan := make(chan string, 100)
	respBuf := make([]uint8, 4096)

	go func() {
		defer func() {
			logVerbose("READER TERMINATING")
			close(inchan)
		}()

		var stringBuff []uint8

		//read forever
		for {
			if count, err := con.Read(respBuf); err == nil {
				//add new data to string buffer
				stringBuff = append(stringBuff, respBuf[0:count]...)
				logVerbose("RECEIVING:\"" + string(stringBuff) + "\"")
				if hasMatchingTags(stringBuff) {
					logVerbose("ACCEPTING:\"" + string(stringBuff) + "\"")
					inchan <- string(stringBuff)
					//empty string buffer
					stringBuff = stringBuff[:0]
				}
			} else {
				logVerbose("Connection: %s", err.String())
				break
			}
		}
	}()

	return inchan
}

func startNetWriter(con net.Conn) chan string {
	outchan := make(chan string, 100)

	go func() {
		for msg := range outchan {
			logVerbose("SENDING:\"" + msg + "\"")
			io.WriteString(con, msg)
		}
   	    logVerbose("WRITER TERMINATING")
	}()

	return outchan
}
