package gojabber

import (
        xmlx "github.com/jteeuwen/go-pkg-xmlx"
	"fmt"
	"crypto/md5"
	"encoding/base64"
	"strings"
	"os"
)

/**************************************************************
 * CONSTANTS
 **************************************************************/
const XMLVERSION = "<?xml version='1.0'?>"
const noncecount = "00000001"

// XMPP relevant XML namespaces
const (
	nsStream      = "http://etherx.jabber.org/streams"
	nsTLS         = "urn:ietf:params:xml:ns:xmpp-tls"
	nsSASL        = "urn:ietf:params:xml:ns:xmpp-sasl"
	nsBind        = "urn:ietf:params:xml:ns:xmpp-bind"
	nsClient      = "jabber:client"
	nsRoster      = "jabber:iq:roster"
	nsSession     = "urn:ietf:params:xml:ns:xmpp-session"
	nsChatstates  = "http://jabber.org/protocol/chatstates"
	nsVcardUpdate = "vcard-temp:x:update"
	nsVcard       = "vcard-temp"
)

// Enumeration of Message Types
const (
	Features = iota
	Challenge
	Success
	JID
	Session
	SASLFailure
	Unknown
	Roster
	Presence
	Proceed
	Message
	VCard
	Error
)
/**************************************************************
 * TYPES
 **************************************************************/
type Contact struct {
	Name         string
	Subscription string
	JID          string
	Show         string
	Status       string
	Avatar       Photo
}

type PresenceUpdate struct {
	JID       string
	Show      string
	Status    string
	Type      string
	PhotoHash string
}

type MessageUpdate struct {
	JID   string
	Type  string
	State string //active, composing, paused, inactive
	Body  string
}

type AvatarUpdate struct {
	Type  string
	Photo []byte
	JID   string
}

type Photo struct {
	PhotoHash string
	Photo     []byte
	Type      string
}

/**************************************************************
 * INTERNAL - Parsing
 **************************************************************/
func getMessageType(msg string) (int, os.Error) {
	xmlDoc := xmlx.New()
	if err := xmlDoc.LoadString(msg); err != nil {
		logError(err)
		return Error, err
	}

	logVerbose("Root:%s, ns:%s", xmlDoc.Root.Name.Local, xmlDoc.Root.Name.Space)
	//logVerbose("Child:%s, ns:%s", xmlDoc.Root.Children[0].Name.Local, xmlDoc.Root.Children[0].Name.Space)

	/*
		<presence xml:lang='en'>
		  <show>dnd</show>
		  <status>Wooing Juliet</status>
		  <status xml:lang='cz'>Ja dvo&#x0159;&#x00ED;m Juliet</status>
		  <priority>1</priority>
		</presence>
	*/
	node := xmlDoc.SelectNode("", "presence")
	if node != nil {
		logVerbose("GetMessageType:Presence")
		return Presence, nil
	}
	/*
		<message
			to='romeo@example.net/orchard'
			from='juliet@example.com/balcony'
			type='chat'
			xml:lang='en'>
		  <body>Art thou not Romeo, and a Montague?</body>
		  <thread>e0ffe42b28561960c6b12b944a092794b9683a38</thread>
		</message>
	*/
	node = xmlDoc.SelectNode("", "message")
	if node != nil {
		logVerbose("GetMessageType:Message")
		return Message, nil
	}

	node = xmlDoc.SelectNode("", "iq")
	if node != nil {
		logVerbose("GetMessageType:IQ, looking for specifics")

		/* google chat: 
		<iq from="gmail.com" type="result" id="sess_1"/>	
		*/
		if strings.Contains(node.GetAttr("", "id"), "sess") {
			logVerbose("GetMessageType:Session, google style")
			return Session, nil
		}

		/* facebook: 
		<iq type="result" from="chat.facebook.com" id="sess_1">
			<session xmlns="urn:ietf:params:xml:ns:xmpp-session"/>
		</iq>"
		*/
		node = xmlDoc.SelectNode(nsSession, "session")
		if node != nil {
			logVerbose("GetMessageType:Session")
			return Session, nil
		}

		/* VCARD
		<iq from='juliet@capulet.com' to='romeo@montague.net/orchard' type='result' id='vc2'>
			<vCard xmlns='vcard-temp'>
				<BDAY>1476-06-09</BDAY>
				<ADR>
					<CTRY>Italy</CTRY>
					<LOCALITY>Verona</LOCALITY>
					<HOME/>
				</ADR>
				<NICKNAME/>
				<N>
					<GIVEN>Juliet</GIVEN>
					<FAMILY>Capulet</FAMILY>
				</N>
				<EMAIL>jcapulet@shakespeare.lit</EMAIL>
				<PHOTO>
					<TYPE>image/jpeg</TYPE>
					<BINVAL>
					Base64-encoded-avatar-file-here!
					</BINVAL>
				</PHOTO>
			</vCard>
		</iq>
		*/
		node = xmlDoc.SelectNode(nsVcard, "vCard")
		if node != nil {
			logVerbose("GetMessageType:VCard")
			return VCard, nil
		}

		/* BIND/JID
		<iq type='result' id='bind_2'>
		  <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>
			<jid>somenode@example.com/someresource</jid>
		  </bind>
		</iq>
		*/
		node = xmlDoc.SelectNode(nsBind, "jid")
		if node != nil {
			logVerbose("GetMessageType:JID")
			return JID, nil
		}
	}

	/*
		<iq to='juliet@example.com/balcony' type='result' id='roster_1'>
		  <query xmlns='jabber:iq:roster'>
			<item jid='romeo@example.net'
			      name='Romeo'
			      subscription='both'>
			  <group>Friends</group>
			</item>
		  </query>
		</iq>
	*/
	node = xmlDoc.SelectNode(nsRoster, "query")
	if node != nil {
		logVerbose("GetMessageType:Roster")
		return Roster, nil
	}

	/*
		<stream:features>
		  <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>
			<required/>
		  </starttls>
		  <mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
			<mechanism>DIGEST-MD5</mechanism>
			<mechanism>PLAIN</mechanism>
		  </mechanisms>
		</stream:features>
	*/
	node = xmlDoc.SelectNode(nsStream, "features")
	if node != nil {
		logVerbose("GetMessageType:features")
		return Features, nil
	}
	node = xmlDoc.SelectNode("stream", "features")
	if node != nil {
		logVerbose("GetMessageType:features")
		return Features, nil
	}

	/*
		<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
		cmVhbG09InNvbWVyZWFsbSIsbm9uY2U9Ik9BNk1HOXRFUUdtMmhoIixxb3A9ImF1dGgi
		LGNoYXJzZXQ9dXRmLTgsYWxnb3JpdGhtPW1kNS1zZXNzCg==
		</challenge>
	*/
	node = xmlDoc.SelectNode(nsSASL, "challenge")
	if node != nil {
		logVerbose("GetMessageType:challenge")
		return Challenge, nil
	}

	/*
		<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>
	*/
	node = xmlDoc.SelectNode(nsSASL, "success")
	if node != nil {
		logVerbose("GetMessageType:success")
		return Success, nil
	}

	/*
		<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
		  <incorrect-encoding/>
		</failure>
	*/
	node = xmlDoc.SelectNode(nsSASL, "failure")
	if node != nil {
		logVerbose("GetMessageType:Failure")
		return SASLFailure, nil
	}

	/*
		<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
	*/
	node = xmlDoc.SelectNode(nsTLS, "proceed")
	if node != nil {
		logVerbose("GetMessageType:proceed")
		return Proceed, nil
	}

	logVerbose("GetMessageType:unknown")
	return Unknown, nil
}

func getAvatars(msg string) ([]AvatarUpdate, os.Error) {
	xmlDoc := xmlx.New()
	var updates []AvatarUpdate
	var tempUpdate AvatarUpdate

	if err := xmlDoc.LoadString(msg); err != nil {
		logError(err)
		return nil, err
	}

	/* VCARD
	<iq from='juliet@capulet.com' to='romeo@montague.net/orchard' type='result' id='vc2'>
		<vCard xmlns='vcard-temp'>
			<BDAY>1476-06-09</BDAY>
			<ADR>
				<CTRY>Italy</CTRY>
				<LOCALITY>Verona</LOCALITY>
				<HOME/>
			</ADR>
			<NICKNAME/>
			<N>
				<GIVEN>Juliet</GIVEN>
				<FAMILY>Capulet</FAMILY>
			</N>
			<EMAIL>jcapulet@shakespeare.lit</EMAIL>
			<PHOTO>
				<TYPE>image/jpeg</TYPE>
				<BINVAL>
				Base64-encoded-avatar-file-here!
				</BINVAL>
			</PHOTO>
		</vCard>
	</iq>
	*/

	fromjid := ""
	iqnodes := xmlDoc.SelectNodes("", "iq")
	for _, iqnode := range iqnodes {
		fromjid = iqnode.GetAttr("", "from")
		logVerbose("photo from: %s", fromjid)

		node := iqnode.SelectNode(nsVcard, "PHOTO")
		if node != nil {
			phototype := node.GetValue(nsVcard, "TYPE")
			logVerbose("photo type: %s", phototype)

			base64pic := node.GetValue(nsVcard, "BINVAL")
			if base64pic != "" {
				//base64 has \r\n legal, but xml can strip off the \r
				//see http://lists.w3.org/Archives/Public/w3c-ietf-xmldsig/2001AprJun/0188.html
				//safer to just remove \n (0xa) altogether, or maybe replace it with (0xda)
				base64pic = strings.Replace(base64pic, "\n", "", -1)
				dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(base64pic)))
				if _, err := base64.StdEncoding.Decode(dbuf, []byte(base64pic)); err != nil {
					logError(err)
					return updates, err
				}
				tempUpdate.JID = fromjid
				tempUpdate.Photo = dbuf
				tempUpdate.Type = phototype
				updates = append(updates, tempUpdate)
			}
		}
	}

	return updates, nil
}

func getJID(msg string) (string, os.Error) {
	xmlDoc := xmlx.New()

	if err := xmlDoc.LoadString(msg); err != nil {
		logError(err)
		return "", err
	}

	/*
		<iq type='result' id='bind_2'>
		  <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>
			<jid>somenode@example.com/someresource</jid>
		  </bind>
		</iq>
	*/
	node := xmlDoc.SelectNode(nsBind, "jid")
	if node != nil {
		logVerbose("jid value: %s", node.Value)
		return node.Value, nil
	}

	logVerbose("jid value not found")
	return "", os.NewError(fmt.Sprintf("No JID found in: %s", msg))
}

func getMessage(msg string) (MessageUpdate, os.Error) {
	var tempMessage MessageUpdate

	xmlDoc := xmlx.New()
	if err := xmlDoc.LoadString(msg); err != nil {
		logError(err)
		return tempMessage, err
	}

	/*
		<message
			to='romeo@example.net/orchard'
			from='juliet@example.com/balcony'
			type='chat'
			xml:lang='en'>
		  <body>Art thou not Romeo, and a Montague?</body>
		  <thread>e0ffe42b28561960c6b12b944a092794b9683a38</thread>
		</message>
	*/
	node := xmlDoc.SelectNode("", "message")
	if node != nil {
		tempMessage.JID = node.GetAttr("", "from")
		tempMessage.Type = node.GetAttr("", "type")
		tempMessage.Body = node.GetValue("", "body")

		node = xmlDoc.SelectNode(nsChatstates, "composing")
		if node != nil {
			tempMessage.State = "composing"
		} else {
			node = xmlDoc.SelectNode(nsChatstates, "active")
			if node != nil {
				tempMessage.State = "active"
			}
		}
	}

	return tempMessage, nil
}

func getPresenceUpdates(msg string) ([]PresenceUpdate, os.Error) {
	var updates []PresenceUpdate
	var tempUpdate PresenceUpdate

	xmlDoc := xmlx.New()
	if err := xmlDoc.LoadString(msg); err != nil {
		logError(err)
		return nil, err
	}

	/*
		<presence from='juliet@example.com/balcony' to='romeo@example.net/orchard' xml:lang='en'>
			<show>away</show>
			<status>be right back</status>
			<priority>0</priority>
			<x xmlns="vcard-temp:x:update">
				<photo>8668b9b00eeb2e3a51ea5758e7cff9f7c5780309</photo>
			</x>
		</presence>
	*/
	nodes := xmlDoc.SelectNodes("", "presence")
	for _, node := range nodes {
		//sometimes jid in presence update comes with /resource, split it off
		tempUpdate.JID = (strings.Split(node.GetAttr("", "from"), "/", -1))[0]
		tempUpdate.Type = node.GetAttr("", "type")
		tempUpdate.Show = node.GetValue("", "show")
		tempUpdate.Status = node.GetValue("", "status")
		//photo present? http://xmpp.org/extensions/xep-0153.html
		if tempnode := node.SelectNode(nsVcardUpdate, "x"); tempnode != nil {
			tempUpdate.PhotoHash = tempnode.GetValue(nsVcardUpdate, "photo")
			logVerbose("PhotoHash In Presence Update: %s", tempUpdate.PhotoHash)
		}
		updates = append(updates, tempUpdate)
	}

	return updates, nil
}

func getRoster(msg string) (map[string]*Contact, os.Error) {
	contactMap := make(map[string]*Contact)

	xmlDoc := xmlx.New()
	if err := xmlDoc.LoadString(msg); err != nil {
		logError(err)
		return nil, err
	}

	/*
		<iq to='juliet@example.com/balcony' type='result' id='roster_1'>
		  <query xmlns='jabber:iq:roster'>
			<item jid='romeo@example.net'
			      name='Romeo'
			      subscription='both'>
			  <group>Friends</group>
			</item>
		  </query>
		</iq>
	*/
	nodes := xmlDoc.SelectNodes("jabber:iq:roster", "item")
	for _, node := range nodes {
		tempContact := new(Contact)
		tempContact.Name = node.GetAttr("", "name")
		tempContact.Subscription = node.GetAttr("", "subscription")
		tempContact.JID = node.GetAttr("", "jid")
		tempContact.Show = "offline"
		tempContact.Status = ""
		contactMap[tempContact.JID] = tempContact
	}

	return contactMap, nil
}

/**
 * For each feature type, return a slice of values
 */
func getFeatures(msg string) (map[string][]string, os.Error) {
	keyValueMap := make(map[string][]string)

	xmlDoc := xmlx.New()
	if err := xmlDoc.LoadString(msg); err != nil {
		logError(err)
		return nil, err
	}

	/*
		<stream:features>
		  <mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
			<mechanism>DIGEST-MD5</mechanism>
			<mechanism>PLAIN</mechanism>
		  </mechanisms>
		</stream:features>
	*/
	nodes := xmlDoc.SelectNodes(nsSASL, "mechanism")
	for _, node := range nodes {
		keyValueMap["mechanism"] = append(keyValueMap["mechanism"], node.Value)
		logVerbose("mechanism: %s", node.Value)
	}

	/*
		stream:features>
		  <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>
		</stream:features>
	*/
	nodes = xmlDoc.SelectNodes(nsBind, "bind")
	for _, node := range nodes {
		keyValueMap["bind"] = append(keyValueMap["bind"], node.Value)
		logVerbose("bind: %s", node.Value)
	}

	/*
		stream:features>
		  <session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>
		</stream:features>
	*/
	nodes = xmlDoc.SelectNodes(nsSession, "session")
	for _, node := range nodes {
		keyValueMap["session"] = append(keyValueMap["session"], node.Value)
		logVerbose("session: %s", node.Value)
	}

	return keyValueMap, nil
}

/**
 *  for challenge type, determine appropriate response
 * 	responding to an SASL challenge: http://www.ietf.org/rfc/rfc2831.txt 
 **/
func getChallengeResp_DIGESTMD5(challenge string, username string, password string, cnonce string, forceRealm string) (string, os.Error) {
	keyValueMap := make(map[string]string)
	xmlDoc := xmlx.New()

	if err := xmlDoc.LoadString(challenge); err != nil {
		logError(err)
		return "", err
	}

	node := xmlDoc.SelectNode(nsSASL, "challenge")
	if node == nil {
		return "", os.NewError(fmt.Sprintf("No Challenge in: ", challenge))
	}
	logVerbose("urn:ietf:params:xml:ns:xmpp-sasl,challenge Node found")
	logVerbose("challenge: %s", node.Value)

	/*
		<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
		cmVhbG09InNvbWVyZWFsbSIsbm9uY2U9Ik9BNk1HOXRFUUdtMmhoIixxb3A9ImF1dGgi
		LGNoYXJzZXQ9dXRmLTgsYWxnb3JpdGhtPW1kNS1zZXNzCg==
		</challenge>
		is base64 encoded to begin with based on IMAP4 AUTHENTICATE command [RFC 2060],

		decodes to something like

		digest-challenge  =
			1#( realm | nonce | qop-options | stale | maxbuf | charset
			    algorithm | cipher-opts | auth-param )
			ex:	
			realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",qop="auth",
			algorithm=md5-sess,charset=utf-8
	*/

	dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(node.Value)))
	if _, err := base64.StdEncoding.Decode(dbuf, []byte(node.Value)); err != nil {
		logVerbose("Error Decoding.")
	}
	logVerbose("Decoded: %s", dbuf)

	//tokenize challenge properties, and store in map for convenience
	//some of them will be reused to send the response
	tokens := strings.Split(string(dbuf), ",", -1)
	for _, tok := range tokens {
		logVerbose("token: " + tok)
		pair := strings.Split(tok, "=", 2)
		logVerbose(pair[0] + ":" + pair[1])
		keyValueMap[pair[0]] = strings.Trim(pair[1], "'\"")
	}

	/*
		digest-response  = 
			1#( username | realm | nonce | cnonce |
				nonce-count | qop | digest-uri | response |
				maxbuf | charset | cipher | authzid |
				auth-param )
			ex:
				charset=utf-8,username="chris",realm="elwood.innosoft.com",
				nonce="OA6MG9tEQGm2hh",nc=00000001,cnonce="OA6MHXh6VqTrRk",
				digest-uri="imap/elwood.innosoft.com",
				response=d388dad90d4bbd760a152321f2143af7,qop=auth
	*/

	/*	
		from the digest response above, 'response' is complicated

		from RFC2831:

		Let H(s) be the 16 octet MD5 hash [RFC 1321] of the octet string s.

		Let KD(k, s) be H({k, ":", s}), i.e., the 16 octet hash of the string
		k, a colon and the string s.

		Let HEX(n) be the representation of the 16 octet MD5 hash n as a
		string of 32 hex digits (with alphabetic characters always in lower
		case, since MD5 is case sensitive).

		response-value  =	HEX( 
								KD ( 
									  HEX(H(A1)), { nonce-value, ":" nc-value, ":", cnonce-value, ":", qop-value, ":", HEX(H(A2)) }
								   )
							   )

		A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
			 ":", nonce-value, ":", cnonce-value, ":", authzid-value }
		A2       = { "AUTHENTICATE:", digest-uri-value }
	*/

	var realm string

	if forceRealm != "" {
		realm = forceRealm
	} else {
		realm = keyValueMap["realm"]
	}

	/* HEX(H(A1)) */
	hash := md5.New()
	hash.Write([]byte(username + ":" + realm + ":" + password))
	X := hash.Sum()
	A1 := append(X, []byte(":"+keyValueMap["nonce"]+":"+cnonce)...)
	hash.Reset()
	hash.Write(A1)
	HA1 := hash.Sum()
	HEXHA1 := strings.ToLower(fmt.Sprintf("%x", HA1))
	logVerbose("HEXHA1: %s", HEXHA1)

	/* HEX(H(A2)) */
	digesturi := "xmpp/" + realm
	A2 := "AUTHENTICATE:" + digesturi
	hash.Reset()
	hash.Write([]byte(A2))
	HA2 := string(hash.Sum())
	HEXHA2 := strings.ToLower(fmt.Sprintf("%x", HA2))
	logVerbose("HEXHA2: %s", HEXHA2)

	hash.Reset()
	hash.Write([]byte(HEXHA1 + ":" + keyValueMap["nonce"] + ":" + noncecount + ":" + cnonce + ":" + keyValueMap["qop"] + ":" + HEXHA2))
	KD := string(hash.Sum())
	HEXKD := strings.ToLower(fmt.Sprintf("%x", KD))
	logVerbose("HEXKD: %s", HEXKD)

	reply := "username='" + username + "'" +
		",realm='" + realm + "'" +
		",nonce='" + keyValueMap["nonce"] + "'" +
		",cnonce='" + cnonce + "'" +
		",nc=" + noncecount +
		",qop=" + keyValueMap["qop"] +
		",digest-uri='" + digesturi + "'" +
		",response=" + HEXKD +
		",charset=" + keyValueMap["charset"]
	//",authzid='" + authzid + "'" //authzid in RFC2222
	reply = strings.Replace(reply, "'", "\"", -1)

	//is base64 encoded to begin with based on IMAP4 AUTHENTICATE command [RFC 2060],
	logVerbose("formed reply: %s", reply)
	base64buf := make([]byte, base64.StdEncoding.EncodedLen(len(reply)))
	base64.StdEncoding.Encode(base64buf, []byte(reply))

	return "<response xmlns='" + nsSASL + "'>" + string(base64buf) + "</response>", nil
}
