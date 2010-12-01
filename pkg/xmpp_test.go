package gojabber

import (
	"testing"
)

const ref_response = "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>dXNlcm5hbWU9InRlc3QiLHJlYWxtPSJvc1hzdHJlYW0ubG9jYWwiLG5vbmNlPSIzOTI2MTY3MzYiLGNub25jZT0iMDVFMEE2RTctMEI3Qi00NDMwLTk1NDktMEZFMUMyNDRBQkFCIixuYz0wMDAwMDAwMSxxb3A9YXV0aCxkaWdlc3QtdXJpPSJ4bXBwL29zWHN0cmVhbS5sb2NhbCIscmVzcG9uc2U9Mzc5OTFiODcwZTBmNmNjNzU3ZWM3NGM0Nzg3NzQ3MmIsY2hhcnNldD11dGYtOA==</response>"

func TestChallenges(t *testing.T) {
	challenge := "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>bm9uY2U9IjM5MjYxNjczNiIscW9wPSJhdXRoIixjaGFyc2V0PXV0Zi04LGFsZ29yaXRobT1tZDUtc2Vzcw==</challenge>"
	resp, _ := GetChallengeResp_DIGESTMD5(challenge, "test", "secret", "05E0A6E7-0B7B-4430-9549-0FE1C244ABAB", "osXstream.local")
	if resp != ref_response {
		t.Error("Calculated challenge response does not equal reference\n")
		t.Error("Calculated: %s\n", string(resp))
		t.Error("Reference: %s\n", string(ref_response))
	}
}
