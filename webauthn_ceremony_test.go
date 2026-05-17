package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// cborEncodeMinimal emits CBOR for the subset of types used by the WebAuthn
// fixtures: positive/negative int, byte string, text string, and small maps.
// It is hand-rolled to keep the test self-contained.
func cborEncodeMinimal(v any) []byte {
	switch x := v.(type) {
	case int:
		return cborEncodeMinimal(int64(x))
	case int64:
		if x >= 0 {
			return cborMajorLen(0, uint64(x))
		}
		return cborMajorLen(1, uint64(-1-x))
	case []byte:
		return append(cborMajorLen(2, uint64(len(x))), x...)
	case string:
		return append(cborMajorLen(3, uint64(len(x))), x...)
	case map[any]any:
		out := cborMajorLen(5, uint64(len(x)))
		for k, val := range x {
			out = append(out, cborEncodeMinimal(k)...)
			out = append(out, cborEncodeMinimal(val)...)
		}
		return out
	}
	panic(fmt.Sprintf("cborEncodeMinimal: unsupported type %T", v))
}

func cborMajorLen(major byte, n uint64) []byte {
	head := major << 5
	switch {
	case n < 24:
		return []byte{head | byte(n)}
	case n <= 0xff:
		return []byte{head | 24, byte(n)}
	case n <= 0xffff:
		return []byte{head | 25, byte(n >> 8), byte(n)} //nolint:gosec // Bounded by the case guard.
	default:
		buf := make([]byte, 5)
		buf[0] = head | 26
		binary.BigEndian.PutUint32(buf[1:], uint32(n)) //nolint:gosec // Test fixture; size bounded by caller.
		return buf
	}
}

func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p256: %v", err)
	}
	return key
}

func cosePublicKey(pub *ecdsa.PublicKey) []byte {
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	// Pad to 32 bytes per COSE expectations.
	if len(x) < 32 {
		x = append(make([]byte, 32-len(x)), x...)
	}
	if len(y) < 32 {
		y = append(make([]byte, 32-len(y)), y...)
	}
	return cborEncodeMinimal(map[any]any{
		int64(1):  int64(2),  // kty = EC2
		int64(3):  int64(-7), // alg = ES256
		int64(-1): int64(1),  // crv = P-256
		int64(-2): x,
		int64(-3): y,
	})
}

func buildAttestedAuthData(rpID string, credID []byte, cosePub []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	var buf []byte
	buf = append(buf, rpHash[:]...)
	buf = append(buf, 0x41)                // UP|AT
	buf = append(buf, 0, 0, 0, 0)          // signCount = 0
	buf = append(buf, make([]byte, 16)...) // AAGUID
	credLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credLen, uint16(len(credID))) //nolint:gosec // Test fixture; credID is short.
	buf = append(buf, credLen...)
	buf = append(buf, credID...)
	buf = append(buf, cosePub...)
	return buf
}

func buildAttestationObject(authData []byte) []byte {
	return cborEncodeMinimal(map[any]any{
		"fmt":      "none",
		"attStmt":  map[any]any{},
		"authData": authData,
	})
}

func enrollSessionFor(t *testing.T, broker *Broker, userID string) string {
	t.Helper()
	if _, err := broker.createSession(httptest.NewRecorder(), userID, true); err != nil {
		t.Fatalf("create session: %v", err)
	}
	for id, sess := range broker.store.RuntimeSnapshot().Sessions {
		if sess.UserID == userID {
			return id
		}
	}
	t.Fatal("session id not found")
	return ""
}

func beginRegistration(t *testing.T, broker *Broker, sid string) string {
	t.Helper()
	beginReq := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin", nil)
	addSessionCookie(beginReq, sid)
	beginRR := httptest.NewRecorder()
	broker.handleWebAuthnRegisterBegin(beginRR, beginReq)
	if beginRR.Code != http.StatusOK {
		t.Fatalf("begin status = %d body=%s", beginRR.Code, beginRR.Body.String())
	}
	var beginBody struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(beginRR.Body.Bytes(), &beginBody); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	return beginBody.PublicKey.Challenge
}

func beginLogin(t *testing.T, broker *Broker, username string) string {
	t.Helper()
	body := strings.NewReader(`{"username":"` + username + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", body)
	req.RemoteAddr = "127.0.0.1:1111"
	rr := httptest.NewRecorder()
	broker.handleWebAuthnLoginBegin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login begin status = %d body=%s", rr.Code, rr.Body.String())
	}
	var beginBody struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &beginBody); err != nil {
		t.Fatalf("decode login begin: %v", err)
	}
	return beginBody.PublicKey.Challenge
}

func registerSyntheticCredential(t *testing.T, broker *Broker, sid string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	challenge := beginRegistration(t, broker, sid)
	key := newP256Key(t)
	credID := []byte("credential-id-bytes")
	authData := buildAttestedAuthData(broker.cfg.WebAuthn.RPID, credID, cosePublicKey(&key.PublicKey))
	attObj := buildAttestationObject(authData)

	clientData := webauthnClientData{Type: "webauthn.create", Challenge: challenge, Origin: broker.cfg.WebAuthn.Origins[0]}
	cdBytes, _ := json.Marshal(clientData)
	body := map[string]any{
		"rawId": base64.RawURLEncoding.EncodeToString(credID),
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdBytes),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObj),
		},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", strings.NewReader(string(bodyBytes)))
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleWebAuthnRegisterFinish(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("finish status = %d body=%s", rr.Code, rr.Body.String())
	}
	return key, credID
}

func loginWithSyntheticCredential(t *testing.T, broker *Broker, username string, key *ecdsa.PrivateKey, credID []byte) {
	t.Helper()
	loginChallenge := beginLogin(t, broker, username)
	authData := assertionAuthDataBytes(t, broker.cfg.WebAuthn.RPID, 1)
	clientData := webauthnClientData{Type: "webauthn.get", Challenge: loginChallenge, Origin: broker.cfg.WebAuthn.Origins[0]}
	cdBytes, _ := json.Marshal(clientData)
	clientHash := sha256.Sum256(cdBytes)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body := map[string]any{
		"rawId": base64.RawURLEncoding.EncodeToString(credID),
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdBytes),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
		},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", strings.NewReader(string(bodyBytes)))
	req.RemoteAddr = "127.0.0.1:2222"
	rr := httptest.NewRecorder()
	broker.handleWebAuthnLoginFinish(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login finish status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestWebAuthnRegistrationCeremony(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.cfg.WebAuthn.RPID = "broker.example"
	broker.cfg.WebAuthn.Origins = []string{"http://broker.example"}

	sid := enrollSessionFor(t, broker, "alice")
	key, credID := registerSyntheticCredential(t, broker, sid)

	user, _ := broker.store.GetUser("alice")
	if len(user.WebAuthnCredentials) != 1 {
		t.Fatalf("creds = %#v", user.WebAuthnCredentials)
	}

	loginWithSyntheticCredential(t, broker, "alice", key, credID)

	user, _ = broker.store.GetUser("alice")
	if user.WebAuthnCredentials[0].SignCount != 1 {
		t.Fatalf("sign count not updated: %d", user.WebAuthnCredentials[0].SignCount)
	}
}

func assertionAuthDataBytes(t *testing.T, rpID string, signCount uint32) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 0, 37)
	buf = append(buf, rpHash[:]...)
	buf = append(buf, 0x01) // UP only
	cnt := make([]byte, 4)
	binary.BigEndian.PutUint32(cnt, signCount)
	buf = append(buf, cnt...)
	return buf
}

func TestVerifyAssertionAuthDataErrors(t *testing.T) {
	if _, err := verifyAssertionAuthData(nil, "x"); err == nil {
		t.Fatal("nil authData should fail")
	}
	short := make([]byte, 36)
	if _, err := verifyAssertionAuthData(short, "x"); err == nil {
		t.Fatal("short authData should fail")
	}
	rpHash := sha256.Sum256([]byte("known"))
	good := append([]byte{}, rpHash[:]...)
	good = append(good, 0x01)
	good = append(good, 0, 0, 0, 7)
	if _, err := verifyAssertionAuthData(good, "different-rp"); err == nil {
		t.Fatal("wrong rpID should fail")
	}
	if _, err := verifyAssertionAuthData(append(append([]byte{}, rpHash[:]...), make([]byte, 5)...), "known"); err == nil {
		t.Fatal("missing UP flag should fail")
	}
	signCount, err := verifyAssertionAuthData(good, "known")
	if err != nil || signCount != 7 {
		t.Fatalf("good case: signCount=%d err=%v", signCount, err)
	}
}

func TestVerifyWebAuthnAttestationRejectsBadInputs(t *testing.T) {
	broker := newLogoutTestBroker(t)

	// Garbage rawId.
	req := webauthnAttestationResponse{RawID: "!!!"}
	if _, err := broker.verifyWebAuthnAttestation(req, "challenge"); err == nil {
		t.Fatal("bad rawId should fail")
	}

	// Valid rawId, bad clientDataJSON encoding.
	req = webauthnAttestationResponse{RawID: base64.RawURLEncoding.EncodeToString([]byte("id"))}
	req.Response.ClientDataJSON = "!!!"
	if _, err := broker.verifyWebAuthnAttestation(req, "challenge"); err == nil {
		t.Fatal("bad clientDataJSON should fail")
	}

	// Wrong type field.
	cd := webauthnClientData{Type: "webauthn.get", Challenge: "abc", Origin: "http://broker.example"}
	cdBytes, _ := json.Marshal(cd)
	req.Response.ClientDataJSON = base64.RawURLEncoding.EncodeToString(cdBytes)
	if _, err := broker.verifyWebAuthnAttestation(req, "abc"); err == nil {
		t.Fatal("wrong clientData.type should fail")
	}
}

func TestVerifyWebAuthnAssertionRejectsBadInputs(t *testing.T) {
	broker := newLogoutTestBroker(t)
	// Wrong type.
	if err := broker.verifyWebAuthnAssertion(webauthnAssertionResponse{}, "u", "c", []byte("{}"), webauthnClientData{Type: "webauthn.create"}); err == nil {
		t.Fatal("wrong type should fail")
	}
}

func TestParseAttestedAuthDataAndCOSEKey(t *testing.T) {
	key := newP256Key(t)
	cose := cosePublicKey(&key.PublicKey)
	authData := buildAttestedAuthData("rp.example", []byte("idid"), cose)
	parsed, err := parseAttestedAuthData(authData, "rp.example")
	if err != nil {
		t.Fatalf("parseAttestedAuthData: %v", err)
	}
	if string(parsed.CredentialID) != "idid" {
		t.Fatalf("credID = %q", parsed.CredentialID)
	}
	pub, err := parseCOSEES256PublicKey(parsed.COSEPublicKey)
	if err != nil {
		t.Fatalf("parseCOSEES256PublicKey: %v", err)
	}
	if pub.X.Cmp(key.X) != 0 || pub.Y.Cmp(key.Y) != 0 {
		t.Fatal("recovered key coordinates do not match")
	}

	// Tampered rpId hash.
	broken := append([]byte{}, authData...)
	broken[0] ^= 0xff
	if _, err := parseAttestedAuthData(broken, "rp.example"); err == nil {
		t.Fatal("tampered rpId hash should fail")
	}

	// Missing UP flag.
	noUP := append([]byte{}, authData...)
	noUP[32] = 0x40
	if _, err := parseAttestedAuthData(noUP, "rp.example"); err == nil {
		t.Fatal("missing UP flag should fail")
	}
}

// silence unused import warning when tests are trimmed.
var _ = time.Second
