package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The real keymaker key is not (and must never be) in the test tree: the
// tests swap in their own keypair and mint keys with it.
var testPub, testPriv = func() (string, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(pub), priv
}()

type testPayload struct {
	V    int    `json:"v"`
	Name string `json:"name"`
	Gb   int64  `json:"gb"`
	Mb   int64  `json:"mb"`
	Exp  int64  `json:"exp"`
	ID   string `json:"id"`
	RT   string `json:"rt"`
	Gist string `json:"gist"`
	GT   string `json:"gt"`
}

func mintTestKey(t *testing.T, p testPayload) string {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	sig := ed25519.Sign(testPriv, []byte(payload))
	return "FV1." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func validPayload() testPayload {
	return testPayload{V: 1, Name: "لیلا", Gb: 50, ID: "abcd1234", RT: "rt-token", Gist: "gist", GT: "gt"}
}

func TestParseFoxyKeyAcceptsACleanKey(t *testing.T) {
	saved := foxyKeyPublic
	foxyKeyPublic = testPub
	defer func() { foxyKeyPublic = saved }()

	kp, err := parseFoxyKey(mintTestKey(t, validPayload()))
	if err != nil {
		t.Fatalf("clean key rejected: %v", err)
	}
	if kp.RT != "rt-token" || kp.Gb != 50 || kp.Name != "لیلا" {
		t.Fatalf("wrong payload: %+v", kp)
	}
}

func TestParseFoxyKeyToleratesJunkAroundAndInside(t *testing.T) {
	saved := foxyKeyPublic
	foxyKeyPublic = testPub
	defer func() { foxyKeyPublic = saved }()

	key := mintTestKey(t, validPayload())
	// what a Persian chat app does to a pasted key: a caption, RTL marks,
	// zero-width chars inside, line breaks, a trailing label
	const rlm = "\u200F"
	const zwsp = "\u200B"
	const nbsp = "\u00A0"
	noisy := rlm + "کلید فاکسی:" + rlm + " FoxyVPN: " +
		strings.ReplaceAll(key, ".", zwsp+".\n"+nbsp) + rlm

	kp, err := parseFoxyKey(noisy)
	if err != nil {
		t.Fatalf("noisy key rejected: %v", err)
	}
	if kp.RT != "rt-token" {
		t.Fatalf("wrong payload: %+v", kp)
	}
}

func TestParseFoxyKeyWithoutFV1PrefixStillFails(t *testing.T) {
	saved := foxyKeyPublic
	foxyKeyPublic = testPub
	defer func() { foxyKeyPublic = saved }()

	// a 10-digit style code or any text without the FV1 envelope is not a key
	if _, err := parseFoxyKey("1234567890"); err == nil {
		t.Fatal("a bare number was accepted")
	}
	if _, err := parseFoxyKey(""); err == nil {
		t.Fatal("an empty key was accepted")
	}
}

func TestParseFoxyKeyRejectsWrongSignature(t *testing.T) {
	saved := foxyKeyPublic
	foxyKeyPublic = testPub
	defer func() { foxyKeyPublic = saved }()

	key := mintTestKey(t, validPayload())
	parts := strings.Split(key, ".")
	// flip one character of the payload: the signature no longer matches
	payload := []rune(parts[1])
	if payload[0] == 'A' {
		payload[0] = 'B'
	} else {
		payload[0] = 'A'
	}
	tampered := "FV1." + string(payload) + "." + parts[2]
	if _, err := parseFoxyKey(tampered); err == nil {
		t.Fatal("a tampered key was accepted")
	}
}

func TestParseFoxyKeyRejectsExpired(t *testing.T) {
	saved := foxyKeyPublic
	foxyKeyPublic = testPub
	defer func() { foxyKeyPublic = saved }()

	expired := validPayload()
	expired.Exp = time.Now().Add(-24 * time.Hour).Unix()
	if _, err := parseFoxyKey(mintTestKey(t, expired)); err == nil {
		t.Fatal("an expired key was accepted")
	}
}
