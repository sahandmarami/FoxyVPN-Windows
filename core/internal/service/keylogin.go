package service

// FoxyVPN key sign-in: a person adds an account by pasting a key (FV1)
// instead of typing an email and a password. The key is minted and signed
// offline by the FoxyVPN keymaker; it carries a Firefox Account refresh
// token, an optional expiry, and a quota note. This file checks the key's
// signature, exchanges the token, learns the account's email from the
// profile, and puts the account into rotation like any other.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/armanlife/firefox-vpn-client/core/internal/accounts"
	"github.com/armanlife/firefox-vpn-client/core/internal/fxa"
	"github.com/armanlife/firefox-vpn-client/core/internal/proxy"
)

// The keymaker's public key (Ed25519, base64). A key is trusted only when
// this key signed it.
var foxyKeyPublic = "hA5+kmj6X7JrqYWraZQY+q09q72mNUJx2aLPNnX/Ntw="

// keyJunkRe strips everything that sneaks into a pasted key but is not part
// of it: spaces and line breaks, non-breaking and other Unicode spaces, and
// the zero-width and bidi control marks (RLM, LRM, ZWNJ, ...) that Persian
// chat apps add when the key travels inside right-to-left text.
var keyJunkRe = regexp.MustCompile(`[\p{Z}\s\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]+`)

// Codes of a keyError; the apps say them in their language.
const (
	KeyErrInvalid  = "key_invalid"  // not an FV1 key, or the signature fails
	KeyErrExpired  = "key_expired"  // the key carries an expiry that passed
	KeyErrRejected = "key_rejected" // FxA refused the token inside the key
	KeyErrNetwork  = "key_network"  // Mozilla could not be reached
)

// shortReason keeps an underlying error for the apps' detail line without
// dumping a whole error body: the first line, at most ~180 runes.
func shortReason(err error) string {
	if err == nil {
		return ""
	}
	text := strings.SplitN(strings.TrimSpace(err.Error()), "\n", 2)[0]
	runes := []rune(text)
	if len(runes) > 180 {
		text = string(runes[:180]) + "…"
	}
	return text
}

// keyError says what went wrong with a key sign-in, with a code the apps
// translate.
type keyError struct {
	code string
	text string
	err  error
}

func (e *keyError) Error() string {
	if e.text != "" {
		return e.text
	}
	return "the FoxyVPN key was not accepted"
}

func (e *keyError) Unwrap() error { return e.err }

func keyErr(code, text string, err error) *keyError {
	return &keyError{code: code, text: text, err: err}
}

// foxyKeyPayload is the JSON inside an FV1 key (base64url, unsigned JSON
// from the keymaker; field names match the Android keymaker's).
type foxyKeyPayload struct {
	V    int    `json:"v"`
	Name string `json:"name"`
	Gb   int64  `json:"gb"`
	Mb   int64  `json:"mb"`
	Exp  int64  `json:"exp"`
	ID   string `json:"id"`
	RT   string `json:"rt"` // the Firefox Account refresh token
	Gist string `json:"gist"`
	GT   string `json:"gt"`
}

// parseFoxyKey checks the FV1 envelope and its signature and returns the
// payload.
func parseFoxyKey(key string) (*foxyKeyPayload, error) {
	// Tolerate whatever the sharing app wrapped around the key: a
	// "FoxyVPN:" label, a Persian caption before it, line breaks inside,
	// and invisible bidi marks. All junk is removed first (replacing it
	// with spaces would split "FV1" from its first dot), then a label
	// prefix is dropped, then everything before the "FV1." envelope.
	key = keyJunkRe.ReplaceAllString(strings.TrimSpace(key), "")
	key = strings.TrimPrefix(key, "FoxyVPN: ")
	key = strings.TrimPrefix(key, "FoxyVPN:")
	if i := strings.Index(key, "FV1."); i > 0 {
		key = key[i:]
	}
	parts := strings.Split(key, ".")
	if len(parts) != 3 || parts[0] != "FV1" || parts[1] == "" || parts[2] == "" {
		return nil, errors.New("this is not a FoxyVPN key")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("this is not a FoxyVPN key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("this is not a FoxyVPN key")
	}
	pub, err := base64.StdEncoding.DecodeString(foxyKeyPublic)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("the keymaker's public key is broken")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(parts[1]), sig) {
		return nil, errors.New("the key's signature does not check out")
	}
	var kp foxyKeyPayload
	if err := json.Unmarshal(payload, &kp); err != nil {
		return nil, errors.New("this is not a FoxyVPN key")
	}
	if kp.V != 1 || kp.RT == "" {
		return nil, errors.New("this key's version is not supported")
	}
	if kp.Exp > 0 && time.Now().Unix() > kp.Exp {
		return nil, fmt.Errorf("the key expired on %s", time.Unix(kp.Exp, 0).Format(time.DateOnly))
	}
	return &kp, nil
}

// signInWithKey adds an account from a FoxyVPN key and returns it.
func (d *Daemon) signInWithKey(ctx context.Context, key string) (accounts.Account, error) {
	kp, err := parseFoxyKey(key)
	if err != nil {
		return accounts.Account{}, keyErr(KeyErrInvalid, "", err)
	}
	if kp.Exp > 0 && time.Now().Unix() > kp.Exp {
		return accounts.Account{}, keyErr(KeyErrExpired, "", fmt.Errorf("the key expired on %s", time.Unix(kp.Exp, 0).Format(time.DateOnly)))
	}
	tok, err := fxa.RefreshToken(ctx, kp.RT)
	if err != nil {
		if errors.Is(err, fxa.ErrReauthRequired) {
			// the token inside the key is dead (rotated away or
			// revoked): the detail says exactly what Mozilla answered
			return accounts.Account{}, keyErr(KeyErrRejected, shortReason(err), err)
		}
		if code := proxy.FailureCode(err); code == proxy.FailureNoNetwork || code == proxy.FailureUnreachable {
			return accounts.Account{}, keyErr(KeyErrNetwork, shortReason(err), err)
		}
		return accounts.Account{}, keyErr(KeyErrRejected, shortReason(err), err)
	}
	email, err := fxa.ProfileEmail(ctx, tok.AccessToken)
	if err != nil {
		if errors.Is(err, fxa.ErrReauthRequired) {
			return accounts.Account{}, keyErr(KeyErrRejected, shortReason(err), err)
		}
		if code := proxy.FailureCode(err); code == proxy.FailureNoNetwork || code == proxy.FailureUnreachable {
			return accounts.Account{}, keyErr(KeyErrNetwork, shortReason(err), err)
		}
		return accounts.Account{}, keyErr(KeyErrNetwork, shortReason(err), err)
	}
	acc, err := d.addSignedInAccount(email, "", tok)
	if err != nil {
		return accounts.Account{}, err
	}
	return acc, nil
}
