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
	"strings"
	"time"

	"github.com/armanlife/firefox-vpn-client/core/internal/accounts"
	"github.com/armanlife/firefox-vpn-client/core/internal/fxa"
	"github.com/armanlife/firefox-vpn-client/core/internal/proxy"
)

// The keymaker's public key (Ed25519, base64). A key is trusted only when
// this key signed it.
const foxyKeyPublic = "hA5+kmj6X7JrqYWraZQY+q09q72mNUJx2aLPNnX/Ntw="

// Codes of a keyError; the apps say them in their language.
const (
	KeyErrInvalid  = "key_invalid"  // not an FV1 key, or the signature fails
	KeyErrExpired  = "key_expired"  // the key carries an expiry that passed
	KeyErrRejected = "key_rejected" // FxA refused the token inside the key
	KeyErrNetwork  = "key_network"  // Mozilla could not be reached
)

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
	RT   string `json:"rt"`  // the Firefox Account refresh token
	Gist string `json:"gist"`
	GT   string `json:"gt"`
}

// parseFoxyKey checks the FV1 envelope and its signature and returns the
// payload.
func parseFoxyKey(key string) (*foxyKeyPayload, error) {
	key = strings.TrimSpace(key)
	// Tolerate a "FoxyVPN:" prefix (sharing apps sometimes add one) and
	// line breaks inside the key.
	key = strings.TrimPrefix(key, "FoxyVPN: ")
	key = strings.TrimPrefix(key, "FoxyVPN:")
	key = strings.Join(strings.Fields(key), "")
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
			return accounts.Account{}, keyErr(KeyErrRejected, "", err)
		}
		if code := proxy.FailureCode(err); code == proxy.FailureNoNetwork || code == proxy.FailureUnreachable {
			return accounts.Account{}, keyErr(KeyErrNetwork, "", err)
		}
		return accounts.Account{}, keyErr(KeyErrRejected, "", err)
	}
	email, err := fxa.ProfileEmail(ctx, tok.AccessToken)
	if err != nil {
		if errors.Is(err, fxa.ErrReauthRequired) {
			return accounts.Account{}, keyErr(KeyErrRejected, "", err)
		}
		if code := proxy.FailureCode(err); code == proxy.FailureNoNetwork || code == proxy.FailureUnreachable {
			return accounts.Account{}, keyErr(KeyErrNetwork, "", err)
		}
		return accounts.Account{}, keyErr(KeyErrNetwork, "", err)
	}
	acc, err := d.addSignedInAccount(email, "", tok)
	if err != nil {
		return accounts.Account{}, err
	}
	return acc, nil
}
