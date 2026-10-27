package fxa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ProfileEmail asks FxA who an OAuth access token belongs to. The token
// must carry the "profile" scope (the client's own scope does).
//
// The profile lives on its own server (profile.accounts.firefox.com), not
// on the auth server: api.accounts.firefox.com has no /profile route and
// answers it with HTTP 404 (errno 999), which once broke every key
// sign-in — the only flow that must learn the email from the token.
func ProfileEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fxaProfileServer+"/profile", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := fxaDo(ctx, func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, fxaProfileServer+"/profile", nil)
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", "Bearer "+accessToken)
		return r, nil
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", newFxaAPIError(resp.StatusCode, body)
	}
	var profile struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		return "", fmt.Errorf("parsing the profile response: %w", err)
	}
	if profile.Email == "" {
		return "", fmt.Errorf("the profile has no email; the token's scope must include profile")
	}
	return profile.Email, nil
}
