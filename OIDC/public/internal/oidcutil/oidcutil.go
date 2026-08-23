// Package oidcutil holds the tiny bits of OIDC/Authorization Code Flow
// plumbing shared between the legit relying party (rp) and the attacker
// demo server. It talks to a real Keycloak instance over HTTP - no
// external dependencies, stdlib only.
package oidcutil

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config describes where the Keycloak realm lives and which client we act as.
type Config struct {
	IssuerBase string // e.g. http://localhost:8080
	Realm      string // e.g. demo
	ClientID   string // e.g. demo-rp (public client, no secret, for demo simplicity)
}

func (c Config) AuthorizeEndpoint() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", c.IssuerBase, c.Realm)
}

func (c Config) TokenEndpoint() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.IssuerBase, c.Realm)
}

// BuildAuthURL builds the Authorization Code Flow request to Keycloak.
func BuildAuthURL(cfg Config, redirectURI, state, scope string) string {
	q := url.Values{}
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("state", state)
	return cfg.AuthorizeEndpoint() + "?" + q.Encode()
}

// TokenResponse mirrors Keycloak's token endpoint JSON body.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// ExchangeCode performs the server-to-server "code -> tokens" leg of the flow
// for a public client (no client_secret).
func ExchangeCode(cfg Config, code, redirectURI string) (*TokenResponse, error) {
	return exchangeCode(cfg, code, redirectURI, "")
}

// ExchangeCodeConfidential is like ExchangeCode but authenticates the client
// with its secret, as required for confidential OIDC clients.
func ExchangeCodeConfidential(cfg Config, clientSecret, code, redirectURI string) (*TokenResponse, error) {
	return exchangeCode(cfg, code, redirectURI, clientSecret)
}

func exchangeCode(cfg Config, code, redirectURI, clientSecret string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", cfg.ClientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, cfg.TokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decoding token response: %w (raw: %s)", err, body)
	}
	if tr.Error != "" {
		return &tr, fmt.Errorf("keycloak error: %s (%s)", tr.Error, tr.ErrorDescription)
	}
	return &tr, nil
}

// DecodeIDTokenUnsafe extracts the JWT payload claims WITHOUT verifying the
// signature. That's fine to inspect claims in this teaching demo, but real
// clients must verify signature/issuer/audience/expiry via the realm's JWKS.
func DecodeIDTokenUnsafe(idToken string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: expected 3 dot-separated parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshalling claims: %w", err)
	}
	return claims, nil
}

// RandString returns a URL-safe random string, used for state/session IDs.
func RandString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means the system RNG is broken
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
