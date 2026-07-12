// Package github bridges user identity via GitHub's OAuth app. GitHub is only
// the identity source; the gateway never forwards GitHub tokens downstream.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	authorizeURL = "https://github.com/login/oauth/authorize"
	tokenURL     = "https://github.com/login/oauth/access_token"
	userURL      = "https://api.github.com/user"
)

type Client struct {
	clientID     string
	clientSecret string
	http         *http.Client
}

func New(clientID, clientSecret string) *Client {
	return &Client{
		clientID:     clientID,
		clientSecret: clientSecret,
		http:         &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) AuthURL(state, redirectURI string) string {
	q := url.Values{}
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("scope", "read:user")
	q.Set("allow_signup", "false")
	return authorizeURL + "?" + q.Encode()
}

// Exchange swaps the GitHub authorization code for the user's numeric ID and login.
func (c *Client) Exchange(ctx context.Context, code, redirectURI string) (int64, string, error) {
	accessToken, err := c.exchangeCode(ctx, code, redirectURI)
	if err != nil {
		return 0, "", err
	}
	return c.fetchUser(ctx, accessToken)
}

func (c *Client) exchangeCode(ctx context.Context, code, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode github token response: %w", err)
	}
	if body.Error != "" {
		return "", fmt.Errorf("github token error: %s (%s)", body.Error, body.ErrorDesc)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("github returned no access token")
	}
	return body.AccessToken, nil
}

func (c *Client) fetchUser(ctx context.Context, accessToken string) (int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userURL, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("github /user returned %d", resp.StatusCode)
	}

	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return 0, "", fmt.Errorf("decode github user: %w", err)
	}
	if user.ID == 0 {
		return 0, "", fmt.Errorf("github user has no id")
	}
	return user.ID, user.Login, nil
}
