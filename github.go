package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/oauth2"
)

// GitHubConfig holds GitHub API configuration
type GitHubConfig struct {
	Owner string
	Repo  string
	Token string
}

// PublicKeyResponse represents GitHub's public key API response
type PublicKeyResponse struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"`
}

// SecretUpdateRequest represents the request body for updating a secret
type SecretUpdateRequest struct {
	EncryptedValue string `json:"encrypted_value"`
	KeyID          string `json:"key_id"`
}

// NewGitHubConfig creates GitHubConfig from environment variables
func NewGitHubConfig() (*GitHubConfig, error) {
	config := &GitHubConfig{
		Owner: os.Getenv("GITHUB_OWNER"),
		Repo:  os.Getenv("GITHUB_REPO"),
		Token: os.Getenv("GITHUB_TOKEN"),
	}

	return config, nil
}

// UpdateGitHubSecret updates or creates a GitHub repository secret
func UpdateGitHubSecret(refreshToken string, config *GitHubConfig) error {
	if refreshToken == "" {
		return fmt.Errorf("refresh token is empty")
	}

	if config == nil {
		return fmt.Errorf("GitHub config is nil")
	}

	// Get repository public key
	publicKey, keyID, err := getRepositoryPublicKey(config)
	if err != nil {
		return fmt.Errorf("failed to get repository public key: %w", err)
	}

	// Encrypt the refresh token
	encryptedValue, err := encryptSecret(refreshToken, publicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Update the secret
	if err := updateSecret(config, "GOOGLE_REFRESH_TOKEN", encryptedValue, keyID); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}

// getRepositoryPublicKey fetches the repository's public key for secret encryption
func getRepositoryPublicKey(config *GitHubConfig) ([]byte, string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/secrets/public-key",
		config.Owner, config.Repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.Token))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
	}

	var keyResponse PublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResponse); err != nil {
		return nil, "", err
	}

	// Decode base64 public key
	publicKey, err := base64.StdEncoding.DecodeString(keyResponse.Key)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode public key: %w", err)
	}

	return publicKey, keyResponse.KeyID, nil
}

// encryptSecret encrypts a secret value using the repository's public key
func encryptSecret(secretValue string, publicKey []byte) (string, error) {
	// Convert public key to [32]byte
	if len(publicKey) != 32 {
		return "", fmt.Errorf("invalid public key length: expected 32, got %d", len(publicKey))
	}

	var publicKeyArray [32]byte
	copy(publicKeyArray[:], publicKey)

	// Generate ephemeral keypair for encryption
	ephemeralPublicKey, ephemeralSecretKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	// Encrypt the secret
	encrypted := box.Seal(nil, []byte(secretValue), new([24]byte), &publicKeyArray, ephemeralSecretKey)

	// Combine ephemeral public key with encrypted data
	sealed := append(ephemeralPublicKey[:], encrypted...)

	// Encode to base64
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// updateSecret updates or creates a repository secret
func updateSecret(config *GitHubConfig, secretName, encryptedValue, keyID string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/secrets/%s",
		config.Owner, config.Repo, secretName)

	requestBody := SecretUpdateRequest{
		EncryptedValue: encryptedValue,
		KeyID:          keyID,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.Token))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer func() { _ = resp.Body.Close() }()

	// 201 Created or 204 No Content are both success
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update secret (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// UpdateGitHubRefreshToken updates the GOOGLE_REFRESH_TOKEN secret from an OAuth2 token
func UpdateGitHubRefreshToken(token *oauth2.Token) error {
	if token == nil {
		return fmt.Errorf("token is nil")
	}

	if token.RefreshToken == "" {
		return fmt.Errorf("refresh token is empty")
	}

	config, err := NewGitHubConfig()
	if err != nil {
		return fmt.Errorf("failed to create GitHub config: %w", err)
	}

	return UpdateGitHubSecret(token.RefreshToken, config)
}

// UpdateGitHubTokenData updates multiple secrets related to OAuth2 token
func UpdateGitHubTokenData(token *oauth2.Token) error {
	if token == nil {
		return fmt.Errorf("token is nil")
	}

	config, err := NewGitHubConfig()
	if err != nil {
		return fmt.Errorf("failed to create GitHub config: %w", err)
	}

	// Get repository public key once
	publicKey, keyID, err := getRepositoryPublicKey(config)
	if err != nil {
		return fmt.Errorf("failed to get repository public key: %w", err)
	}

	// Update refresh token if present
	if token.RefreshToken != "" {
		encryptedRefresh, err := encryptSecret(token.RefreshToken, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt refresh token: %w", err)
		}

		if err := updateSecret(config, "GOOGLE_REFRESH_TOKEN", encryptedRefresh, keyID); err != nil {
			return fmt.Errorf("failed to update GOOGLE_REFRESH_TOKEN: %w", err)
		}
	}

	// Optionally update access token (useful for workflows that need immediate access)
	if token.AccessToken != "" {
		encryptedAccess, err := encryptSecret(token.AccessToken, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt access token: %w", err)
		}

		if err := updateSecret(config, "GOOGLE_ACCESS_TOKEN", encryptedAccess, keyID); err != nil {
			// Non-fatal: log but continue
			fmt.Printf("Warning: failed to update GOOGLE_ACCESS_TOKEN: %v\n", err)
		}

		// Store expiry as well for reference
		expiryStr := token.Expiry.Format(time.RFC3339)
		encryptedExpiry, err := encryptSecret(expiryStr, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt expiry: %w", err)
		}

		if err := updateSecret(config, "GOOGLE_TOKEN_EXPIRY", encryptedExpiry, keyID); err != nil {
			// Non-fatal: log but continue
			fmt.Printf("Warning: failed to update GOOGLE_TOKEN_EXPIRY: %v\n", err)
		}
	}

	return nil
}

// GetGitHubSecretsList lists all secrets in the repository (names only, values are never exposed)
func GetGitHubSecretsList(config *GitHubConfig) ([]string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/secrets",
		config.Owner, config.Repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.Token))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Secrets []struct {
			Name      string    `json:"name"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
		} `json:"secrets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	names := make([]string, len(result.Secrets))
	for i, secret := range result.Secrets {
		names[i] = secret.Name
	}

	return names, nil
}

// StoreSecretsInGitHub stores the OAuth credentials and token in GitHub repository secrets
func (tm *TokenManager) StoreSecretsInGitHub() error {
	if tm.githubConfig == nil {
		return fmt.Errorf("GitHub config not available")
	}

	publicKey, keyID, err := getRepositoryPublicKey(tm.githubConfig)
	if err != nil {
		return fmt.Errorf("failed to get repository public key: %w", err)
	}

	encryptedClientID, err := encryptSecret(tm.config.ClientID, publicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt client ID: %w", err)
	}
	if err := updateSecret(tm.githubConfig, "GOOGLE_CLIENT_ID", encryptedClientID, keyID); err != nil {
		return fmt.Errorf("failed to update GOOGLE_CLIENT_ID: %w", err)
	}

	encryptedClientSecret, err := encryptSecret(tm.config.ClientSecret, publicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt client secret: %w", err)
	}
	if err := updateSecret(tm.githubConfig, "GOOGLE_CLIENT_SECRET", encryptedClientSecret, keyID); err != nil {
		return fmt.Errorf("failed to update GOOGLE_CLIENT_SECRET: %w", err)
	}

	if tm.token != nil && tm.token.RefreshToken != "" {
		encryptedRefreshToken, err := encryptSecret(tm.token.RefreshToken, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
		if err := updateSecret(tm.githubConfig, "GOOGLE_REFRESH_TOKEN", encryptedRefreshToken, keyID); err != nil {
			return fmt.Errorf("failed to update GOOGLE_REFRESH_TOKEN: %w", err)
		}
	}

	log.Println("OAuth credentials and token stored in GitHub secrets")
	return nil
}
