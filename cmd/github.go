package gtoken

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/goccy/go-json"
	"golang.org/x/crypto/nacl/box"
)

type PublicKeyResponse struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"`
}

type SecretUpdateRequest struct {
	EncryptedValue string `json:"encrypted_value"`
	KeyID          string `json:"key_id"`
}

func (a *AppState) getRepositoryPublicKey(ctx context.Context) ([]byte, string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/secrets/public-key",
		a.Config.GitHubOwner, a.Config.GitHubRepo)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := HTTPClient.R().
		SetBearerAuthToken(a.Config.GitHubToken).
		SetContext(ctx).
		SetHeader("Accept", "application/vnd.github+json").
		SetHeader("X-GitHub-Api-Version", "2022-11-28").
		Get(url)

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

	publicKey, err := base64.StdEncoding.DecodeString(keyResponse.Key)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode public key: %w", err)
	}

	return publicKey, keyResponse.KeyID, nil
}

func (a *AppState) encryptSecret(secretValue string, publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("invalid public key length: expected 32, got %d", len(publicKey))
	}

	var publicKeyArray [32]byte
	copy(publicKeyArray[:], publicKey)

	encrypted, err := box.SealAnonymous(nil, []byte(secretValue), &publicKeyArray, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt secret: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (a *AppState) updateSecret(ctx context.Context, secretName, encryptedValue, keyID string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/secrets/%s",
		a.Config.GitHubOwner, a.Config.GitHubRepo, secretName)

	requestBody := SecretUpdateRequest{
		EncryptedValue: encryptedValue,
		KeyID:          keyID,
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := HTTPClient.R().
		SetBearerAuthToken(a.Config.GitHubToken).
		SetContext(ctx).
		SetHeader("Accept", "application/vnd.github+json").
		SetHeader("Content-Type", "application/json").
		SetHeader("X-GitHub-Api-Version", "2022-11-28").
		SetBodyJsonMarshal(requestBody).
		Put(url)

	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to update secret (status %d): %s", resp.StatusCode, resp.String())
	}

	return nil
}

func (a *AppState) GetGitHubSecretsList(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/secrets",
		a.Config.GitHubOwner, a.Config.GitHubRepo)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := HTTPClient.R().
		SetBearerAuthToken(a.Config.GitHubToken).
		SetContext(ctx).
		SetHeader("Accept", "application/vnd.github+json").
		SetHeader("X-GitHub-Api-Version", "2022-11-28").
		Get(url)

	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, resp.String())
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

func (a *AppState) StoreSecretsInGitHub(ctx context.Context) error {
	publicKey, keyID, err := a.getRepositoryPublicKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to get repository public key: %w", err)
	}

	encryptedClientID, err := a.encryptSecret(a.oauthConfig.ClientID, publicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt client ID: %w", err)
	}
	if err := a.updateSecret(ctx, "GOOGLE_CLIENT_ID", encryptedClientID, keyID); err != nil {
		return fmt.Errorf("failed to update GOOGLE_CLIENT_ID: %w", err)
	}

	encryptedClientSecret, err := a.encryptSecret(a.oauthConfig.ClientSecret, publicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt client secret: %w", err)
	}
	if err := a.updateSecret(ctx, "GOOGLE_CLIENT_SECRET", encryptedClientSecret, keyID); err != nil {
		return fmt.Errorf("failed to update GOOGLE_CLIENT_SECRET: %w", err)
	}

	if a.token != nil && a.token.RefreshToken != "" {
		encryptedRefreshToken, err := a.encryptSecret(a.token.RefreshToken, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
		if err := a.updateSecret(ctx, "GOOGLE_REFRESH_TOKEN", encryptedRefreshToken, keyID); err != nil {
			return fmt.Errorf("failed to update GOOGLE_REFRESH_TOKEN: %w", err)
		}
	}

	log.Println("OAuth credentials and token stored in GitHub secrets")
	return nil
}
