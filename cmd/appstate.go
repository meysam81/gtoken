package gtoken

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/caarlos0/env/v11"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type AppState struct {
	Config *Config

	redisClient *redis.Client
	gcm         cipher.AEAD

	oauthConfig *oauth2.Config
	token       *oauth2.Token
	httpClient  *http.Client
	codeChan    chan string
	errChan     chan error
}

func NewAppState() (*AppState, error) {
	config := &Config{}
	if err := env.Parse(config); err != nil {
		return nil, err
	}

	opts, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	redisClient := redis.NewClient(opts)

	hash := sha256.Sum256([]byte(config.SecretKey))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	appState := &AppState{
		Config:      config,
		redisClient: redisClient,
		gcm:         gcm,
		codeChan:    make(chan string, 1),
		errChan:     make(chan error, 1),
	}

	if err := appState.loadSecretsFromRedis(context.Background()); err != nil {
		appState.oauthConfig = &oauth2.Config{
			ClientID:     config.GoogleClientID,
			ClientSecret: config.GoogleClientSecret,
			RedirectURL:  config.GetRedirectURL(),
			Scopes: []string{
				"https://www.googleapis.com/auth/chromewebstore",
			},
			Endpoint: google.Endpoint,
		}
	}

	return appState, nil
}

func (a *AppState) encrypt(plaintext string) (string, error) {
	nonce := make([]byte, a.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := a.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (a *AppState) decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	nonceSize := a.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextRaw := data[:nonceSize], data[nonceSize:]
	plaintext, err := a.gcm.Open(nil, nonce, ciphertextRaw, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func (a *AppState) SetSecret(ctx context.Context, key, value string) error {
	encrypted, err := a.encrypt(value)
	if err != nil {
		return fmt.Errorf("failed to encrypt value: %w", err)
	}

	return a.redisClient.Set(ctx, key, encrypted, 0).Err()
}

func (a *AppState) GetSecret(ctx context.Context, key string) (string, error) {
	encrypted, err := a.redisClient.Get(ctx, key).Result()
	if err != nil {
		return "", err
	}

	return a.decrypt(encrypted)
}

func (a *AppState) SetRepoCredential(ctx context.Context, repoKey, field, value string) error {
	encrypted, err := a.encrypt(value)
	if err != nil {
		return fmt.Errorf("failed to encrypt value: %w", err)
	}

	return a.redisClient.HSet(ctx, repoKey, field, encrypted).Err()
}

func (a *AppState) GetRepoCredential(ctx context.Context, repoKey, field string) (string, error) {
	encrypted, err := a.redisClient.HGet(ctx, repoKey, field).Result()
	if err != nil {
		return "", err
	}

	return a.decrypt(encrypted)
}

func (a *AppState) GetAllRepoCredentials(ctx context.Context, repoKey string) (map[string]string, error) {
	encryptedData, err := a.redisClient.HGetAll(ctx, repoKey).Result()
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for field, encrypted := range encryptedData {
		decrypted, err := a.decrypt(encrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt field %s: %w", field, err)
		}
		result[field] = decrypted
	}

	return result, nil
}

func (a *AppState) DeleteSecret(ctx context.Context, key string) error {
	return a.redisClient.Del(ctx, key).Err()
}

func (a *AppState) DeleteRepoCredential(ctx context.Context, repoKey, field string) error {
	return a.redisClient.HDel(ctx, repoKey, field).Err()
}

func (a *AppState) Close() error {
	return a.redisClient.Close()
}

func (a *AppState) loadSecretsFromRedis(ctx context.Context) error {
	repoKey := a.Config.GetRepoKey()

	credentials, err := a.GetAllRepoCredentials(ctx, repoKey)
	if err != nil {
		return fmt.Errorf("failed to load credentials from Redis: %w", err)
	}

	if len(credentials) == 0 {
		return fmt.Errorf("no credentials found in Redis")
	}

	clientID, hasClientID := credentials["GOOGLE_CLIENT_ID"]
	clientSecret, hasClientSecret := credentials["GOOGLE_CLIENT_SECRET"]

	if !hasClientID || !hasClientSecret {
		return fmt.Errorf("missing OAuth credentials in Redis")
	}

	a.oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  a.Config.GetRedirectURL(),
		Scopes: []string{
			"https://www.googleapis.com/auth/chromewebstore",
		},
		Endpoint: google.Endpoint,
	}

	refreshToken, hasRefreshToken := credentials["GOOGLE_REFRESH_TOKEN"]
	if hasRefreshToken && refreshToken != "" {
		a.token = &oauth2.Token{
			RefreshToken: refreshToken,
		}
		a.httpClient = a.oauthConfig.Client(ctx, a.token)
	}

	return nil
}
