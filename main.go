package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	tokenFile = "token.json"
)

// validateRequiredEnvVars checks all required environment variables at startup
func validateRequiredEnvVars() error {
	requiredVars := map[string]string{
		"SECRET_KEY":           os.Getenv("SECRET_KEY"),
		"GITHUB_OWNER":         os.Getenv("GITHUB_OWNER"),
		"GITHUB_REPO":          os.Getenv("GITHUB_REPO"),
		"GITHUB_TOKEN":         os.Getenv("GITHUB_TOKEN"),
		"GOOGLE_CLIENT_ID":     os.Getenv("GOOGLE_CLIENT_ID"),
		"GOOGLE_CLIENT_SECRET": os.Getenv("GOOGLE_CLIENT_SECRET"),
	}

	var missing []string
	for key, value := range requiredVars {
		if value == "" {
			missing = append(missing, key)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("required environment variables are missing: %s", strings.Join(missing, ", "))
	}

	return nil
}

// getRedirectURL returns the appropriate redirect URL based on environment
func getRedirectURL() string {
	if renderURL := os.Getenv("RENDER_EXTERNAL_URL"); renderURL != "" {
		return renderURL + "/callback"
	}
	return "http://localhost:8080/callback"
}

// getPort returns the port to listen on
func getPort() string {
	if port := os.Getenv("PORT"); port != "" {
		return port
	}

	if passengerPort := os.Getenv("PASSENGER_PORT"); passengerPort != "" {
		return passengerPort
	}
	return "8080"
}

// TokenManager handles OAuth2 token operations
type TokenManager struct {
	config       *oauth2.Config
	token        *oauth2.Token
	client       *http.Client
	codeChan     chan string
	errChan      chan error
	githubConfig *GitHubConfig
	redisClient  *RedisClient
}

// NewTokenManager creates a new TokenManager instance
func NewTokenManager() (*TokenManager, error) {
	redisClient, err := NewRedisClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis client: %w", err)
	}

	githubConfig, err := NewGitHubConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub config: %w", err)
	}

	tm := &TokenManager{
		codeChan:     make(chan string, 1),
		errChan:      make(chan error, 1),
		githubConfig: githubConfig,
		redisClient:  redisClient,
	}

	if err := tm.loadSecretsFromRedis(context.Background()); err != nil {
		log.Printf("Warning: failed to load secrets from Redis: %v", err)

		clientID := os.Getenv("GOOGLE_CLIENT_ID")
		clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

		tm.config = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  getRedirectURL(),
			Scopes: []string{
				"https://www.googleapis.com/auth/chromewebstore",
			},
			Endpoint: google.Endpoint,
		}
	}

	return tm, nil
}

func (tm *TokenManager) loadSecretsFromRedis(ctx context.Context) error {
	clientID, err := tm.redisClient.GetSecret(ctx, "GOOGLE_CLIENT_ID")
	if err != nil {
		return fmt.Errorf("failed to get client ID from Redis: %w", err)
	}

	clientSecret, err := tm.redisClient.GetSecret(ctx, "GOOGLE_CLIENT_SECRET")
	if err != nil {
		return fmt.Errorf("failed to get client secret from Redis: %w", err)
	}

	tm.config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  getRedirectURL(),
		Scopes: []string{
			"https://www.googleapis.com/auth/chromewebstore",
		},
		Endpoint: google.Endpoint,
	}

	refreshToken, err := tm.redisClient.GetSecret(ctx, "GOOGLE_REFRESH_TOKEN")
	if err == nil && refreshToken != "" {
		tm.token = &oauth2.Token{
			RefreshToken: refreshToken,
		}
		tm.client = tm.config.Client(ctx, tm.token)
		log.Println("Loaded existing token from Redis")
	}

	return nil
}

func (tm *TokenManager) saveSecretsToRedis(ctx context.Context) error {
	if tm.config == nil {
		return fmt.Errorf("OAuth config not available")
	}

	if err := tm.redisClient.SetSecret(ctx, "GOOGLE_CLIENT_ID", tm.config.ClientID); err != nil {
		return fmt.Errorf("failed to save client ID to Redis: %w", err)
	}

	if err := tm.redisClient.SetSecret(ctx, "GOOGLE_CLIENT_SECRET", tm.config.ClientSecret); err != nil {
		return fmt.Errorf("failed to save client secret to Redis: %w", err)
	}

	if tm.token != nil && tm.token.RefreshToken != "" {
		if err := tm.redisClient.SetSecret(ctx, "GOOGLE_REFRESH_TOKEN", tm.token.RefreshToken); err != nil {
			return fmt.Errorf("failed to save refresh token to Redis: %w", err)
		}
	}

	log.Println("OAuth credentials and token saved to Redis")
	return nil
}

// startHTTPServer starts the HTTP server for OAuth callbacks
func (tm *TokenManager) startHTTPServer(ctx context.Context) *http.Server {
	port := getPort()
	srv := &http.Server{Addr: ":" + port}

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			select {
			case tm.errChan <- fmt.Errorf("no code in callback"):
			default:
			}
			_, _ = fmt.Fprintf(w, "Error: no authorization code received")
			return
		}
		select {
		case tm.codeChan <- code:
			_, _ = fmt.Fprintf(w, "Authorization successful! You can close this window.")
		default:
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	return srv
}

// Authorize performs the OAuth2 authorization flow
func (tm *TokenManager) Authorize(ctx context.Context) error {
	if tm.token != nil && tm.token.RefreshToken != "" {
		log.Println("Using existing token from Redis")
		return tm.refreshIfNeeded(ctx)
	}

	if err := tm.loadToken(); err == nil {
		log.Println("Using existing token from file")
		return tm.refreshIfNeeded(ctx)
	}

	authURL := tm.config.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	fmt.Printf("Visit this URL to authorize:\n%s\n", authURL)

	var code string
	select {
	case code = <-tm.codeChan:
	case err := <-tm.errChan:
		return fmt.Errorf("callback error: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	}

	token, err := tm.config.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w", err)
	}

	tm.token = token
	tm.client = tm.config.Client(ctx, token)

	if err := tm.saveToken(); err != nil {
		log.Printf("Warning: failed to save token to file: %v", err)
	}

	if err := tm.saveSecretsToRedis(ctx); err != nil {
		log.Printf("Warning: failed to save secrets to Redis: %v", err)
	}

	return nil
}

// refreshIfNeeded refreshes the token if it's expired
func (tm *TokenManager) refreshIfNeeded(ctx context.Context) error {
	if tm.token == nil {
		return fmt.Errorf("no token available")
	}

	// Check if token needs refresh
	if tm.token.Valid() {
		return nil
	}

	log.Println("Token expired, refreshing...")

	// Create a new token source and get refreshed token
	tokenSource := tm.config.TokenSource(ctx, tm.token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	tm.token = newToken
	tm.client = oauth2.NewClient(ctx, tokenSource)

	// Save updated token
	if err := tm.saveToken(); err != nil {
		log.Printf("Warning: failed to save refreshed token to file: %v", err)
	}

	if err := tm.saveSecretsToRedis(ctx); err != nil {
		log.Printf("Warning: failed to save refreshed secrets to Redis: %v", err)
	}

	log.Println("Token refreshed successfully")
	return nil
}

// PrintToken prints the current access token
func (tm *TokenManager) PrintToken() {
	if tm.token == nil {
		fmt.Println("No token available")
		return
	}

	fmt.Printf("\n=== Token Info ===\n")
	fmt.Printf("Access Token: [REDACTED]\n")
	fmt.Printf("Token Type: %s\n", tm.token.TokenType)
	fmt.Printf("Expiry: %s\n", tm.token.Expiry.Format(time.RFC3339))
	if tm.token.RefreshToken != "" {
		fmt.Println("Refresh Token: [present]")
	}
	fmt.Println("Token details have been stored in GitHub secrets")
	fmt.Println("==================")
}

// saveToken saves the token to a file
func (tm *TokenManager) saveToken() error {
	file, err := os.Create(tokenFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	return json.NewEncoder(file).Encode(tm.token)
}

// loadToken loads the token from a file
func (tm *TokenManager) loadToken() error {
	file, err := os.Open(tokenFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	tm.token = &oauth2.Token{}
	if err := json.NewDecoder(file).Decode(tm.token); err != nil {
		return err
	}

	tm.client = tm.config.Client(context.Background(), tm.token)
	return nil
}

func main() {
	// Validate all required environment variables first
	if err := validateRequiredEnvVars(); err != nil {
		log.Fatalf("Environment validation failed: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	defer stop()

	// Initialize token manager
	tm, err := NewTokenManager()
	if err != nil {
		log.Fatalf("Failed to create token manager: %v", err)
	}
	defer func() { _ = tm.redisClient.Close() }()

	// Start HTTP server immediately for callbacks and health checks
	srv := tm.startHTTPServer(ctx)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer func() {
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("HTTP server started on port %s", getPort())

	// Start health checker as goroutine
	StartHealthChecker(ctx)

	// Perform initial authorization
	if err := tm.Authorize(ctx); err != nil {
		log.Fatalf("Authorization failed: %v", err)
	}

	// Store initial secrets in GitHub
	if err := tm.StoreSecretsInGitHub(); err != nil {
		log.Printf("Failed to store initial secrets in GitHub: %v", err)
	} else {
		tm.PrintToken()
	}

	// Setup ticker for periodic token refresh and display
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	log.Println("Token manager running. Press Ctrl+C to stop.")

	// Main event loop
	for {
		select {
		case <-ticker.C:
			log.Println("Performing periodic token refresh...")
			if err := tm.refreshIfNeeded(ctx); err != nil {
				log.Printf("Failed to refresh token: %v", err)
				// Try to re-authorize
				if err := tm.Authorize(ctx); err != nil {
					log.Printf("Re-authorization failed: %v", err)
					continue
				}
			}

			// Store refreshed secrets in GitHub
			if err := tm.StoreSecretsInGitHub(); err != nil {
				log.Printf("Failed to store refreshed secrets in GitHub: %v", err)
			} else {
				tm.PrintToken()
			}

		case <-ctx.Done():
			log.Println("Received shutdown signal. waiting for server to stop...")
			<-shutdownCtx.Done()
			log.Println("shutdown complete")
			return
		}
	}
}
