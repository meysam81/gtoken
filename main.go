package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	tokenFile = "token.json"
)

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
	config   *oauth2.Config
	token    *oauth2.Token
	client   *http.Client
	codeChan chan string
	errChan  chan error
}

// NewTokenManager creates a new TokenManager instance
func NewTokenManager() (*TokenManager, error) {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set")
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  getRedirectURL(),
		Scopes: []string{
			"https://www.googleapis.com/auth/chromewebstore",
		},
		Endpoint: google.Endpoint,
	}

	return &TokenManager{
		config:   config,
		codeChan: make(chan string, 1),
		errChan:  make(chan error, 1),
	}, nil
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
	// Try to load existing token
	if err := tm.loadToken(); err == nil {
		log.Println("Using existing token")
		return tm.refreshIfNeeded(ctx)
	}

	// Need new authorization
	authURL := tm.config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	fmt.Printf("Visit this URL to authorize:\n%s\n", authURL)

	// Wait for authorization code or error
	var code string
	select {
	case code = <-tm.codeChan:
	case err := <-tm.errChan:
		return fmt.Errorf("callback error: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	}

	// Exchange code for token
	token, err := tm.config.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w", err)
	}

	tm.token = token
	tm.client = tm.config.Client(ctx, token)

	// Save token for future use
	if err := tm.saveToken(); err != nil {
		log.Printf("Warning: failed to save token: %v", err)
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
		log.Printf("Warning: failed to save refreshed token: %v", err)
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
	fmt.Println("Token details have been sent via email")
	fmt.Println("==================")
}

// EmailToken sends the current token via email
func (tm *TokenManager) EmailToken() error {
	if tm.token == nil {
		return fmt.Errorf("no token available")
	}

	if err := SendTokenNotification(tm.token); err != nil {
		return fmt.Errorf("failed to send token email: %w", err)
	}

	log.Println("Token information sent via email")
	return nil
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	defer stop()

	// Initialize token manager
	tm, err := NewTokenManager()
	if err != nil {
		log.Fatalf("Failed to create token manager: %v", err)
	}

	// Start HTTP server immediately for callbacks and health checks
	srv := tm.startHTTPServer(ctx)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	// Email initial token
	if err := tm.EmailToken(); err != nil {
		log.Printf("Failed to email initial token: %v", err)
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

			// Email refreshed token
			if err := tm.EmailToken(); err != nil {
				log.Printf("Failed to email refreshed token: %v", err)
			} else {
				tm.PrintToken()
			}

		case <-ctx.Done():
			log.Println("Received shutdown signal")
			return
		}
	}
}
