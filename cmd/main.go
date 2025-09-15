package gtoken

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/oauth2"
)

func (a *AppState) saveSecretsToRedis(ctx context.Context) error {
	if a.oauthConfig == nil {
		return fmt.Errorf("OAuth config not available")
	}

	repoKey := a.Config.GetRepoKey()

	if err := a.SetRepoCredential(ctx, repoKey, "GOOGLE_CLIENT_ID", a.oauthConfig.ClientID); err != nil {
		return fmt.Errorf("failed to save client ID to Redis: %w", err)
	}

	if err := a.SetRepoCredential(ctx, repoKey, "GOOGLE_CLIENT_SECRET", a.oauthConfig.ClientSecret); err != nil {
		return fmt.Errorf("failed to save client secret to Redis: %w", err)
	}

	if a.token != nil && a.token.RefreshToken != "" {
		if err := a.SetRepoCredential(ctx, repoKey, "GOOGLE_REFRESH_TOKEN", a.token.RefreshToken); err != nil {
			return fmt.Errorf("failed to save refresh token to Redis: %w", err)
		}
	}

	log.Println("OAuth credentials and token saved to Redis")
	return nil
}

func (a *AppState) startHTTPServer(ctx context.Context) *http.Server {
	port := a.Config.GetPort()
	srv := &http.Server{Addr: ":" + port}

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			select {
			case a.errChan <- fmt.Errorf("no code in callback"):
			default:
			}
			_, _ = fmt.Fprintf(w, "Error: no authorization code received")
			return
		}
		select {
		case a.codeChan <- code:
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

func (a *AppState) Authorize(ctx context.Context) error {
	if a.token != nil && a.token.RefreshToken != "" {
		log.Println("Using existing token from Redis")
		return a.refreshIfNeeded(ctx)
	}

	authURL := a.oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	fmt.Printf("Visit this URL to authorize:\n%s\n", authURL)

	var code string
	select {
	case code = <-a.codeChan:
	case err := <-a.errChan:
		return fmt.Errorf("callback error: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	}

	token, err := a.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w", err)
	}

	a.token = token
	a.httpClient = a.oauthConfig.Client(ctx, token)

	if err := a.saveSecretsToRedis(ctx); err != nil {
		log.Printf("Warning: failed to save secrets to Redis: %v", err)
	}

	return nil
}

func (a *AppState) refreshIfNeeded(ctx context.Context) error {
	if a.token == nil {
		return fmt.Errorf("no token available")
	}

	if a.token.Valid() {
		return nil
	}

	log.Println("Token expired, refreshing...")

	tokenSource := a.oauthConfig.TokenSource(ctx, a.token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	a.token = newToken
	a.httpClient = oauth2.NewClient(ctx, tokenSource)

	if err := a.saveSecretsToRedis(ctx); err != nil {
		log.Printf("Warning: failed to save refreshed secrets to Redis: %v", err)
	}

	log.Println("Token refreshed successfully")
	return nil
}

func (a *AppState) PrintToken() {
	if a.token == nil {
		fmt.Println("No token available")
		return
	}

	fmt.Printf("\n=== Token Info ===\n")
	fmt.Printf("Access Token: [REDACTED]\n")
	fmt.Printf("Token Type: %s\n", a.token.TokenType)
	fmt.Printf("Expiry: %s\n", a.token.Expiry.Format(time.RFC3339))
	if a.token.RefreshToken != "" {
		fmt.Println("Refresh Token: [present]")
	}
	fmt.Println("Token details have been stored in GitHub secrets")
	fmt.Println("==================")
}

func Main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	defer stop()

	appState, err := NewAppState()
	if err != nil {
		log.Fatalf("Failed to create app state: %v", err)
	}
	defer func() { _ = appState.Close() }()

	srv := appState.startHTTPServer(ctx)
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer func() {
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("HTTP server started on port %s", appState.Config.GetPort())

	if err := appState.Authorize(ctx); err != nil {
		log.Fatalf("Authorization failed: %v", err)
	}

	if err := appState.StoreSecretsInGitHub(ctx); err != nil {
		log.Printf("Failed to store initial secrets in GitHub: %v", err)
	} else {
		appState.PrintToken()
	}

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	log.Println("Token manager running. Press Ctrl+C to stop.")

	for {
		select {
		case <-ticker.C:
			log.Println("Performing periodic token refresh...")
			if err := appState.refreshIfNeeded(ctx); err != nil {
				log.Printf("Failed to refresh token: %v", err)
				if err := appState.Authorize(ctx); err != nil {
					log.Printf("Re-authorization failed: %v", err)
					continue
				}
			}

			if err := appState.StoreSecretsInGitHub(ctx); err != nil {
				log.Printf("Failed to store refreshed secrets in GitHub: %v", err)
			} else {
				appState.PrintToken()
			}

		case <-ctx.Done():
			log.Println("Received shutdown signal. waiting for server to stop...")
			<-shutdownCtx.Done()
			log.Println("shutdown complete")
			return
		}
	}
}
