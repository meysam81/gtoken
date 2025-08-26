package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"golang.org/x/oauth2"
)

// EmailConfig holds SMTP configuration
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	FromName     string
	FromEmail    string
	ToEmail      string
	Subject      string
}

// NewEmailConfig creates EmailConfig from environment variables
func NewEmailConfig() (*EmailConfig, error) {
	portStr := os.Getenv("SMTP_PORT")
	if portStr == "" {
		portStr = "587" // Default to TLS port
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid SMTP_PORT: %w", err)
	}

	config := &EmailConfig{
		SMTPHost:     os.Getenv("SMTP_HOST"),
		SMTPPort:     port,
		SMTPUsername: os.Getenv("SMTP_USERNAME"),
		SMTPPassword: os.Getenv("SMTP_PASSWORD"),
		FromName:     os.Getenv("FROM_NAME"),
		FromEmail:    os.Getenv("FROM_EMAIL"),
		ToEmail:      os.Getenv("TO_EMAIL"),
		Subject:      os.Getenv("EMAIL_SUBJECT"),
	}

	// Validate required fields
	if config.SMTPHost == "" || config.SMTPUsername == "" || config.SMTPPassword == "" {
		return nil, fmt.Errorf("SMTP_HOST, SMTP_USERNAME, and SMTP_PASSWORD must be set")
	}

	if config.FromEmail == "" || config.ToEmail == "" {
		return nil, fmt.Errorf("FROM_EMAIL and TO_EMAIL must be set")
	}

	// Set defaults
	if config.FromName == "" {
		config.FromName = "OAuth2 Token Manager"
	}

	if config.Subject == "" {
		config.Subject = "OAuth2 Token Update"
	}

	return config, nil
}

// SendTokenEmail sends the OAuth2 token information via email
func SendTokenEmail(token *oauth2.Token, config *EmailConfig) error {
	if token == nil {
		return fmt.Errorf("token is nil")
	}

	if config == nil {
		return fmt.Errorf("email config is nil")
	}

	// Build email body
	body, err := buildEmailBody(token, config)
	if err != nil {
		return fmt.Errorf("failed to build email body: %w", err)
	}

	// Build message
	message := buildMessage(config, body)

	// Send email
	if err := sendEmail(config, message); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// buildEmailBody creates the HTML email body with token information
func buildEmailBody(token *oauth2.Token, config *EmailConfig) (string, error) {
	const emailTemplate = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 20px auto; padding: 20px; }
        .header { background-color: #4285f4; color: white; padding: 20px; border-radius: 5px 5px 0 0; }
        .content { background-color: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-radius: 0 0 5px 5px; }
        .token-info { background-color: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #4285f4; }
        .label { font-weight: bold; color: #666; }
        .value { font-family: 'Courier New', monospace; word-break: break-all; color: #333; margin: 5px 0 15px 0; }
        .timestamp { color: #666; font-size: 0.9em; margin-top: 20px; }
        .warning { color: #ff6b6b; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>OAuth2 Token Update</h2>
        </div>
        <div class="content">
            <p>Your OAuth2 token has been successfully {{.Status}}.</p>

            <div class="token-info">
                <div class="label">Access Token:</div>
                <div class="value">{{.AccessToken}}</div>

                <div class="label">Token Type:</div>
                <div class="value">{{.TokenType}}</div>

                <div class="label">Expiry:</div>
                <div class="value">{{.Expiry}}</div>

                <div class="label">Time Until Expiry:</div>
                <div class="value {{if .IsExpiringSoon}}warning{{end}}">{{.TimeUntilExpiry}}</div>

                <div class="label">Refresh Token:</div>
                <div class="value">{{.RefreshTokenStatus}}</div>

                <div class="label">Scopes:</div>
                <div class="value">https://www.googleapis.com/auth/chromewebstore, offline_access</div>
            </div>

            <div class="timestamp">
                <p>Generated at: {{.GeneratedAt}}</p>
            </div>
        </div>
    </div>
</body>
</html>
`

	// Prepare template data
	data := struct {
		Status             string
		AccessToken        string
		TokenType          string
		Expiry             string
		TimeUntilExpiry    string
		IsExpiringSoon     bool
		RefreshTokenStatus string
		GeneratedAt        string
	}{
		Status:      "refreshed",
		AccessToken: truncateToken(token.AccessToken),
		TokenType:   token.TokenType,
		Expiry:      token.Expiry.Format(time.RFC3339),
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	// Calculate time until expiry
	timeUntilExpiry := time.Until(token.Expiry)
	if timeUntilExpiry > 0 {
		hours := int(timeUntilExpiry.Hours())
		minutes := int(timeUntilExpiry.Minutes()) % 60
		data.TimeUntilExpiry = fmt.Sprintf("%d hours %d minutes", hours, minutes)
		data.IsExpiringSoon = hours < 2
	} else {
		data.TimeUntilExpiry = "Token is expired"
		data.IsExpiringSoon = true
	}

	// Check refresh token
	if token.RefreshToken != "" {
		data.RefreshTokenStatus = "[Present - Token can be auto-refreshed]"
	} else {
		data.RefreshTokenStatus = "[Not present - Manual reauthorization may be required]"
	}

	// Parse and execute template
	tmpl, err := template.New("email").Parse(emailTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// truncateToken shows first and last 10 characters of token for security
func truncateToken(token string) string {
	if len(token) <= 24 {
		return "[REDACTED]"
	}
	return fmt.Sprintf("%s...%s", token[:10], token[len(token)-10:])
}

// buildMessage constructs the complete email message with headers
func buildMessage(config *EmailConfig, body string) []byte {
	headers := make(map[string]string)
	headers["From"] = fmt.Sprintf("%s <%s>", config.FromName, config.FromEmail)
	headers["To"] = config.ToEmail
	headers["Subject"] = config.Subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=\"UTF-8\""

	var message bytes.Buffer
	for k, v := range headers {
		message.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	message.WriteString("\r\n")
	message.WriteString(body)

	return message.Bytes()
}

// sendEmail sends the email using SMTP
func sendEmail(config *EmailConfig, message []byte) error {
	addr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)

	// Setup authentication
	auth := smtp.PlainAuth("", config.SMTPUsername, config.SMTPPassword, config.SMTPHost)

	// Try TLS connection first (port 587 or 465)
	if config.SMTPPort == 587 || config.SMTPPort == 465 {
		return sendEmailTLS(addr, auth, config, message)
	}

	// Fallback to plain SMTP (port 25)
	return smtp.SendMail(addr, auth, config.FromEmail, []string{config.ToEmail}, message)
}

// sendEmailTLS sends email using TLS/STARTTLS
func sendEmailTLS(addr string, auth smtp.Auth, config *EmailConfig, message []byte) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// STARTTLS
	tlsConfig := &tls.Config{
		ServerName: config.SMTPHost,
	}

	if err := client.StartTLS(tlsConfig); err != nil {
		return err
	}

	// Authenticate
	if err := client.Auth(auth); err != nil {
		return err
	}

	// Set sender and recipient
	if err := client.Mail(config.FromEmail); err != nil {
		return err
	}

	if err := client.Rcpt(config.ToEmail); err != nil {
		return err
	}

	// Send message
	w, err := client.Data()
	if err != nil {
		return err
	}
	defer func() { _ = w.Close() }()

	_, err = w.Write(message)
	return err
}

// SendTokenNotification is a convenience function that creates config and sends email
func SendTokenNotification(token *oauth2.Token) error {
	config, err := NewEmailConfig()
	if err != nil {
		return fmt.Errorf("failed to create email config: %w", err)
	}

	return SendTokenEmail(token, config)
}
