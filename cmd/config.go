package gtoken

import "github.com/caarlos0/env/v11"

type Config struct {
	SecretKey string `env:"SECRET_KEY,required"`

	RedisURL string `env:"REDIS_URL" envDefault:"redis://localhost:6379/0"`

	Port          string `env:"PORT" envDefault:"8080"`
	PassengerPort string `env:"PASSENGER_PORT"`

	BaseURL           string `env:"BASE_URL"`
	RenderExternalURL string `env:"RENDER_EXTERNAL_URL"`

	GoogleClientID     string `env:"GOOGLE_CLIENT_ID,required"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET,required"`

	GitHubOwner string `env:"GITHUB_OWNER,required"`
	GitHubRepo  string `env:"GITHUB_REPO,required"`
	GitHubToken string `env:"GITHUB_TOKEN,required"`
}

func NewConfig() (*Config, error) {
	c := &Config{}
	err := env.Parse(c)
	return c, err
}

func (c *Config) GetPort() string {
	if c.PassengerPort != "" {
		return c.PassengerPort
	}
	return c.Port
}

func (c *Config) GetRedirectURL() string {
	if c.BaseURL != "" {
		return c.BaseURL + "/callback"
	}

	if c.RenderExternalURL != "" {
		return c.RenderExternalURL + "/callback"
	}
	return "http://localhost:" + c.GetPort() + "/callback"
}

func (c *Config) GetRepoKey() string {
	return c.GitHubOwner + "/" + c.GitHubRepo
}
